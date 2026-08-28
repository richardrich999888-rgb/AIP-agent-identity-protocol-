/**
 * Registry of active digital agents: onboarding, credential renewal, and the
 * instant kill-switch.
 *
 * # Trust model
 *
 * The registry is the credential issuer *and* the runtime authority. Every
 * profile it hands out is HMAC-signed over the canonical payload, so a
 * profile object that has been edited after issue (an added permission, a
 * flipped revocation flag) fails `verifyCredential`. But signatures alone
 * cannot express revocation — a signed credential stays validly signed
 * forever — so authorization always consults the registry's *live* record,
 * and `revokeAgent` takes effect the moment the map is updated, not when
 * some token expires.
 *
 * # Storage
 *
 * The working set is an in-memory Map; IndexedDB persistence (when the
 * runtime has it) is a write-through so a console reload does not silently
 * forget which agents were onboarded or, worse, which were revoked. Reads
 * never block on IndexedDB — the memory map is the authority within a
 * session.
 */

import { canonicalJson, hmacSignHex, hmacVerifyHex, importHmacKey } from "../crypto";
import {
  agentDid,
  officerDid,
  profileSigningPayload,
  type AgentEmployeeProfile,
} from "./agent-profile";

/** Everything the caller supplies at onboarding; the registry assigns the
 * lifecycle fields, derives both DIDs from the plain identifiers (one
 * source of truth — a caller-supplied DID that disagreed with the agentId
 * would be a forgery vector), and signs. */
export type AgentOnboardingSpec = Omit<
  AgentEmployeeProfile,
  | "did"
  | "supervisorDid"
  | "revocationStatus"
  | "issuedAtUtc"
  | "expiresAtUtc"
  | "credentialSignature"
> & {
  /** Credential lifetime in milliseconds. */
  validForMs: number;
};

/** The bytes a supervisor co-signature covers: one agent, one tool, under
 * this standard — so a co-signature captured for `fly_to` cannot be replayed
 * to authorize `execute_thruster_burn`, nor a signature for one agent be
 * spent on another. */
function coSignaturePayload(
  profile: Pick<AgentEmployeeProfile, "did" | "supervisorDid">,
  toolName: string,
): string {
  return canonicalJson({
    standard: "SYNTRIASS-dual-key-v1",
    agentDid: profile.did,
    supervisorDid: profile.supervisorDid,
    toolName,
  });
}

const DB_NAME = "ot_agent_identity_registry";
const STORE = "profiles";

/** Opens the persistence DB, or resolves null where IndexedDB is absent
 * (tests, SSR) — persistence is an upgrade, not a requirement. */
function openDb(): Promise<IDBDatabase | null> {
  if (typeof indexedDB === "undefined") return Promise.resolve(null);
  return new Promise((resolve) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE, { keyPath: "agentId" });
    };
    req.onsuccess = () => resolve(req.result);
    // A broken IndexedDB (private mode, quota) degrades to memory-only.
    req.onerror = () => resolve(null);
  });
}

export class IdentityRegistry {
  private readonly agents = new Map<string, AgentEmployeeProfile>();
  private readonly key: Promise<CryptoKey>;
  private readonly db: Promise<IDBDatabase | null>;
  private readonly listeners = new Set<() => void>();
  /** Monotonic change counter — the snapshot `useSyncExternalStore` wants,
   * since a revocation replaces a map entry without changing the count. */
  private version = 0;

  /**
   * @param signingSecret secret for the HMAC credential signatures. In a
   * deployment this comes from operator configuration; it must not be
   * hard-coded by callers into committed source.
   */
  constructor(signingSecret: string, opts: { persist?: boolean } = {}) {
    this.key = importHmacKey(signingSecret);
    this.db = opts.persist === false ? Promise.resolve(null) : openDb();
  }

  /** Subscribe to registry changes (onboard/renew/suspend/revoke). Returns
   * the unsubscribe function — the shape `useSyncExternalStore` wants. */
  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(): void {
    this.version++;
    for (const l of this.listeners) l();
  }

  /** Changes on every registry mutation (onboard/renew/suspend/revoke). */
  get snapshotVersion(): number {
    return this.version;
  }

  private async persist(profile: AgentEmployeeProfile): Promise<void> {
    const db = await this.db;
    if (!db) return;
    await new Promise<void>((resolve) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(profile);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve(); // degraded persistence, not a failure
    });
  }

  /** Onboards a new digital employee: assigns the credential window, signs
   * the canonical payload, registers, persists. */
  async onboardAgent(spec: AgentOnboardingSpec): Promise<AgentEmployeeProfile> {
    if (this.agents.has(spec.agentId)) {
      throw new Error(`agent ${spec.agentId} is already registered`);
    }
    if (spec.validForMs <= 0) {
      throw new Error("credential lifetime must be positive");
    }
    const issued = new Date();
    const unsigned: Omit<AgentEmployeeProfile, "credentialSignature"> = {
      agentId: spec.agentId,
      did: agentDid(spec.agentId),
      agentName: spec.agentName,
      organization: spec.organization,
      modelEngine: spec.modelEngine,
      modelDigest: spec.modelDigest,
      systemPromptHash: spec.systemPromptHash,
      enclaveType: spec.enclaveType,
      department: spec.department,
      clearanceLevel: spec.clearanceLevel,
      supervisorOperatorId: spec.supervisorOperatorId,
      supervisorDid: officerDid(spec.supervisorOperatorId),
      assignedPermissions: [...spec.assignedPermissions],
      requiresDualKeyAuthorization: [...spec.requiresDualKeyAuthorization],
      revocationStatus: "ACTIVE",
      issuedAtUtc: issued.toISOString(),
      expiresAtUtc: new Date(issued.getTime() + spec.validForMs).toISOString(),
    };
    const profile = await this.sign(unsigned);
    this.agents.set(profile.agentId, profile);
    await this.persist(profile);
    this.emit();
    return profile;
  }

  /** Re-issues the credential with a new expiry. Refused for revoked agents:
   * renewal is not a resurrection path — the kill-switch stays a kill-switch. */
  async renewCredential(
    agentId: string,
    validForMs: number,
  ): Promise<AgentEmployeeProfile> {
    const current = this.require(agentId);
    if (current.revocationStatus === "REVOKED") {
      throw new Error(`agent ${agentId} is revoked; revocation is terminal`);
    }
    if (validForMs <= 0) {
      throw new Error("credential lifetime must be positive");
    }
    const issued = new Date();
    const profile = await this.sign({
      ...current,
      issuedAtUtc: issued.toISOString(),
      expiresAtUtc: new Date(issued.getTime() + validForMs).toISOString(),
    });
    this.agents.set(agentId, profile);
    await this.persist(profile);
    this.emit();
    return profile;
  }

  /** Instant kill-switch. Takes effect on the in-memory record immediately;
   * the re-signed REVOKED profile is what persists, so a reload cannot
   * resurrect the agent from a stale ACTIVE row. */
  async revokeAgent(agentId: string): Promise<AgentEmployeeProfile> {
    return this.setStatus(agentId, "REVOKED");
  }

  /** Reversible pause pending supervisor review. */
  async suspendAgent(agentId: string): Promise<AgentEmployeeProfile> {
    return this.setStatus(agentId, "SUSPENDED");
  }

  /** Lifts a suspension. Refused for revoked agents. */
  async reinstateAgent(agentId: string): Promise<AgentEmployeeProfile> {
    const current = this.require(agentId);
    if (current.revocationStatus === "REVOKED") {
      throw new Error(`agent ${agentId} is revoked; revocation is terminal`);
    }
    return this.setStatus(agentId, "ACTIVE");
  }

  private async setStatus(
    agentId: string,
    status: AgentEmployeeProfile["revocationStatus"],
  ): Promise<AgentEmployeeProfile> {
    const current = this.require(agentId);
    const profile = await this.sign({ ...current, revocationStatus: status });
    this.agents.set(agentId, profile);
    await this.persist(profile);
    this.emit();
    return profile;
  }

  /** The live record — the authority the permission guard should be fed. */
  getAgent(agentId: string): AgentEmployeeProfile | undefined {
    return this.agents.get(agentId);
  }

  listAgents(): AgentEmployeeProfile[] {
    return [...this.agents.values()];
  }

  /** Checks the HMAC over the canonical payload. A `true` here means "issued
   * by this registry and unmodified since" — liveness (revocation) is still
   * the map's call, which is why authorization uses {@link getAgent}. */
  async verifyCredential(profile: AgentEmployeeProfile): Promise<boolean> {
    const { credentialSignature, ...unsigned } = profile;
    return hmacVerifyHex(
      await this.key,
      profileSigningPayload(unsigned),
      credentialSignature,
    );
  }

  /**
   * Issues a human supervisor's co-signature authorizing one invocation of
   * one high-consequence tool by one agent. In a deployment this call sits
   * behind the supervisor's own authentication (their console, their
   * hardware token); the registry refuses to countersign for anyone but the
   * supervisor of record, so a different officer's id cannot mint consent
   * for an agent they do not command.
   */
  async issueSupervisorCoSignature(
    supervisorOperatorId: string,
    agentId: string,
    toolName: string,
  ): Promise<string> {
    const profile = this.require(agentId);
    if (profile.supervisorOperatorId !== supervisorOperatorId) {
      throw new Error(
        `${supervisorOperatorId} is not the supervisor of record for ${agentId}`,
      );
    }
    return hmacSignHex(await this.key, coSignaturePayload(profile, toolName));
  }

  /** Verifies a co-signature for one (agent, tool) pair. The payload binds
   * both DIDs and the tool name, so replay across tools or agents fails. */
  async verifySupervisorCoSignature(
    profile: AgentEmployeeProfile,
    toolName: string,
    signatureHex: string,
  ): Promise<boolean> {
    return hmacVerifyHex(
      await this.key,
      coSignaturePayload(profile, toolName),
      signatureHex,
    );
  }

  private require(agentId: string): AgentEmployeeProfile {
    const profile = this.agents.get(agentId);
    if (!profile) throw new Error(`agent ${agentId} is not registered`);
    return profile;
  }

  private async sign(
    unsigned: Omit<AgentEmployeeProfile, "credentialSignature">,
  ): Promise<AgentEmployeeProfile> {
    const credentialSignature = await hmacSignHex(
      await this.key,
      profileSigningPayload(unsigned),
    );
    return { ...unsigned, credentialSignature };
  }
}
