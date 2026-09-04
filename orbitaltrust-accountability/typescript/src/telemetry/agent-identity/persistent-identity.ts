/**
 * Persistent identity vs. delegated authority — the load-bearing distinction.
 *
 * Who an agent *is* (its DID, keys, model provenance, enclave) is durable:
 * it survives restarts, machines and sessions, and revoking its permissions
 * must not erase it — an audit that cannot name the actor because the actor
 * was deleted is not an audit. What an agent *may do* is a separate,
 * time-bounded, revocable grant signed by the human (or upstream agent) who
 * delegated the authority. Actions bind the two together in evidence
 * packets: non-repudiable, hash-chained proof of which identity did what
 * under which grant, delegated by whom.
 */

import { canonicalJson, hmacSignHex, hmacVerifyHex, importHmacKey } from "../crypto";
import type { ClearanceLevel } from "./agent-profile";

export type AgentDidString = `did:syntriass:agent:${string}`;
export type OfficerDidString = `did:syntriass:officer:${string}`;

export function toAgentDid(agentId: string): AgentDidString {
  return `did:syntriass:agent:${agentId}`;
}

export function toOfficerDid(operatorId: string): OfficerDidString {
  return `did:syntriass:officer:${operatorId}`;
}

/** Durable across restarts, machines, and sessions. Carries no permissions:
 * authority lives in grants, never in identity. */
export interface PersistentAgentIdentity {
  /** Stable decentralized identifier. */
  did: AgentDidString;
  /** e.g. "AGT-0481-JARVIS" */
  agentId: string;
  agentName: string;
  /** e.g. "SYNTRIASS_LABS" | "DEFENCE_SPACE_AGENCY" */
  organization: string;
  /** Agent's cryptographic public key (JWK / hex). */
  publicKey: string;
  /** SHA-256 of model weights & quantization profile. */
  modelDigest: string;
  /** SHA-256 of base guardrail instructions. */
  systemPromptHash: string;
  enclaveType: "SOFTWARE_SANDBOX" | "TPM_2_0" | "SECURE_ENCLAVE" | "AWS_NITRO";
  createdAtUtc: string;
  version: string;
}

/** Dynamic, time-bounded, revocable authority. Rotating, narrowing or
 * revoking a grant never touches the identity it was issued to. */
export interface DelegatedAuthorityGrant {
  /** UUID v4. */
  grantId: string;
  agentDid: AgentDidString;
  /** Human supervisor / upstream authority. */
  delegatorDid: OfficerDidString;
  /** Upstream delegation DID trail for sub-agent trees, root first. */
  delegationChain: string[];
  clearanceLevel: ClearanceLevel;
  /** Permitted tool verbs. */
  grantedTools: string[];
  /** Tools requiring dual-key human supervisor co-signature. */
  requiresMultiSigTools: string[];
  rateLimitMaxPerHour: number;
  validFromUtc: string;
  expiresAtUtc: string;
  status: "ACTIVE" | "SUSPENDED" | "REVOKED";
  /** Delegator's cryptographic signature over this grant's terms. */
  grantSignature: string;
}

/** PQC posture stamped into an evidence packet: which suite protected the
 * transaction and the recomputable digest of what was protected. The
 * latency figure carries its provenance ("SPEC_TARGET" until a deployment
 * measures the real kernel path) so the stamp never dresses a design
 * number as a reading. */
export interface PqcAuditStamp {
  cipherSuite: string;
  hndlProtectionStatus: string;
  kernelLatencyNs: number;
  latencyProvenance: string;
  /** SHA-256 over the canonical input payload of the governed action. */
  evidenceDigest: string;
}

/** Non-repudiable proof of one governed action (or refused attempt). */
export interface EvidencePacket {
  /** UUID v4. */
  id: string;
  /** Monotonic per-agent index, starting at 1. */
  sequenceNumber: number;
  timestampUtc: string;
  agentDid: AgentDidString;
  /** The grant the action ran under — "" when it was blocked for having
   * no usable grant at all, which is itself evidence. */
  grantId: string;
  delegatorDid: OfficerDidString;
  delegationChain: string[];
  modelDigest: string;
  rawPrompt: string;
  toolExecuted: {
    name: string;
    inputParams: Record<string, unknown>;
    status: "SUCCESS" | "FAILED" | "BLOCKED_BY_POLICY";
    supervisorCoSignature?: string;
    error?: string;
  };
  /** SHA-256 of pre-action viewport/entity state. */
  preStateHash: string;
  /** SHA-256 of post-action state; equals preStateHash when nothing ran. */
  postStateHash: string;
  /** PQC transport posture the action ran under, when the funnel is
   * configured with one. Under the packet hash like every other field. */
  pqcAuditRecord?: PqcAuditStamp;
  /** packetHash of the previous packet; genesis anchor for the first. */
  previousPacketHash: string;
  /** SHA-256(previousPacketHash + canonicalPayload). */
  packetHash: string;
}

/**
 * The bytes a grant signature covers: the delegation's *terms* — everything
 * except the signature and the lifecycle `status`. Status is deliberately
 * outside the signature: revocation is registry-live state flipped by the
 * store without access to the delegator's key, and a kill-switch that had
 * to wait for the delegator to come back and re-sign would not be a
 * kill-switch. Everything the delegator actually promised — who, what
 * tools, what clearance, what window, what chain — is under the signature,
 * so none of it can be widened after issue.
 */
export function grantSigningPayload(
  grant: Omit<DelegatedAuthorityGrant, "grantSignature" | "status">,
): string {
  return canonicalJson({
    grantId: grant.grantId,
    agentDid: grant.agentDid,
    delegatorDid: grant.delegatorDid,
    delegationChain: [...grant.delegationChain],
    clearanceLevel: grant.clearanceLevel,
    grantedTools: [...grant.grantedTools],
    requiresMultiSigTools: [...grant.requiresMultiSigTools],
    rateLimitMaxPerHour: grant.rateLimitMaxPerHour,
    validFromUtc: grant.validFromUtc,
    expiresAtUtc: grant.expiresAtUtc,
  });
}

/**
 * The key authority for delegation: signs grants and mints/verifies
 * per-invocation supervisor co-signatures. HMAC for the same reason as the
 * credential registry — issuer and verifier are the same runtime, and
 * WebCrypto Ed25519 support is still uneven. The asymmetric upgrade path is
 * this class's seam.
 */
export class DelegationAuthority {
  private readonly key: Promise<CryptoKey>;

  constructor(signingSecret: string) {
    this.key = importHmacKey(signingSecret);
  }

  async signGrant(
    unsigned: Omit<DelegatedAuthorityGrant, "grantSignature">,
  ): Promise<DelegatedAuthorityGrant> {
    const grantSignature = await hmacSignHex(
      await this.key,
      grantSigningPayload(unsigned),
    );
    return { ...unsigned, grantSignature };
  }

  /** True when the grant's terms are exactly as the delegator signed them. */
  async verifyGrant(grant: DelegatedAuthorityGrant): Promise<boolean> {
    return hmacVerifyHex(
      await this.key,
      grantSigningPayload(grant),
      grant.grantSignature,
    );
  }

  /** Co-signature payload binds the grant id as well as the tool, so a
   * ticket minted under one grant dies with that grant. */
  private coSignaturePayload(grant: DelegatedAuthorityGrant, toolName: string): string {
    return canonicalJson({
      standard: "SYNTRIASS-dual-key-v2",
      grantId: grant.grantId,
      agentDid: grant.agentDid,
      delegatorDid: grant.delegatorDid,
      toolName,
    });
  }

  async issueCoSignature(
    grant: DelegatedAuthorityGrant,
    toolName: string,
  ): Promise<string> {
    return hmacSignHex(await this.key, this.coSignaturePayload(grant, toolName));
  }

  async verifyCoSignature(
    grant: DelegatedAuthorityGrant,
    toolName: string,
    signatureHex: string,
  ): Promise<boolean> {
    return hmacVerifyHex(
      await this.key,
      this.coSignaturePayload(grant, toolName),
      signatureHex,
    );
  }
}
