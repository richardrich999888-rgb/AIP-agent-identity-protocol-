/**
 * The persistent-identity subsystem's contract, as executable claims:
 *
 * - identity is durable: rotating or revoking authority never touches it,
 *   and a funnel restarted over the same store continues the chain rather
 *   than forking it;
 * - authority is dynamic: a revocation or a narrowed grant takes effect on
 *   the very next invocation;
 * - sub-agent delegation chains ride into the sealed evidence;
 * - one historical edit is detected with the exact sequence number;
 * - multi-sig tools execute only under a verifiable supervisor ticket.
 */

import { beforeEach, describe, expect, it } from "vitest";

import {
  DelegationAuthority,
  toAgentDid,
  toOfficerDid,
  type DelegatedAuthorityGrant,
  type PersistentAgentIdentity,
} from "../src/telemetry/agent-identity/persistent-identity";
import { MemoryIdentityStore } from "../src/telemetry/agent-identity/identity-store";
import {
  GovernedExecutionFunnel,
  type GovernedToolRequest,
} from "../src/telemetry/agent-accountability/governed-execution";
import {
  EvidenceVerifier,
  evidencePacketPayload,
} from "../src/telemetry/agent-accountability/verifier";
import { sha256Hex } from "../src/telemetry/crypto";
import type { ToolManifest } from "../src/telemetry/agent-identity/permission-guard";

const AGENT_DID = toAgentDid("AGT-0481-JARVIS");
const OFFICER_DID = toOfficerDid("OFFICER-IAF-882");
const MODEL_DIGEST = "3".repeat(64);
const PROMPT_HASH = "4".repeat(64);
const RUNTIME = { modelDigest: MODEL_DIGEST, systemPromptHash: PROMPT_HASH };

const MANIFEST: ToolManifest = {
  fly_to: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
  screen_conjunctions: {
    requiredPermission: "SCREEN_CONJUNCTIONS",
    minimumClearance: "CONFIDENTIAL",
  },
  execute_thruster_burn: {
    requiredPermission: "EXECUTE_MANEUVER",
    minimumClearance: "TOP_SECRET",
  },
};

const IDENTITY: PersistentAgentIdentity = {
  did: AGENT_DID,
  agentId: "AGT-0481-JARVIS",
  agentName: "Orbital Tactical Copilot",
  organization: "DEFENCE_SPACE_AGENCY",
  publicKey: "a".repeat(64),
  modelDigest: MODEL_DIGEST,
  systemPromptHash: PROMPT_HASH,
  enclaveType: "SOFTWARE_SANDBOX",
  createdAtUtc: "2026-08-01T00:00:00.000Z",
  version: "1.0.0",
};

let store: MemoryIdentityStore;
let authority: DelegationAuthority;
let funnel: GovernedExecutionFunnel;
let verifier: EvidenceVerifier;

function makeFunnel(): GovernedExecutionFunnel {
  return new GovernedExecutionFunnel({
    store,
    manifest: MANIFEST,
    verifyGrant: (g) => authority.verifyGrant(g),
    verifyCoSignature: (g, tool, sig) => authority.verifyCoSignature(g, tool, sig),
  });
}

async function issueGrant(
  overrides: Partial<Omit<DelegatedAuthorityGrant, "grantSignature">> = {},
): Promise<DelegatedAuthorityGrant> {
  const now = Date.now();
  const grant = await authority.signGrant({
    grantId: crypto.randomUUID(),
    agentDid: AGENT_DID,
    delegatorDid: OFFICER_DID,
    delegationChain: [OFFICER_DID],
    clearanceLevel: "TOP_SECRET",
    grantedTools: ["fly_to", "screen_conjunctions", "execute_thruster_burn"],
    requiresMultiSigTools: [],
    rateLimitMaxPerHour: 100,
    validFromUtc: new Date(now - 1000).toISOString(),
    expiresAtUtc: new Date(now + 60 * 60 * 1000).toISOString(),
    status: "ACTIVE",
    ...overrides,
  });
  await store.issueAuthorityGrant(grant);
  return grant;
}

function request(
  overrides: Partial<GovernedToolRequest> = {},
): GovernedToolRequest {
  return {
    agentDid: AGENT_DID,
    runtimeParameters: RUNTIME,
    rawPrompt: "voice: fly to Delhi",
    toolName: "fly_to",
    inputParams: { target: "Delhi" },
    preState: { camera: [78.9, 20.5, 1.2e7], shader: "FLIR" },
    execute: () => ({ camera: [77.2, 28.6, 5e5], shader: "FLIR" }),
    ...overrides,
  };
}

beforeEach(async () => {
  store = new MemoryIdentityStore();
  authority = new DelegationAuthority("delegation-secret");
  funnel = makeFunnel();
  verifier = new EvidenceVerifier(store);
  await store.registerPersistentIdentity(IDENTITY);
});

describe("identity persistence across restarts", () => {
  it("keeps identity intact while grants rotate, and a restarted funnel continues the chain", async () => {
    const first = await issueGrant();
    await funnel.execute(request());
    await store.revokeAuthorityGrant(first.grantId, "shift change");
    await issueGrant({ grantedTools: ["fly_to"] });

    // The durable identity is byte-identical through the whole rotation.
    await expect(store.getPersistentIdentity(AGENT_DID)).resolves.toEqual(IDENTITY);

    // "Restart": a fresh funnel over the same store must continue the
    // persisted chain, not fork a second genesis.
    const restarted = makeFunnel();
    const outcome = await restarted.execute(request());
    expect(outcome.packet.sequenceNumber).toBe(2);
    const audit = await verifier.verifyEvidenceChain(AGENT_DID);
    expect(audit).toEqual({ valid: true, totalPackets: 2 });
  });

  it("refuses an unregistered identity and a duplicate registration", async () => {
    await expect(store.registerPersistentIdentity(IDENTITY)).rejects.toThrow(
      /already registered/,
    );
    await issueGrant({ agentDid: toAgentDid("AGT-GHOST") });
    const ghost = await new GovernedExecutionFunnel({
      store,
      manifest: MANIFEST,
      verifyGrant: (g) => authority.verifyGrant(g),
      verifyCoSignature: () => false,
    }).execute(request({ agentDid: toAgentDid("AGT-GHOST") }));
    expect(ghost.status).toBe("BLOCKED_BY_POLICY");
    if (!ghost.verdict.permitted) {
      expect(ghost.verdict.rejection.code).toBe("IDENTITY_NOT_REGISTERED");
      expect(ghost.verdict.rejection.stage).toBe(1);
    }
  });

  it("blocks when runtime parameters drift from the stored identity", async () => {
    await issueGrant();
    const outcome = await funnel.execute(
      request({
        runtimeParameters: { modelDigest: "f".repeat(64), systemPromptHash: PROMPT_HASH },
      }),
    );
    expect(outcome.status).toBe("BLOCKED_BY_POLICY");
    if (!outcome.verdict.permitted) {
      expect(outcome.verdict.rejection.code).toBe("MODEL_INTEGRITY_COMPROMISED");
    }
  });
});

describe("dynamic authority modulation", () => {
  it("revocation takes effect on the next invocation without touching identity", async () => {
    const grant = await issueGrant();
    expect((await funnel.execute(request())).status).toBe("SUCCESS");

    await store.revokeAuthorityGrant(grant.grantId, "operator kill-switch");
    const blocked = await funnel.execute(request());
    expect(blocked.status).toBe("BLOCKED_BY_POLICY");
    if (!blocked.verdict.permitted) {
      expect(blocked.verdict.rejection.code).toBe("NO_ACTIVE_GRANT");
      expect(blocked.verdict.rejection.stage).toBe(2);
    }
    const stored = await store.getGrant(grant.grantId);
    expect(stored?.status).toBe("REVOKED");
    expect(stored?.revocationReason).toBe("operator kill-switch");
    await expect(store.getPersistentIdentity(AGENT_DID)).resolves.toEqual(IDENTITY);
  });

  it("a narrowed replacement grant modulates authority immediately", async () => {
    const wide = await issueGrant();
    expect((await funnel.execute(request({ toolName: "screen_conjunctions" }))).status).toBe(
      "SUCCESS",
    );
    await store.revokeAuthorityGrant(wide.grantId, "narrowing to navigation only");
    await issueGrant({ grantedTools: ["fly_to"], clearanceLevel: "RESTRICTED" });

    const denied = await funnel.execute(request({ toolName: "screen_conjunctions" }));
    expect(denied.status).toBe("BLOCKED_BY_POLICY");
    if (!denied.verdict.permitted) {
      expect(denied.verdict.rejection.code).toBe("TOOL_NOT_GRANTED");
    }
    expect((await funnel.execute(request())).status).toBe("SUCCESS");
  });

  it("rejects a grant whose terms were widened after signing", async () => {
    const grant = await issueGrant({ grantedTools: ["fly_to"] });
    // Hostile edit straight into storage: add a tool the delegator never signed.
    (await store.getGrant(grant.grantId))!.grantedTools.push("execute_thruster_burn");
    const outcome = await funnel.execute(request({ toolName: "execute_thruster_burn" }));
    expect(outcome.status).toBe("BLOCKED_BY_POLICY");
    if (!outcome.verdict.permitted) {
      expect(outcome.verdict.rejection.code).toBe("GRANT_SIGNATURE_INVALID");
    }
  });

  it("enforces the grant's hourly rate limit on executed actions", async () => {
    await issueGrant({ rateLimitMaxPerHour: 2 });
    expect((await funnel.execute(request())).status).toBe("SUCCESS");
    expect((await funnel.execute(request())).status).toBe("SUCCESS");
    const third = await funnel.execute(request());
    expect(third.status).toBe("BLOCKED_BY_POLICY");
    if (!third.verdict.permitted) {
      expect(third.verdict.rejection.code).toBe("RATE_LIMIT_EXCEEDED");
    }
  });
});

describe("sub-agent delegation tracking", () => {
  it("preserves the upstream delegation chain and binds it into the packet", async () => {
    const chain = [
      OFFICER_DID,
      "did:syntriass:agent:AGT-0100-MOTHERSHIP",
      AGENT_DID,
    ];
    await issueGrant({ delegationChain: chain });
    const outcome = await funnel.execute(request());
    expect(outcome.packet.delegationChain).toEqual(chain);
    expect(outcome.packet.delegatorDid).toBe(OFFICER_DID);

    // The chain is under the packet hash: rewriting history to hide the
    // intermediary breaks verification.
    const packets = await store.listEvidenceForAgent(AGENT_DID);
    packets[0].delegationChain = [OFFICER_DID, AGENT_DID];
    const audit = await verifier.verifyEvidenceChain(AGENT_DID);
    expect(audit.valid).toBe(false);
  });
});

describe("tamper rejection", () => {
  it("detects an edited historical field with the exact sequence number", async () => {
    await issueGrant();
    await funnel.execute(request());
    await funnel.execute(request({ rawPrompt: "voice: screen the belt" }));
    await funnel.execute(request());
    const packets = await store.listEvidenceForAgent(AGENT_DID);
    packets[1].rawPrompt = "voice: something innocuous";

    const audit = await verifier.verifyEvidenceChain(AGENT_DID);
    expect(audit.valid).toBe(false);
    expect(audit.brokenSequence).toBe(2);
    expect(audit.totalPackets).toBe(3);
    expect(audit.reason).toMatch(/modified after sealing/);
  });

  it("a re-hashed forgery is exposed by the next packet's link", async () => {
    await issueGrant();
    await funnel.execute(request());
    await funnel.execute(request());
    const packets = await store.listEvidenceForAgent(AGENT_DID);
    packets[0].rawPrompt = "forged";
    const { previousPacketHash, packetHash: _old, ...payload } = packets[0];
    packets[0].packetHash = await sha256Hex(
      previousPacketHash + evidencePacketPayload(payload),
    );
    const audit = await verifier.verifyEvidenceChain(AGENT_DID);
    expect(audit.valid).toBe(false);
    expect(audit.brokenSequence).toBe(2);
  });

  it("verifies pre/post state hashes are part of the sealed payload", async () => {
    await issueGrant();
    const outcome = await funnel.execute(request());
    expect(outcome.packet.preStateHash).toMatch(/^[0-9a-f]{64}$/);
    expect(outcome.packet.postStateHash).toMatch(/^[0-9a-f]{64}$/);
    expect(outcome.packet.postStateHash).not.toBe(outcome.packet.preStateHash);

    const packets = await store.listEvidenceForAgent(AGENT_DID);
    packets[0].postStateHash = packets[0].preStateHash; // hide the effect
    const audit = await verifier.verifyEvidenceChain(AGENT_DID);
    expect(audit.valid).toBe(false);
    expect(audit.brokenSequence).toBe(1);
  });
});

describe("multi-sig gating", () => {
  const BURN = "execute_thruster_burn";

  it("denies a restricted tool without a co-signature, sealing the refusal", async () => {
    await issueGrant({ requiresMultiSigTools: [BURN] });
    const outcome = await funnel.execute(request({ toolName: BURN }));
    expect(outcome.status).toBe("BLOCKED_BY_POLICY");
    if (!outcome.verdict.permitted) {
      expect(outcome.verdict.rejection.code).toBe("REQUIRES_SUPERVISOR_MULTISIG");
      expect(outcome.verdict.rejection.detail).toBe(
        "High-consequence tool requires human supervisor co-signature",
      );
    }
    await expect(verifier.verifyEvidenceChain(AGENT_DID)).resolves.toMatchObject({
      valid: true,
      totalPackets: 1,
    });
  });

  it("rejects forged and cross-tool tickets, accepts the genuine one", async () => {
    const grant = await issueGrant({ requiresMultiSigTools: [BURN] });

    const forged = await funnel.execute(
      request({ toolName: BURN, supervisorCoSignature: "ab".repeat(32) }),
    );
    expect(forged.status).toBe("BLOCKED_BY_POLICY");

    const wrongTool = await authority.issueCoSignature(grant, "fly_to");
    const replayed = await funnel.execute(
      request({ toolName: BURN, supervisorCoSignature: wrongTool }),
    );
    expect(replayed.status).toBe("BLOCKED_BY_POLICY");

    const ticket = await authority.issueCoSignature(grant, BURN);
    const approved = await funnel.execute(
      request({ toolName: BURN, supervisorCoSignature: ticket }),
    );
    expect(approved.status).toBe("SUCCESS");
    expect(approved.packet.toolExecuted.supervisorCoSignature).toBe(ticket);
  });
});

describe("dossier export", () => {
  it("exports byte-faithful jsonl and RFC-4180 csv", async () => {
    await issueGrant();
    await funnel.execute(request({ rawPrompt: 'fly to "Delhi",\nfast' }));
    const jsonl = await verifier.exportEvidenceDossierJsonl(AGENT_DID);
    expect(jsonl.trim().split("\n")).toHaveLength(1);
    const parsed = JSON.parse(jsonl.trim());
    expect(parsed.agentDid).toBe(AGENT_DID);
    expect(parsed.packetHash).toMatch(/^[0-9a-f]{64}$/);

    const csv = await verifier.exportEvidenceDossierCsv(AGENT_DID);
    const lines = csv.trim().split("\r\n");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('"packetHash"');
    expect(lines[1]).toContain('""Delhi""');
  });
});
