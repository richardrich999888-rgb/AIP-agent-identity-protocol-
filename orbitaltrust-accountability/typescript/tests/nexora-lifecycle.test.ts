/**
 * The NEXORA/AIP subsystem's contract, as executable claims:
 *
 * - lifecycle chains are born exactly once, close forever on a terminal
 *   revocation, and survive a service restart without forking;
 * - delegation only attenuates: scope, clearance and multi-sig obligations
 *   never widen down the tree, and a mid-tree revocation cascades;
 * - evidence packets bind the lifecycle head, actions seal back into the
 *   lifecycle chain, and the verifier catches tampering in either chain —
 *   or in the cross-references between them — with the exact sequence.
 */

import { beforeEach, describe, expect, it } from "vitest";

import { toAgentDid, toOfficerDid } from "../src/telemetry/agent-identity/persistent-identity";
import type { ToolManifest } from "../src/telemetry/agent-identity/permission-guard";
import { MemoryNexoraStore } from "../src/telemetry/nexora/nexora-store";
import { NexoraAnchorChain } from "../src/telemetry/nexora/anchor-chain";
import {
  AipDelegationAuthority,
  AipDelegationGraph,
} from "../src/telemetry/nexora/delegation-graph";
import { AipEvidenceSealer } from "../src/telemetry/nexora/aip-evidence";
import {
  NexoraVerifier,
  aipPacketPayloadBytes,
} from "../src/telemetry/nexora/nexora-verifier";
import { sha256Hex } from "../src/telemetry/crypto";

const OFFICER = toOfficerDid("OFFICER-IAF-882");
const MOTHERSHIP = toAgentDid("AGT-0100-MOTHERSHIP");
const SUBAGENT = toAgentDid("AGT-0481-JARVIS");
const MODEL_A = "a1".repeat(32);
const MODEL_B = "b2".repeat(32);
const BURN = "execute_thruster_burn";

const MANIFEST: ToolManifest = {
  fly_to: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
  screen_conjunctions: {
    requiredPermission: "SCREEN_CONJUNCTIONS",
    minimumClearance: "CONFIDENTIAL",
  },
  [BURN]: { requiredPermission: "EXECUTE_MANEUVER", minimumClearance: "SECRET" },
};

let store: MemoryNexoraStore;
let chain: NexoraAnchorChain;
let authority: AipDelegationAuthority;
let graph: AipDelegationGraph;
let sealer: AipEvidenceSealer;
let verifier: NexoraVerifier;

function makeSealer(): AipEvidenceSealer {
  return new AipEvidenceSealer({ store, anchors: chain, graph, authority, manifest: MANIFEST });
}

async function birth(agentDid: typeof MOTHERSHIP, modelDigest = MODEL_A) {
  return chain.appendAnchor({
    anchorType: "AGENT_GENESIS",
    agentDid,
    actorDid: OFFICER,
    payload: { modelDigest },
  });
}

function toolRequest(overrides: Record<string, unknown> = {}) {
  return {
    agentDid: SUBAGENT,
    runtimeModelDigest: MODEL_A,
    rawPrompt: "voice: fly to Delhi",
    toolName: "fly_to",
    inputParams: { target: "Delhi" },
    preState: { camera: [78.9, 20.5] },
    execute: () => ({ camera: [77.2, 28.6] }),
    ...overrides,
  } as Parameters<AipEvidenceSealer["execute"]>[0];
}

beforeEach(() => {
  store = new MemoryNexoraStore();
  chain = new NexoraAnchorChain(store);
  authority = new AipDelegationAuthority("aip-secret");
  graph = new AipDelegationGraph(store, chain, authority);
  sealer = makeSealer();
  verifier = new NexoraVerifier(store);
});

describe("lifecycle anchor chain", () => {
  it("is born exactly once, genesis first, with a model digest bound", async () => {
    await expect(
      chain.appendAnchor({
        anchorType: "OWNERSHIP_BINDING",
        agentDid: SUBAGENT,
        actorDid: OFFICER,
        payload: { owner: "DEFENCE_SPACE_AGENCY" },
      }),
    ).rejects.toThrow(/must be AGENT_GENESIS/);
    await expect(
      chain.appendAnchor({
        anchorType: "AGENT_GENESIS",
        agentDid: SUBAGENT,
        actorDid: OFFICER,
        payload: {},
      }),
    ).rejects.toThrow(/must bind a modelDigest/);

    const genesis = await birth(SUBAGENT);
    expect(genesis.sequenceNumber).toBe(1);
    await expect(birth(SUBAGENT)).rejects.toThrow(/already has a genesis/);
  });

  it("chains milestones and closes forever on a terminal revocation", async () => {
    await birth(SUBAGENT);
    await chain.appendAnchor({
      anchorType: "OWNERSHIP_BINDING",
      agentDid: SUBAGENT,
      actorDid: OFFICER,
      payload: { owner: "DEFENCE_SPACE_AGENCY" },
    });
    // A suspension is a milestone, not an ending.
    await chain.appendAnchor({
      anchorType: "AUTHORITY_REVOCATION",
      agentDid: SUBAGENT,
      actorDid: OFFICER,
      payload: { terminal: false, reason: "shift review" },
    });
    await chain.appendAnchor({
      anchorType: "AUTHORITY_REVOCATION",
      agentDid: SUBAGENT,
      actorDid: OFFICER,
      payload: { terminal: true, reason: "decommissioned" },
    });
    await expect(
      chain.appendAnchor({
        anchorType: "CAPABILITY_MODULATION",
        agentDid: SUBAGENT,
        actorDid: OFFICER,
        payload: {},
      }),
    ).rejects.toThrow(/closed by a terminal revocation/);
    await expect(verifier.verifyAnchorChain(SUBAGENT)).resolves.toEqual({
      valid: true,
      total: 4,
    });
  });

  it("continues across a restart instead of forking, and detects tampering exactly", async () => {
    await birth(SUBAGENT);
    const restarted = new NexoraAnchorChain(store);
    const second = await restarted.appendAnchor({
      anchorType: "AIR_GAP_ENCLAVE_TRANSFER",
      agentDid: SUBAGENT,
      actorDid: OFFICER,
      payload: { enclave: "TPM_2_0" },
    });
    expect(second.sequenceNumber).toBe(2);
    await expect(verifier.verifyAnchorChain(SUBAGENT)).resolves.toMatchObject({
      valid: true,
      total: 2,
    });

    const anchors = await store.listAnchorsForAgent(SUBAGENT);
    anchors[1].payload = { enclave: "SOFTWARE_SANDBOX" }; // hide the transfer
    const verdict = await verifier.verifyAnchorChain(SUBAGENT);
    expect(verdict.valid).toBe(false);
    expect(verdict.brokenSequence).toBe(2);
    expect(verdict.reason).toMatch(/modified after sealing/);
  });
});

describe("delegation graph attenuation", () => {
  beforeEach(async () => {
    await birth(MOTHERSHIP);
    await birth(SUBAGENT);
    await graph.delegate({
      parentDid: OFFICER,
      childDid: MOTHERSHIP,
      scope: ["fly_to", "screen_conjunctions", BURN],
      multiSigTools: [BURN],
      clearanceLevel: "SECRET",
      validForMs: 60 * 60 * 1000,
    });
  });

  it("refuses scope, clearance and cycle violations at delegation time", async () => {
    await expect(
      graph.delegate({
        parentDid: MOTHERSHIP,
        childDid: SUBAGENT,
        scope: ["fly_to", "override_airspace"],
        clearanceLevel: "RESTRICTED",
        validForMs: 3600_000,
      }),
    ).rejects.toThrow(/scope attenuation violated/);
    await expect(
      graph.delegate({
        parentDid: MOTHERSHIP,
        childDid: SUBAGENT,
        scope: ["fly_to"],
        clearanceLevel: "TOP_SECRET",
        validForMs: 3600_000,
      }),
    ).rejects.toThrow(/clearance attenuation violated/);
    await expect(
      graph.delegate({
        parentDid: MOTHERSHIP,
        childDid: MOTHERSHIP,
        scope: ["fly_to"],
        clearanceLevel: "SECRET",
        validForMs: 3600_000,
      }),
    ).rejects.toThrow(/cycle/);
  });

  it("intersects scope, inherits multi-sig, and takes the weakest clearance", async () => {
    await graph.delegate({
      parentDid: MOTHERSHIP,
      childDid: SUBAGENT,
      scope: ["fly_to", BURN],
      clearanceLevel: "CONFIDENTIAL",
      validForMs: 3600_000,
    });
    const effective = await graph.resolveAuthority(SUBAGENT);
    expect(effective).not.toBeNull();
    expect(effective!.path).toEqual([OFFICER, MOTHERSHIP, SUBAGENT]);
    expect(effective!.scope.sort()).toEqual(["fly_to", BURN].sort());
    // BURN was multi-sig at the root; the sub-agent cannot shed it.
    expect(effective!.multiSigTools).toContain(BURN);
    expect(effective!.clearanceLevel).toBe("CONFIDENTIAL");
  });

  it("cascades a mid-tree revocation to the whole subtree", async () => {
    const rootEdge = (await store.listEdgesForChild(MOTHERSHIP))[0];
    await graph.delegate({
      parentDid: MOTHERSHIP,
      childDid: SUBAGENT,
      scope: ["fly_to"],
      clearanceLevel: "CONFIDENTIAL",
      validForMs: 3600_000,
    });
    expect(await graph.resolveAuthority(SUBAGENT)).not.toBeNull();

    await graph.revokeEdge(rootEdge.edgeId, OFFICER, "officer kill-switch");
    expect(await graph.resolveAuthority(SUBAGENT)).toBeNull();
    expect(await graph.resolveAuthority(MOTHERSHIP)).toBeNull();

    // The revocation is anchored in the mothership's verifiable history.
    const anchors = await store.listAnchorsForAgent(MOTHERSHIP);
    const revocation = anchors.find((a) => a.anchorType === "AUTHORITY_REVOCATION");
    expect(revocation?.payload.reason).toBe("officer kill-switch");
  });

  it("an edge widened in storage after signing confers nothing", async () => {
    await graph.delegate({
      parentDid: MOTHERSHIP,
      childDid: SUBAGENT,
      scope: ["fly_to"],
      clearanceLevel: "CONFIDENTIAL",
      validForMs: 3600_000,
    });
    const edge = (await store.listEdgesForChild(SUBAGENT))[0];
    edge.scope.push(BURN); // hostile widening, straight into storage
    await store.updateEdge(edge);
    // The edge's signature no longer verifies, so the whole path dissolves.
    expect(await graph.resolveAuthority(SUBAGENT)).toBeNull();
  });
});

describe("AIP evidence sealing", () => {
  beforeEach(async () => {
    await birth(MOTHERSHIP);
    await birth(SUBAGENT);
    await graph.delegate({
      parentDid: OFFICER,
      childDid: MOTHERSHIP,
      scope: ["fly_to", "screen_conjunctions", BURN],
      multiSigTools: [BURN],
      clearanceLevel: "SECRET",
      validForMs: 3600_000,
    });
    await graph.delegate({
      parentDid: MOTHERSHIP,
      childDid: SUBAGENT,
      scope: ["fly_to", BURN],
      clearanceLevel: "SECRET",
      validForMs: 3600_000,
    });
  });

  it("seals a permitted action bound to the lifecycle head, and anchors it back", async () => {
    const outcome = await sealer.execute(toolRequest());
    expect(outcome.status).toBe("SUCCESS");
    expect(outcome.packet.delegationPath).toEqual([OFFICER, MOTHERSHIP, SUBAGENT]);
    expect(outcome.packet.anchorHash).toMatch(/^[0-9a-f]{64}$/);
    expect(outcome.sealAnchorId).not.toBeNull();

    const report = await verifier.verifyAgent(SUBAGENT);
    expect(report.anchors.valid).toBe(true);
    expect(report.packets.valid).toBe(true);
    expect(report.crossConsistent).toBe(true);
    expect(report.findings).toEqual([]);

    const anchors = await store.listAnchorsForAgent(SUBAGENT);
    const seal = anchors.find((a) => a.anchorType === "ACTION_EXECUTION_SEAL");
    expect(seal?.payload.packetHash).toBe(outcome.packet.packetHash);
  });

  it("enforces the lifecycle chain's model binding across a migration", async () => {
    expect((await sealer.execute(toolRequest())).status).toBe("SUCCESS");

    await chain.appendAnchor({
      anchorType: "MODEL_VERSION_MIGRATION",
      agentDid: SUBAGENT,
      actorDid: OFFICER,
      payload: { modelDigest: MODEL_B, reason: "quantization update" },
    });
    const stale = await sealer.execute(toolRequest()); // still running MODEL_A
    expect(stale.status).toBe("BLOCKED_BY_POLICY");
    if (!stale.verdict.permitted) {
      expect(stale.verdict.rejection.code).toBe("MODEL_INTEGRITY_COMPROMISED");
    }
    const migrated = await sealer.execute(toolRequest({ runtimeModelDigest: MODEL_B }));
    expect(migrated.status).toBe("SUCCESS");
  });

  it("gates inherited multi-sig tools on a verifiable co-signature", async () => {
    const noTicket = await sealer.execute(toolRequest({ toolName: BURN }));
    expect(noTicket.status).toBe("BLOCKED_BY_POLICY");
    if (!noTicket.verdict.permitted) {
      expect(noTicket.verdict.rejection.code).toBe("REQUIRES_SUPERVISOR_MULTISIG");
    }

    const agentEdge = (await store.listEdgesForChild(SUBAGENT))[0];
    const wrongTool = await authority.issueCoSignature(agentEdge, "fly_to");
    const replayed = await sealer.execute(
      toolRequest({ toolName: BURN, supervisorCoSignature: wrongTool }),
    );
    expect(replayed.status).toBe("BLOCKED_BY_POLICY");

    const ticket = await authority.issueCoSignature(agentEdge, BURN);
    const approved = await sealer.execute(
      toolRequest({ toolName: BURN, supervisorCoSignature: ticket }),
    );
    expect(approved.status).toBe("SUCCESS");
    expect(approved.packet.toolExecuted.supervisorCoSignature).toBe(ticket);
  });

  it("seals refusals, and a terminally revoked agent seals unanchored evidence", async () => {
    const unknown = await sealer.execute(toolRequest({ toolName: "self_destruct" }));
    expect(unknown.status).toBe("BLOCKED_BY_POLICY");

    await chain.appendAnchor({
      anchorType: "AUTHORITY_REVOCATION",
      agentDid: SUBAGENT,
      actorDid: OFFICER,
      payload: { terminal: true, reason: "decommissioned" },
    });
    const afterKill = await sealer.execute(toolRequest());
    expect(afterKill.status).toBe("BLOCKED_BY_POLICY");
    if (!afterKill.verdict.permitted) {
      expect(afterKill.verdict.rejection.code).toBe("LIFECYCLE_CLOSED");
    }
    expect(afterKill.packet.anchorHash).toBe("");
    expect(afterKill.sealAnchorId).toBeNull();

    const report = await verifier.verifyAgent(SUBAGENT);
    expect(report.crossConsistent).toBe(true);
  });
});

describe("independent deterministic verification", () => {
  beforeEach(async () => {
    await birth(SUBAGENT);
    await graph.delegate({
      parentDid: OFFICER,
      childDid: SUBAGENT,
      scope: ["fly_to"],
      clearanceLevel: "SECRET",
      validForMs: 3600_000,
    });
    await sealer.execute(toolRequest());
    await sealer.execute(toolRequest({ rawPrompt: "voice: fly to Leh" }));
  });

  it("detects a tampered packet with the exact sequence", async () => {
    const packets = await store.listPacketsForAgent(SUBAGENT);
    packets[1].rawPrompt = "voice: something innocuous";
    const verdict = await verifier.verifyPacketChain(SUBAGENT);
    expect(verdict.valid).toBe(false);
    expect(verdict.brokenSequence).toBe(2);
  });

  it("detects a re-hashed packet whose anchor binding was forged", async () => {
    const packets = await store.listPacketsForAgent(SUBAGENT);
    const last = packets[packets.length - 1];
    // A smart forger rewrites the binding AND recomputes the packet hash —
    // the packet chain then verifies, but the cross-check exposes a
    // lifecycle state that never existed.
    last.anchorHash = "9".repeat(64);
    const { previousPacketHash, packetHash: _old, ...payload } = last;
    last.packetHash = await sha256Hex(previousPacketHash + aipPacketPayloadBytes(payload));

    const report = await verifier.verifyAgent(SUBAGENT);
    expect(report.packets.valid).toBe(true);
    expect(report.crossConsistent).toBe(false);
    expect(report.findings.join(" ")).toMatch(/not in the agent's lifecycle chain/);
  });

  it("detects a re-hashed seal anchor naming a packet that never existed", async () => {
    const anchors = await store.listAnchorsForAgent(SUBAGENT);
    const seal = anchors[anchors.length - 1]; // last anchor is the newest seal
    expect(seal.anchorType).toBe("ACTION_EXECUTION_SEAL");
    // Forge the referent AND recompute the anchor hash — the anchor chain
    // then verifies, but the named packet is absent from the ledger.
    seal.payload = { ...seal.payload, packetHash: "9".repeat(64) };
    const { previousAnchorHash, anchorHash: _old, ...payload } = seal;
    const { anchorPayloadBytes } = await import(
      "../src/telemetry/nexora/anchor-chain"
    );
    seal.anchorHash = await sha256Hex(previousAnchorHash + anchorPayloadBytes(payload));

    const report = await verifier.verifyAgent(SUBAGENT);
    expect(report.anchors.valid).toBe(true);
    expect(report.crossConsistent).toBe(false);
    expect(report.findings.join(" ")).toMatch(/absent from the ledger/);
  });

  it("exports a byte-faithful jsonl dossier", async () => {
    const jsonl = await verifier.exportAipDossierJsonl(SUBAGENT);
    const lines = jsonl.trim().split("\n");
    expect(lines).toHaveLength(2);
    const parsed = JSON.parse(lines[0]);
    expect(parsed.agentDid).toBe(SUBAGENT);
    expect(parsed.packetHash).toMatch(/^[0-9a-f]{64}$/);
  });
});
