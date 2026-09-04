/**
 * The copilot's NEXORA binding, as executable claims:
 *
 * - arming the copilot anchors the spec'd lifecycle sequence — AGENT_GENESIS
 *   → SUPERVISOR_DELEGATION → CAPABILITY_MODULATION — exactly once;
 * - every governed dispatch seals an AIP evidence packet with pre/post state
 *   hashes AND an ACTION_EXECUTION_SEAL anchor naming that packet, and the
 *   independent verifier finds both chains valid and cross-consistent;
 * - a verb outside the grant is blocked by the outer accountability tier
 *   before the AIP tier runs — one refusal, one record, no orphan packet;
 * - editing a sealed packet in storage is detected by the verifier with the
 *   exact broken sequence — what the tab's INTEGRITY BREACH banner renders.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import type { TacticalCapabilities, ViewportContext } from "../src/agent/capabilities";
import {
  ensureJarvisGoverned,
  governedDispatchTool,
  JARVIS_AGENT_ID,
  type GovernanceDeps,
} from "../src/agent/governed-dispatch";
import { IdentityRegistry } from "../src/telemetry/agent-identity/identity-registry";
import { toAgentDid } from "../src/telemetry/agent-identity/persistent-identity";
import { AccountabilityService } from "../src/telemetry/agent-accountability/accountability-service";
import { MemoryLedgerStorage } from "../src/telemetry/agent-accountability/ledger-storage";
import { CONSOLE_TOOL_MANIFEST } from "../src/telemetry/governance";
import { MemoryNexoraStore } from "../src/telemetry/nexora/nexora-store";
import { NexoraAnchorChain } from "../src/telemetry/nexora/anchor-chain";
import {
  AipDelegationAuthority,
  AipDelegationGraph,
} from "../src/telemetry/nexora/delegation-graph";
import { AipEvidenceSealer } from "../src/telemetry/nexora/aip-evidence";
import { NexoraVerifier } from "../src/telemetry/nexora/nexora-verifier";

const JARVIS_DID = toAgentDid(JARVIS_AGENT_ID);

const VIEWPORT: ViewportContext = {
  camera: { latitudeDeg: 20.5, longitudeDeg: 78.9, altitudeKm: 12000, headingDeg: 0, pitchDeg: -90 },
  selected: { id: "SPACE-25544", kind: "space", name: "ISS" },
  enabledLayers: [],
  shaderMode: "flir",
  counts: { air: 0, sea: 0, orbit: 1, alertCells: 0 },
};

function mockCaps(): TacticalCapabilities {
  return {
    flyToLocation: vi.fn(async () => "Flying."),
    orbitEntity: vi.fn(async () => "Orbiting."),
    cockpitMode: vi.fn(async () => "Locked."),
    setShaderMode: vi.fn(() => "Thermal."),
    toggleDataLayer: vi.fn(() => "Toggled."),
    annotateBoundingBox: vi.fn(() => "Marked."),
    getNearbyContacts: vi.fn(async () => []),
    screenConjunctionThreats: vi.fn(async () => []),
    computeAvoidanceManeuver: vi.fn(async () => ({
      satelliteId: "1",
      deltaVMS: 0.42,
      pcBefore: 1e-3,
      pcAfter: 1e-8,
      achievesTarget: true,
    })),
    snapshotContext: vi.fn(() => VIEWPORT),
  };
}

let deps: GovernanceDeps;
let store: MemoryNexoraStore;
let verifier: NexoraVerifier;

beforeEach(() => {
  const registry = new IdentityRegistry("copilot-test-secret", { persist: false });
  store = new MemoryNexoraStore();
  const anchors = new NexoraAnchorChain(store);
  const authority = new AipDelegationAuthority("nexora-test-secret");
  const graph = new AipDelegationGraph(store, anchors, authority);
  const sealer = new AipEvidenceSealer({
    store,
    anchors,
    graph,
    authority,
    manifest: CONSOLE_TOOL_MANIFEST,
  });
  verifier = new NexoraVerifier(store);
  deps = {
    registry,
    service: new AccountabilityService(new MemoryLedgerStorage(), CONSOLE_TOOL_MANIFEST),
    nexora: { anchors, graph, sealer },
  };
});

describe("NEXORA live wiring for the copilot", () => {
  it("arming anchors GENESIS → SUPERVISOR_DELEGATION → CAPABILITY_MODULATION, idempotently", async () => {
    await ensureJarvisGoverned("groq-fast", deps);
    await ensureJarvisGoverned("groq-fast", deps);

    const anchors = await store.listAnchorsForAgent(JARVIS_DID);
    expect(anchors.map((a) => a.anchorType)).toEqual([
      "AGENT_GENESIS",
      "SUPERVISOR_DELEGATION",
      "CAPABILITY_MODULATION",
    ]);
    expect(anchors.map((a) => a.sequenceNumber)).toEqual([1, 2, 3]);
    // Genesis binds the credential's model digest.
    const profile = deps.registry.getAgent(JARVIS_AGENT_ID)!;
    expect(anchors[0].payload.modelDigest).toBe(profile.modelDigest);
    // The grant covers the nine verbs and nothing more.
    const { TOOL_SCHEMAS } = await import("../src/agent/tactical-tools");
    expect(anchors[2].payload.toolsGranted).toEqual(TOOL_SCHEMAS.map((t) => t.name));
    await expect(verifier.verifyAnchorChain(JARVIS_DID)).resolves.toEqual({
      valid: true,
      total: 3,
    });
  });

  it("a dispatch seals an evidence packet and an ACTION_EXECUTION_SEAL naming it", async () => {
    const caps = mockCaps();
    const result = await governedDispatchTool(
      { name: "fly_to_location", args: { query: "malacca strait" } },
      caps,
      "jarvis, take me to the malacca strait",
      "groq-fast",
      deps,
    );
    expect(result.ok).toBe(true);
    expect(caps.flyToLocation).toHaveBeenCalledOnce();

    const packets = await store.listPacketsForAgent(JARVIS_DID);
    expect(packets).toHaveLength(1);
    const packet = packets[0];
    expect(packet.toolExecuted.status).toBe("SUCCESS");
    expect(packet.rawPrompt).toBe("jarvis, take me to the malacca strait");
    expect(packet.preStateHash).toMatch(/^[0-9a-f]{64}$/);
    expect(packet.postStateHash).toMatch(/^[0-9a-f]{64}$/);
    // Autonomous verb: no supervisor co-signature on the packet.
    expect(packet.toolExecuted.supervisorCoSignature).toBeUndefined();
    // The delegation path roots at the supervising officer.
    expect(packet.delegationPath[0]).toContain("did:syntriass:officer:");
    expect(packet.delegationPath[packet.delegationPath.length - 1]).toBe(JARVIS_DID);

    const anchors = await store.listAnchorsForAgent(JARVIS_DID);
    const seal = anchors[anchors.length - 1];
    expect(seal.anchorType).toBe("ACTION_EXECUTION_SEAL");
    expect(seal.payload.packetHash).toBe(packet.packetHash);
    // The packet binds the lifecycle head that existed when it ran.
    expect(anchors.map((a) => a.anchorHash)).toContain(packet.anchorHash);

    const report = await verifier.verifyAgent(JARVIS_DID);
    expect(report.anchors.valid).toBe(true);
    expect(report.packets.valid).toBe(true);
    expect(report.crossConsistent).toBe(true);
    expect(report.findings).toEqual([]);

    // Both governance tiers recorded the same attempt.
    const history = await deps.service.history(JARVIS_AGENT_ID);
    expect(history).toHaveLength(1);
    expect(history[0].toolExecuted.executionStatus).toBe("SUCCESS");
  });

  it("an out-of-grant verb is blocked by the outer tier with no orphan packet", async () => {
    const caps = mockCaps();
    const result = await governedDispatchTool(
      { name: "execute_maneuver", args: {} },
      caps,
      "jarvis, execute the burn",
      "groq-fast",
      deps,
    );
    expect(result.ok).toBe(false);

    // The accountability ledger sealed the refusal; the AIP tier never ran
    // (the outer default-deny halts before the funnel's execute callback).
    const history = await deps.service.history(JARVIS_AGENT_ID);
    expect(history[0].toolExecuted.executionStatus).toBe("BLOCKED_BY_POLICY");
    const packets = await store.listPacketsForAgent(JARVIS_DID);
    expect(packets).toHaveLength(0);
  });

  it("a tampered packet is detected at its exact sequence — the breach banner's fact", async () => {
    const caps = mockCaps();
    await governedDispatchTool(
      { name: "set_shader_mode", args: { mode: "flir" } },
      caps, "thermal", "groq-fast", deps,
    );
    await governedDispatchTool(
      { name: "fly_to_location", args: { query: "hormuz" } },
      caps, "hormuz", "groq-fast", deps,
    );

    const packets = await store.listPacketsForAgent(JARVIS_DID);
    expect(packets).toHaveLength(2);
    // Edit history in storage, as an attacker with IndexedDB access would.
    packets[0].rawPrompt = "a command the operator never spoke";

    const report = await verifier.verifyAgent(JARVIS_DID);
    expect(report.packets.valid).toBe(false);
    expect(report.packets.brokenSequence).toBe(1);
    expect(report.crossConsistent).toBe(false);
  });

  it("without the nexora deps the dispatch still works accountability-only", async () => {
    const caps = mockCaps();
    const legacy: GovernanceDeps = { registry: deps.registry, service: deps.service };
    const result = await governedDispatchTool(
      { name: "fly_to_location", args: { query: "x" } },
      caps, "fly", "groq-fast", legacy,
    );
    expect(result.ok).toBe(true);
    expect(await store.listPacketsForAgent(JARVIS_DID)).toHaveLength(0);
    expect(await deps.service.history(JARVIS_AGENT_ID)).toHaveLength(1);
  });
});
