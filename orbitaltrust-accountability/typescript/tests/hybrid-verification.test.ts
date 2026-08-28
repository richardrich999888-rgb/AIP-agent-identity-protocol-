/**
 * The hybrid verification pipeline, as executable claims:
 *
 * - the engine loader never throws: without the built WASM pkg (this test
 *   environment) it settles on the Web Crypto fallback;
 * - the fallback's chain verdicts agree with the store-bound NexoraVerifier
 *   on both valid and tampered records — two implementations, one answer;
 * - the runner's report matches the shape the inspection tab renders,
 *   including cross-reference findings and the packet-set Merkle root;
 * - the Merkle fallback reproduces the Rust core's construction rules;
 * - the executeGoverned facade routes UI calls into the registered governed
 *   executor, refuses unregistered or mis-addressed calls, and never throws.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import type { TacticalCapabilities, ViewportContext } from "../src/agent/capabilities";
import { governedDispatchTool, JARVIS_AGENT_ID, type GovernanceDeps } from "../src/agent/governed-dispatch";
import { IdentityRegistry } from "../src/telemetry/agent-identity/identity-registry";
import { toAgentDid } from "../src/telemetry/agent-identity/persistent-identity";
import { AccountabilityService } from "../src/telemetry/agent-accountability/accountability-service";
import { MemoryLedgerStorage } from "../src/telemetry/agent-accountability/ledger-storage";
import { CONSOLE_TOOL_MANIFEST } from "../src/telemetry/governance";
import { sha256Hex } from "../src/telemetry/crypto";
import { MemoryNexoraStore } from "../src/telemetry/nexora/nexora-store";
import { NexoraAnchorChain } from "../src/telemetry/nexora/anchor-chain";
import { AipDelegationAuthority, AipDelegationGraph } from "../src/telemetry/nexora/delegation-graph";
import { AipEvidenceSealer } from "../src/telemetry/nexora/aip-evidence";
import { NexoraVerifier } from "../src/telemetry/nexora/nexora-verifier";
import { getVerifierEngine, resetVerifierEngineForTests } from "../src/governance/wasm";
import { verifyAgentRecords } from "../src/governance/verification-runner";
import {
  executeGoverned,
  registerGovernedExecutor,
} from "../src/governance/execute-governed";

const VIEWPORT: ViewportContext = {
  camera: { latitudeDeg: 20.5, longitudeDeg: 78.9, altitudeKm: 12000, headingDeg: 0, pitchDeg: -90 },
  selected: null,
  enabledLayers: [],
  shaderMode: "visible",
  counts: { air: 0, sea: 0, orbit: 0, alertCells: 0 },
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

async function sealedRecords() {
  const registry = new IdentityRegistry("hybrid-test-secret", { persist: false });
  const store = new MemoryNexoraStore();
  const anchors = new NexoraAnchorChain(store);
  const authority = new AipDelegationAuthority("hybrid-nexora-secret");
  const graph = new AipDelegationGraph(store, anchors, authority);
  const sealer = new AipEvidenceSealer({ store, anchors, graph, authority, manifest: CONSOLE_TOOL_MANIFEST });
  const deps: GovernanceDeps = {
    registry,
    service: new AccountabilityService(new MemoryLedgerStorage(), CONSOLE_TOOL_MANIFEST),
    nexora: { anchors, graph, sealer },
  };
  const caps = mockCaps();
  await governedDispatchTool({ name: "fly_to_location", args: { query: "hormuz" } }, caps, "fly", "groq-fast", deps);
  await governedDispatchTool({ name: "set_shader_mode", args: { mode: "flir" } }, caps, "thermal", "groq-fast", deps);
  const did = toAgentDid(JARVIS_AGENT_ID);
  return {
    store,
    anchors: await store.listAnchorsForAgent(did),
    packets: await store.listPacketsForAgent(did),
    did,
  };
}

afterEach(() => {
  resetVerifierEngineForTests();
});

describe("hybrid verification pipeline", () => {
  it("settles on an engine without throwing, falling back when no WASM pkg exists", async () => {
    const engine = await getVerifierEngine();
    expect(["wasm", "webcrypto"]).toContain(engine.engine);
  });

  it("agrees with the store-bound verifier on valid records", async () => {
    const m = await sealedRecords();
    const runner = await verifyAgentRecords(m.anchors, m.packets);
    const reference = await new NexoraVerifier(m.store).verifyAgent(m.did);
    expect(runner.anchors.valid).toBe(reference.anchors.valid);
    expect(runner.packets.valid).toBe(reference.packets.valid);
    expect(runner.crossConsistent).toBe(reference.crossConsistent);
    expect(runner.anchors.valid).toBe(true);
    expect(runner.packetMerkleRoot).toMatch(/^[0-9a-f]{64}$/);
  });

  it("agrees with the store-bound verifier on tampered records, naming the sequence", async () => {
    const m = await sealedRecords();
    m.packets[0].rawPrompt = "a command the operator never spoke";
    const runner = await verifyAgentRecords(m.anchors, m.packets);
    const reference = await new NexoraVerifier(m.store).verifyAgent(m.did);
    expect(runner.packets.valid).toBe(false);
    expect(runner.packets.brokenSequence).toBe(1);
    expect(reference.packets.valid).toBe(false);
    expect(reference.packets.brokenSequence).toBe(1);
  });

  it("flags a forged cross-reference the chains alone cannot see", async () => {
    const m = await sealedRecords();
    // Re-point a packet at a hash that is not in the lifecycle chain,
    // re-sealing its own chain so only the cross-reference law can object.
    const forged = structuredClone(m.packets);
    forged[1].anchorHash = "f".repeat(64);
    const { aipPacketPayloadBytes, AIP_EVIDENCE_GENESIS_HASH } = await import(
      "../src/telemetry/nexora/nexora-verifier"
    );
    let previous = AIP_EVIDENCE_GENESIS_HASH;
    for (const packet of forged) {
      const { previousPacketHash: _p, packetHash: _h, ...payload } = packet;
      packet.previousPacketHash = previous;
      packet.packetHash = await sha256Hex(previous + aipPacketPayloadBytes(payload));
      previous = packet.packetHash;
    }
    const runner = await verifyAgentRecords(m.anchors, forged);
    expect(runner.packets.valid).toBe(true);
    expect(runner.crossConsistent).toBe(false);
    expect(runner.findings.join(" ")).toContain("not in the agent's lifecycle chain");
  });

  it("the Merkle fallback reproduces the core's construction rules", async () => {
    const engine = await getVerifierEngine();
    expect(await engine.merkleRoot([])).toBe("0".repeat(64));
    const a = await sha256Hex("a");
    const b = await sha256Hex("b");
    expect(await engine.merkleRoot([a])).toBe(a);
    expect(await engine.merkleRoot([a, b])).toBe(await sha256Hex(a + b));
    const c = await sha256Hex("c");
    const ab = await sha256Hex(a + b);
    expect(await engine.merkleRoot([a, b, c])).toBe(await sha256Hex(ab + c));
  });

  it("computes the canonical evidence hash over the record minus chain fields", async () => {
    const m = await sealedRecords();
    const engine = await getVerifierEngine();
    const hash = await engine.computeCanonicalEvidenceHash(
      m.packets[0] as unknown as Record<string, unknown>,
    );
    // Recomputing the seal from that payload digest's preimage reproduces
    // the chain: the canonical hash is the packet's payload commitment.
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    const rehashed = await engine.computeCanonicalEvidenceHash({
      ...(m.packets[0] as unknown as Record<string, unknown>),
      previousPacketHash: "junk",
      packetHash: "junk",
    });
    expect(rehashed).toBe(hash);
  });

  it("executeGoverned routes through the registered executor and refuses otherwise", async () => {
    const before = await executeGoverned({ toolName: "fly_to_location", parameters: {} });
    expect(before.ok).toBe(false);
    expect(before.summary).toContain("not up");

    const seen: Array<{ name: string; transcript: string }> = [];
    const unregister = registerGovernedExecutor("did:syntriass:agent:AGT-TEST", async (call, transcript) => {
      seen.push({ name: call.name, transcript });
      return { ok: true, summary: "done" };
    });

    const ok = await executeGoverned({
      agentDid: "did:syntriass:agent:AGT-TEST",
      toolName: "screen_conjunction_threats",
      parameters: { horizonHours: 24 },
      transcript: "screen the catalog",
    });
    expect(ok.ok).toBe(true);
    expect(seen).toEqual([{ name: "screen_conjunction_threats", transcript: "screen the catalog" }]);

    const wrongAgent = await executeGoverned({
      agentDid: "did:syntriass:agent:SOMEONE-ELSE",
      toolName: "fly_to_location",
      parameters: {},
    });
    expect(wrongAgent.ok).toBe(false);

    unregister();
    const after = await executeGoverned({ toolName: "fly_to_location", parameters: {} });
    expect(after.ok).toBe(false);
  });
});
