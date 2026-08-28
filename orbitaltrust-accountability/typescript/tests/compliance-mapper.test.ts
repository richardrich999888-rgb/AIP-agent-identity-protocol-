/**
 * The compliance mapper, as executable claims:
 *
 * - mappings are deterministic and keyed by the sealed hash they describe;
 * - risk-measurement and risk-treatment verbs carry their extra controls,
 *   and a multisig-gated tool reports GATED_BY_MULTISIG;
 * - the matrix aggregates the control union and the human-oversight facts;
 * - the compliance-enriched dossier's root digest covers the matrix — the
 *   same certification contract the offline Rust verifier recomputes;
 * - the regulator-facing matrix export parses and tethers to that digest.
 */

import { describe, expect, it, vi } from "vitest";

import type { TacticalCapabilities, ViewportContext } from "../src/agent/capabilities";
import { governedDispatchTool, JARVIS_AGENT_ID, type GovernanceDeps } from "../src/agent/governed-dispatch";
import { IdentityRegistry } from "../src/telemetry/agent-identity/identity-registry";
import { toAgentDid } from "../src/telemetry/agent-identity/persistent-identity";
import { AccountabilityService } from "../src/telemetry/agent-accountability/accountability-service";
import { MemoryLedgerStorage } from "../src/telemetry/agent-accountability/ledger-storage";
import { CONSOLE_TOOL_MANIFEST } from "../src/telemetry/governance";
import { MemoryNexoraStore } from "../src/telemetry/nexora/nexora-store";
import { NexoraAnchorChain } from "../src/telemetry/nexora/anchor-chain";
import { AipDelegationAuthority, AipDelegationGraph } from "../src/telemetry/nexora/delegation-graph";
import { AipEvidenceSealer } from "../src/telemetry/nexora/aip-evidence";
import {
  buildComplianceMatrix,
  mapPacketToCompliance,
} from "../src/governance/compliance-schema";
import {
  buildCompliantMissionDossier,
  exportRegulatoryComplianceMatrix,
  verifyMissionDossier,
} from "../src/export/dossier-export";

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

function makeDeps(): { deps: GovernanceDeps; store: MemoryNexoraStore } {
  const registry = new IdentityRegistry("compliance-test-secret", { persist: false });
  const store = new MemoryNexoraStore();
  const anchors = new NexoraAnchorChain(store);
  const authority = new AipDelegationAuthority("compliance-nexora-secret");
  const graph = new AipDelegationGraph(store, anchors, authority);
  const sealer = new AipEvidenceSealer({ store, anchors, graph, authority, manifest: CONSOLE_TOOL_MANIFEST });
  return {
    deps: {
      registry,
      service: new AccountabilityService(new MemoryLedgerStorage(), CONSOLE_TOOL_MANIFEST),
      nexora: { anchors, graph, sealer },
    },
    store,
  };
}

async function runMission() {
  const { deps, store } = makeDeps();
  const caps = mockCaps();
  await governedDispatchTool({ name: "fly_to_location", args: { query: "hormuz" } }, caps, "fly to hormuz", "groq-fast", deps);
  await governedDispatchTool({ name: "screen_conjunction_threats", args: {} }, caps, "screen threats", "groq-fast", deps);
  await governedDispatchTool({ name: "compute_avoidance_maneuver", args: { satelliteId: "1", missDistanceKm: 5 } }, caps, "plan a burn", "groq-fast", deps);
  const agent = deps.registry.getAgent(JARVIS_AGENT_ID)!;
  const did = toAgentDid(JARVIS_AGENT_ID);
  return {
    agent,
    anchors: await store.listAnchorsForAgent(did),
    packets: await store.listPacketsForAgent(did),
    entries: await deps.service.history(JARVIS_AGENT_ID),
    audit: await deps.service.verifyAgentAuditTrail(JARVIS_AGENT_ID),
  };
}

describe("regulatory compliance mapper", () => {
  it("maps each verb to its controls, deterministically, keyed by the sealed hash", async () => {
    const m = await runMission();
    const gated = new Set<string>();
    const fly = mapPacketToCompliance(m.packets[0], gated);
    expect(fly.nistAiRmf.functions).toEqual(["GOVERN-1.2", "MAP-1.5"]);
    expect(fly.euAiAct.articles).toEqual(["Article 12 (Record-Keeping)"]);
    expect(fly.euAiAct.conformityStatus).toBe("CONFORMANT");
    expect(fly.auditProofHash).toBe(m.packets[0].packetHash);
    // Determinism: identical input, identical mapping.
    expect(mapPacketToCompliance(m.packets[0], gated)).toEqual(fly);

    const screen = mapPacketToCompliance(m.packets[1], gated);
    expect(screen.nistAiRmf.functions).toContain("MEASURE-2.4");
    expect(screen.euAiAct.articles).toContain("Article 9 (Risk Management)");
    expect(screen.iso42001.clauses).toContain("Clause 6 (Risk Treatment)");

    const plan = mapPacketToCompliance(m.packets[2], gated);
    expect(plan.nistAiRmf.functions).toContain("MANAGE-2.4");
    expect(plan.euAiAct.articles).toContain("Article 14 (Human Oversight)");
    expect(plan.iso42001.clauses).toContain("Clause 8.5 (Human Oversight)");
  });

  it("reports GATED_BY_MULTISIG for clearance-gated tools", async () => {
    const m = await runMission();
    const gated = new Set(["compute_avoidance_maneuver"]);
    const plan = mapPacketToCompliance(m.packets[2], gated);
    expect(plan.euAiAct.conformityStatus).toBe("GATED_BY_MULTISIG");
  });

  it("aggregates the matrix with human-oversight facts and attestation digests", async () => {
    const m = await runMission();
    const matrix = buildComplianceMatrix({
      identity: m.agent,
      evidencePackets: m.packets,
      actionLedger: m.entries,
    });
    expect(matrix.controls).toHaveLength(3);
    expect(matrix.aggregated.nistAiRmfFunctions).toEqual(
      expect.arrayContaining(["GOVERN-1.2", "MAP-1.5", "MEASURE-2.4", "MANAGE-2.4"]),
    );
    expect(matrix.humanOversight.supervisorDid).toBe(m.agent.supervisorDid);
    expect(matrix.humanOversight.totalActions).toBe(3);
    expect(matrix.attestationDigests).toEqual(m.packets.map((p) => p.packetHash));
  });

  it("falls back to the action ledger when no AIP packets exist", async () => {
    const m = await runMission();
    const matrix = buildComplianceMatrix({
      identity: m.agent,
      evidencePackets: [],
      actionLedger: m.entries,
    });
    expect(matrix.controls).toHaveLength(3);
    expect(matrix.attestationDigests).toEqual(m.entries.map((e) => e.chainHash));
  });

  it("certifies the matrix under the dossier root digest", async () => {
    const m = await runMission();
    const dossier = await buildCompliantMissionDossier({
      identity: m.agent,
      lifecycleAnchors: m.anchors,
      evidencePackets: m.packets,
      actionLedger: m.entries,
      actionChainVerification: m.audit,
    });
    expect(dossier.complianceMatrix.controls).toHaveLength(3);
    await expect(verifyMissionDossier(dossier)).resolves.toBe(true);
    // Editing the matrix after certification breaks the seal.
    const forged = structuredClone(dossier);
    forged.complianceMatrix.controls[0].euAiAct.conformityStatus = "GATED_BY_MULTISIG";
    await expect(verifyMissionDossier(forged)).resolves.toBe(false);
  });

  it("exports a regulator-facing matrix tethered to the root digest", async () => {
    const m = await runMission();
    const dossier = await buildCompliantMissionDossier({
      identity: m.agent,
      lifecycleAnchors: m.anchors,
      evidencePackets: m.packets,
      actionLedger: m.entries,
      actionChainVerification: m.audit,
    });
    const doc = JSON.parse(exportRegulatoryComplianceMatrix(dossier));
    expect(doc.standard).toBe("ASC-SENTINEL-COMPLIANCE-MATRIX-v1");
    expect(doc.agentDid).toBe(m.agent.did);
    expect(doc.certifiedByRootDigest).toBe(dossier.certification.rootDigest);
    expect(doc.complianceMatrix.controls).toHaveLength(3);
  });
});
