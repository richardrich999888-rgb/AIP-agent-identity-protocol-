/**
 * The export suite's contract, as executable claims:
 *
 * - JSONL is byte-faithful: each line parses back to the sealed entry;
 * - the after-action CSV carries the specified columns, survives hostile
 *   prompt text, and is per-row honest about integrity — rows after the
 *   first broken link say false;
 * - the certified dossier's root digest is recomputable by an independent
 *   verifier, and any post-certification edit breaks it;
 * - the governed-execution funnel emits on every ledger commit, which is
 *   what the live UI feed subscribes to.
 */

import { beforeEach, describe, expect, it } from "vitest";

import { IdentityRegistry } from "../src/telemetry/agent-identity/identity-registry";
import type { AgentEmployeeProfile } from "../src/telemetry/agent-identity/agent-profile";
import { AccountabilityService } from "../src/telemetry/agent-accountability/accountability-service";
import { MemoryLedgerStorage } from "../src/telemetry/agent-accountability/ledger-storage";
import {
  buildMissionDossier,
  toAuditCsv,
  toCertifiedDossierJson,
  toJsonl,
  verifyMissionDossier,
} from "../src/telemetry/agent-accountability/exporter";
import { GovernedExecutionFunnel } from "../src/telemetry/agent-accountability/governed-execution";
import { MemoryIdentityStore } from "../src/telemetry/agent-identity/identity-store";
import {
  DelegationAuthority,
  toAgentDid,
  toOfficerDid,
} from "../src/telemetry/agent-identity/persistent-identity";
import { NexoraAnchorChain } from "../src/telemetry/nexora/anchor-chain";
import { MemoryNexoraStore } from "../src/telemetry/nexora/nexora-store";
import type { ToolManifest } from "../src/telemetry/agent-identity/permission-guard";

const MANIFEST: ToolManifest = {
  fly_to: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
};

const PRE_STATE = {
  cameraCoords: [78.9, 20.5, 1.2e7] as [number, number, number],
  activeShader: "FLIR",
};

let registry: IdentityRegistry;
let profile: AgentEmployeeProfile;
let service: AccountabilityService;
let storage: MemoryLedgerStorage;

async function record(rawPrompt: string): Promise<void> {
  await service.executeGoverned({
    profile,
    rawPrompt,
    interpretedIntent: "fly_to",
    toolName: "fly_to",
    inputParams: { target: "Delhi" },
    preExecutionState: PRE_STATE,
    execute: () => {},
  });
}

beforeEach(async () => {
  registry = new IdentityRegistry("export-test-secret", { persist: false });
  profile = await registry.onboardAgent({
    agentId: "AGT-EMP-0481-JARVIS",
    agentName: "Orbital Tactical Copilot",
    organization: "DEFENCE_SPACE_AGENCY",
    modelEngine: "whisper+ollama",
    modelDigest: "1".repeat(64),
    systemPromptHash: "2".repeat(64),
    enclaveType: "SOFTWARE_SANDBOX",
    department: "TACTICAL_C2",
    clearanceLevel: "SECRET",
    supervisorOperatorId: "OFFICER-IAF-882",
    assignedPermissions: ["NAVIGATE_CAMERA"],
    requiresDualKeyAuthorization: [],
    validForMs: 3600_000,
  });
  storage = new MemoryLedgerStorage();
  service = new AccountabilityService(storage, MANIFEST);
});

describe("jsonl forensic stream", () => {
  it("emits one byte-faithful line per sealed entry", async () => {
    await record("fly to delhi");
    await record("fly to leh");
    const entries = await service.history(profile.agentId);
    const lines = toJsonl(entries).trim().split("\n");
    expect(lines).toHaveLength(2);
    lines.forEach((line, i) => {
      expect(JSON.parse(line)).toEqual(entries[i]);
    });
  });
});

describe("after-action csv", () => {
  it("carries the specified columns and survives hostile prompt text", async () => {
    await record('fly to "Delhi",\r\nthen zoom');
    const entries = await service.history(profile.agentId);
    const audit = await service.verifyAgentAuditTrail(profile.agentId);
    const csv = toAuditCsv(entries, audit);

    const [header] = csv.split("\r\n");
    for (const col of [
      "Sequence",
      "Timestamp_UTC",
      "Agent_DID",
      "Supervisor_DID",
      "Prompt",
      "Tool_Name",
      "Parameters",
      "Status",
      "Duration_MS",
      "Prev_Hash",
      "Packet_Hash",
      "Integrity_Valid",
    ]) {
      expect(header).toContain(`"${col}"`);
    }
    expect(csv).toContain('""Delhi""'); // embedded quotes doubled
    expect(csv).toContain('"did:syntriass:officer:OFFICER-IAF-882"');
    expect(csv).toContain('"true"');
  });

  it("marks rows from the first broken link as integrity-invalid", async () => {
    await record("one");
    await record("two");
    await record("three");
    const entries = await service.history(profile.agentId);
    entries[1].rawPrompt = "tampered";
    const audit = await service.verifyAgentAuditTrail(profile.agentId);
    const rows = toAuditCsv(entries, audit).trim().split("\r\n").slice(1);
    expect(rows[0]).toContain('"true"');
    expect(rows[1]).toContain('"false"');
    expect(rows[2]).toContain('"false"'); // one edit poisons the rest
  });
});

describe("certified mission dossier", () => {
  it("bundles identity, anchors, ledger and a recomputable root digest", async () => {
    await record("fly to delhi");
    const entries = await service.history(profile.agentId);
    const audit = await service.verifyAgentAuditTrail(profile.agentId);

    // A real lifecycle trail: genesis + one milestone from the NEXORA tier.
    const nexoraStore = new MemoryNexoraStore();
    const chain = new NexoraAnchorChain(nexoraStore);
    const agentDid = toAgentDid(profile.agentId);
    await chain.appendAnchor({
      anchorType: "AGENT_GENESIS",
      agentDid,
      actorDid: toOfficerDid("OFFICER-IAF-882"),
      payload: { modelDigest: profile.modelDigest },
    });
    await chain.appendAnchor({
      anchorType: "OWNERSHIP_BINDING",
      agentDid,
      actorDid: toOfficerDid("OFFICER-IAF-882"),
      payload: { owner: "DEFENCE_SPACE_AGENCY" },
    });
    const anchors = await nexoraStore.listAnchorsForAgent(agentDid);

    const dossier = await buildMissionDossier({
      identity: profile,
      lifecycleAnchors: anchors,
      actionLedger: entries,
      actionChainVerification: audit,
    });
    expect(dossier.standard).toBe("ASC-SENTINEL-MISSION-DOSSIER-v1");
    expect(dossier.agent.genesisAttestation?.anchorType).toBe("AGENT_GENESIS");
    expect(dossier.lifecycleAnchors).toHaveLength(2);
    expect(dossier.actionLedger).toHaveLength(1);
    expect(dossier.certification.rootDigest).toMatch(/^[0-9a-f]{64}$/);
    await expect(verifyMissionDossier(dossier)).resolves.toBe(true);

    // The serialized form round-trips and still verifies.
    const parsed = JSON.parse(toCertifiedDossierJson(dossier));
    await expect(verifyMissionDossier(parsed)).resolves.toBe(true);

    // Any post-certification edit breaks the digest.
    parsed.actionLedger[0].rawPrompt = "forged";
    await expect(verifyMissionDossier(parsed)).resolves.toBe(false);
  });

  it("an empty anchor trail is a recorded fact, not an omission", async () => {
    await record("fly to delhi");
    const dossier = await buildMissionDossier({
      identity: profile,
      actionLedger: await service.history(profile.agentId),
      actionChainVerification: await service.verifyAgentAuditTrail(profile.agentId),
    });
    expect(dossier.lifecycleAnchors).toEqual([]);
    expect(dossier.agent.genesisAttestation).toBeNull();
    await expect(verifyMissionDossier(dossier)).resolves.toBe(true);
  });
});

describe("live feed change source", () => {
  it("the governed-execution funnel emits on every ledger commit", async () => {
    const store = new MemoryIdentityStore();
    const authority = new DelegationAuthority("feed-secret");
    const agentDid = toAgentDid("AGT-FEED");
    await store.registerPersistentIdentity({
      did: agentDid,
      agentId: "AGT-FEED",
      agentName: "Feed test",
      organization: "SYNTRIASS_LABS",
      publicKey: "a".repeat(64),
      modelDigest: "3".repeat(64),
      systemPromptHash: "4".repeat(64),
      enclaveType: "SOFTWARE_SANDBOX",
      createdAtUtc: new Date().toISOString(),
      version: "1.0.0",
    });
    const funnel = new GovernedExecutionFunnel({
      store,
      manifest: MANIFEST,
      verifyGrant: (g) => authority.verifyGrant(g),
      verifyCoSignature: () => false,
    });
    let notified = 0;
    const unsubscribe = funnel.subscribe(() => notified++);

    // No grant → blocked — and blocked commits still notify: a refusal is
    // a feed event, not a silence.
    await funnel.execute({
      agentDid,
      runtimeParameters: { modelDigest: "3".repeat(64), systemPromptHash: "4".repeat(64) },
      rawPrompt: "fly",
      toolName: "fly_to",
      inputParams: {},
      preState: { x: 1 },
      execute: () => {},
    });
    expect(notified).toBe(1);
    unsubscribe();
  });
});
