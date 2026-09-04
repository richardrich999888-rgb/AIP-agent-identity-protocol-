/**
 * QA verification runbook — the nine sign-off scenarios, executable.
 *
 * Naming note for auditors: the runbook's expected codes map onto the
 * implementation as follows, asserted here under their real names:
 *   UNDER_CLEARED                → CLEARANCE_INSUFFICIENT
 *   INVALID_SUPERVISOR_SIGNATURE → REQUIRES_SUPERVISOR_MULTISIG
 *                                  (detail: "failed verification")
 *   verifyNexoraLifecycle()      → NexoraVerifier.verifyAnchorChain()
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import { IdentityRegistry } from "../src/telemetry/agent-identity/identity-registry";
import type { AgentEmployeeProfile } from "../src/telemetry/agent-identity/agent-profile";
import type { ToolManifest } from "../src/telemetry/agent-identity/permission-guard";
import { AccountabilityService } from "../src/telemetry/agent-accountability/accountability-service";
import { MemoryLedgerStorage } from "../src/telemetry/agent-accountability/ledger-storage";
import {
  buildMissionDossier,
  toAuditCsv,
  toJsonl,
  verifyMissionDossier,
} from "../src/telemetry/agent-accountability/exporter";
import { MemoryIdentityStore } from "../src/telemetry/agent-identity/identity-store";
import {
  DelegationAuthority,
  toAgentDid,
  toOfficerDid,
  type DelegatedAuthorityGrant,
} from "../src/telemetry/agent-identity/persistent-identity";
import { GovernedExecutionFunnel } from "../src/telemetry/agent-accountability/governed-execution";
import { EvidenceVerifier } from "../src/telemetry/agent-accountability/verifier";
import { MemoryNexoraStore } from "../src/telemetry/nexora/nexora-store";
import { NexoraAnchorChain } from "../src/telemetry/nexora/anchor-chain";
import {
  AipDelegationAuthority,
  AipDelegationGraph,
} from "../src/telemetry/nexora/delegation-graph";
import { AipEvidenceSealer } from "../src/telemetry/nexora/aip-evidence";
import { NexoraVerifier } from "../src/telemetry/nexora/nexora-verifier";

const OFFICER = toOfficerDid("OFFICER-IAF-882");
const JARVIS_DID = toAgentDid("AGT-0481-JARVIS");
const MODEL = "cd".repeat(32);
const PROMPT_HASH = "ef".repeat(32);
const RUNTIME = { modelDigest: MODEL, systemPromptHash: PROMPT_HASH };

const MANIFEST: ToolManifest = {
  fly_to_location: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
  screen_conjunction_threats: {
    requiredPermission: "SCREEN_CONJUNCTIONS",
    minimumClearance: "SECRET",
  },
  execute_thruster_burn: { requiredPermission: "EXECUTE_MANEUVER", minimumClearance: "SECRET" },
};

// ── Credential-tier fixtures (QA-ID-01..03) ─────────────────────────────

function onboard(
  registry: IdentityRegistry,
  overrides: Partial<Parameters<IdentityRegistry["onboardAgent"]>[0]> = {},
) {
  return registry.onboardAgent({
    agentId: "AGT-0481-JARVIS",
    agentName: "JARVIS Tactical Copilot",
    organization: "DEFENCE_SPACE_AGENCY",
    modelEngine: "whisper+ollama",
    modelDigest: MODEL,
    systemPromptHash: PROMPT_HASH,
    enclaveType: "SOFTWARE_SANDBOX",
    department: "TACTICAL_C2",
    clearanceLevel: "SECRET",
    supervisorOperatorId: "OFFICER-IAF-882",
    assignedPermissions: ["NAVIGATE_CAMERA", "SCREEN_CONJUNCTIONS"],
    requiresDualKeyAuthorization: [],
    validForMs: 3600_000,
    ...overrides,
  });
}

const PRE_STATE = {
  cameraCoords: [0, 0, 2.0e7] as [number, number, number],
  activeShader: "visible",
};

// ── Persistent/grant-tier fixtures (QA-ID-04, QA-SEC-09) ────────────────

async function grantTierFixture(opts: { multiSig?: string[] } = {}) {
  const store = new MemoryIdentityStore();
  const authority = new DelegationAuthority("qa-secret");
  await store.registerPersistentIdentity({
    did: JARVIS_DID,
    agentId: "AGT-0481-JARVIS",
    agentName: "JARVIS Tactical Copilot",
    organization: "DEFENCE_SPACE_AGENCY",
    publicKey: "ab".repeat(32),
    modelDigest: MODEL,
    systemPromptHash: PROMPT_HASH,
    enclaveType: "SOFTWARE_SANDBOX",
    createdAtUtc: new Date().toISOString(),
    version: "1.0.0",
  });
  const now = Date.now();
  const grant: DelegatedAuthorityGrant = await authority.signGrant({
    grantId: crypto.randomUUID(),
    agentDid: JARVIS_DID,
    delegatorDid: OFFICER,
    delegationChain: [OFFICER],
    clearanceLevel: "SECRET",
    grantedTools: ["fly_to_location", "execute_thruster_burn"],
    requiresMultiSigTools: opts.multiSig ?? [],
    rateLimitMaxPerHour: 100,
    validFromUtc: new Date(now - 1000).toISOString(),
    expiresAtUtc: new Date(now + 3600_000).toISOString(),
    status: "ACTIVE",
  });
  await store.issueAuthorityGrant(grant);
  const funnel = new GovernedExecutionFunnel({
    store,
    manifest: MANIFEST,
    verifyGrant: (g) => authority.verifyGrant(g),
    verifyCoSignature: (g, t, s) => authority.verifyCoSignature(g, t, s),
  });
  return { store, authority, grant, funnel };
}

// ── NEXORA-tier fixtures (QA-NX-05/06, QA-AIP-07) ───────────────────────

function nexoraFixture() {
  const store = new MemoryNexoraStore();
  const chain = new NexoraAnchorChain(store);
  const authority = new AipDelegationAuthority("qa-nexora-secret");
  const graph = new AipDelegationGraph(store, chain, authority);
  const sealer = new AipEvidenceSealer({ store, anchors: chain, graph, authority, manifest: MANIFEST });
  const verifier = new NexoraVerifier(store);
  return { store, chain, authority, graph, sealer, verifier };
}

describe("QA-ID-01: agent onboarding & badge state", () => {
  it("registers AGT-0481-JARVIS at SECRET, ACTIVE, fields intact and signed", async () => {
    const registry = new IdentityRegistry("qa-id-secret", { persist: false });
    const profile = await onboard(registry);
    expect(profile.revocationStatus).toBe("ACTIVE");
    expect(profile.agentId).toBe("AGT-0481-JARVIS");
    expect(profile.did).toBe("did:syntriass:agent:AGT-0481-JARVIS");
    expect(profile.clearanceLevel).toBe("SECRET");
    expect(profile.supervisorDid).toBe(OFFICER);
    expect(profile.modelDigest).toBe(MODEL);
    await expect(registry.verifyCredential(profile)).resolves.toBe(true);
    // The badge derives its state from exactly this registry record.
    expect(registry.getAgent("AGT-0481-JARVIS")).toEqual(profile);
  });
});

describe("QA-ID-02: default-deny unknown tools", () => {
  it("blocks launch_kinetic_strike as UNKNOWN_TOOL without executing the body", async () => {
    const registry = new IdentityRegistry("qa-id-secret", { persist: false });
    const profile = await onboard(registry);
    const service = new AccountabilityService(new MemoryLedgerStorage(), MANIFEST);
    const body = vi.fn();
    const outcome = await service.executeGoverned({
      profile,
      rawPrompt: "launch kinetic strike",
      interpretedIntent: "launch_kinetic_strike",
      toolName: "launch_kinetic_strike",
      inputParams: {},
      preExecutionState: PRE_STATE,
      execute: body,
    });
    expect(outcome.status).toBe("BLOCKED_BY_POLICY");
    if (!outcome.verdict.allowed) {
      expect(outcome.verdict.violation.code).toBe("UNKNOWN_TOOL");
    }
    expect(body).not.toHaveBeenCalled();
    expect(outcome.entry.toolExecuted.errorMessage).toContain("UNKNOWN_TOOL");
  });
});

describe("QA-ID-03: clearance level enforcement", () => {
  it("blocks an UNCLASSIFIED agent from SECRET screening (runbook: UNDER_CLEARED)", async () => {
    const registry = new IdentityRegistry("qa-id-secret", { persist: false });
    const profile = await onboard(registry, {
      agentId: "AGT-0002-LOWCLR",
      clearanceLevel: "UNCLASSIFIED",
    });
    const service = new AccountabilityService(new MemoryLedgerStorage(), MANIFEST);
    const body = vi.fn();
    const outcome = await service.executeGoverned({
      profile,
      rawPrompt: "screen the belt",
      interpretedIntent: "screen_conjunction_threats",
      toolName: "screen_conjunction_threats",
      inputParams: {},
      preExecutionState: PRE_STATE,
      execute: body,
    });
    expect(outcome.status).toBe("BLOCKED_BY_POLICY");
    if (!outcome.verdict.allowed) {
      expect(outcome.verdict.violation.code).toBe("CLEARANCE_INSUFFICIENT");
    }
    expect(body).not.toHaveBeenCalled();
  });
});

describe("QA-ID-04: supervisor multi-sig gating", () => {
  it("no ticket → blocked; forged ticket → blocked; genuine ticket → sealed with co-signature", async () => {
    const { authority, grant, funnel } = await grantTierFixture({
      multiSig: ["execute_thruster_burn"],
    });
    const burn = (supervisorCoSignature?: string) =>
      funnel.execute({
        agentDid: JARVIS_DID,
        runtimeParameters: RUNTIME,
        rawPrompt: "execute the burn",
        toolName: "execute_thruster_burn",
        inputParams: { deltaVMps: 0.42 },
        preState: { camera: [0, 0, 1] },
        ...(supervisorCoSignature ? { supervisorCoSignature } : {}),
        execute: () => {},
      });

    const missing = await burn();
    expect(missing.status).toBe("BLOCKED_BY_POLICY");
    if (!missing.verdict.permitted) {
      expect(missing.verdict.rejection.code).toBe("REQUIRES_SUPERVISOR_MULTISIG");
      expect(missing.verdict.rejection.detail).toBe(
        "High-consequence tool requires human supervisor co-signature",
      );
    }

    // Runbook's INVALID_SUPERVISOR_SIGNATURE: same code, verification detail.
    const forged = await burn("ab".repeat(32));
    expect(forged.status).toBe("BLOCKED_BY_POLICY");
    if (!forged.verdict.permitted) {
      expect(forged.verdict.rejection.code).toBe("REQUIRES_SUPERVISOR_MULTISIG");
      expect(forged.verdict.rejection.detail).toMatch(/failed verification/);
    }

    const ticket = await authority.issueCoSignature(grant, "execute_thruster_burn");
    const approved = await burn(ticket);
    expect(approved.status).toBe("SUCCESS");
    expect(approved.packet.toolExecuted.supervisorCoSignature).toBe(ticket);
  });
});

describe("QA-NX-05: NEXORA lifecycle chain continuity", () => {
  it("chains GENESIS → DELEGATION → MODULATION → EXECUTION_SEAL, 4 linked anchors", async () => {
    const { chain, verifier } = nexoraFixture();
    await chain.appendAnchor({
      anchorType: "AGENT_GENESIS",
      agentDid: JARVIS_DID,
      actorDid: OFFICER,
      payload: { modelDigest: MODEL },
    });
    await chain.appendAnchor({
      anchorType: "SUPERVISOR_DELEGATION",
      agentDid: JARVIS_DID,
      actorDid: OFFICER,
      payload: { scope: ["fly_to_location"] },
    });
    await chain.appendAnchor({
      anchorType: "CAPABILITY_MODULATION",
      agentDid: JARVIS_DID,
      actorDid: OFFICER,
      payload: { added: [], removed: ["execute_thruster_burn"] },
    });
    await chain.appendAnchor({
      anchorType: "ACTION_EXECUTION_SEAL",
      agentDid: JARVIS_DID,
      actorDid: JARVIS_DID,
      payload: { note: "sealed by QA harness" },
    });
    // Runbook's verifyNexoraLifecycle():
    await expect(verifier.verifyAnchorChain(JARVIS_DID)).resolves.toEqual({
      valid: true,
      total: 4,
    });
  });
});

describe("QA-NX-06: terminal revocation kill-switch", () => {
  it("closes the chain, blocks every later execution, and refuses renewal", async () => {
    const { chain, sealer } = nexoraFixture();
    await chain.appendAnchor({
      anchorType: "AGENT_GENESIS",
      agentDid: JARVIS_DID,
      actorDid: OFFICER,
      payload: { modelDigest: MODEL },
    });
    await chain.appendAnchor({
      anchorType: "AUTHORITY_REVOCATION",
      agentDid: JARVIS_DID,
      actorDid: OFFICER,
      payload: { terminal: true, reason: "decommissioned" },
    });

    const body = vi.fn();
    const outcome = await sealer.execute({
      agentDid: JARVIS_DID,
      runtimeModelDigest: MODEL,
      rawPrompt: "fly",
      toolName: "fly_to_location",
      inputParams: {},
      preState: { camera: [0, 0, 1] },
      execute: body,
    });
    expect(outcome.status).toBe("BLOCKED_BY_POLICY");
    if (!outcome.verdict.permitted) {
      expect(outcome.verdict.rejection.code).toBe("LIFECYCLE_CLOSED");
    }
    expect(body).not.toHaveBeenCalled();
    await expect(
      chain.appendAnchor({
        anchorType: "CAPABILITY_MODULATION",
        agentDid: JARVIS_DID,
        actorDid: OFFICER,
        payload: {},
      }),
    ).rejects.toThrow(/closed by a terminal revocation/);

    // Credential-tier renewal is equally terminal.
    const registry = new IdentityRegistry("qa-id-secret", { persist: false });
    await onboard(registry);
    await registry.revokeAgent("AGT-0481-JARVIS");
    await expect(registry.renewCredential("AGT-0481-JARVIS", 1000)).rejects.toThrow(
      /terminal/,
    );
  });
});

describe("QA-AIP-07: evidence & state capture", () => {
  it("fly_to_location seals pre/post hashes and binds live NEXORA anchors", async () => {
    const { chain, graph, sealer, verifier, store } = nexoraFixture();
    await chain.appendAnchor({
      anchorType: "AGENT_GENESIS",
      agentDid: JARVIS_DID,
      actorDid: OFFICER,
      payload: { modelDigest: MODEL },
    });
    await graph.delegate({
      parentDid: OFFICER,
      childDid: JARVIS_DID,
      scope: ["fly_to_location"],
      clearanceLevel: "SECRET",
      validForMs: 3600_000,
    });
    const outcome = await sealer.execute({
      agentDid: JARVIS_DID,
      runtimeModelDigest: MODEL,
      rawPrompt: "jarvis, fly to New Delhi",
      toolName: "fly_to_location",
      inputParams: { coords: [28.61, 77.2] },
      preState: { camera: [0, 0, 2.0e7], shader: "visible" },
      execute: () => ({ camera: [77.2, 28.61, 5.0e5], shader: "visible" }),
    });
    expect(outcome.status).toBe("SUCCESS");
    expect(outcome.packet.preStateHash).toMatch(/^[0-9a-f]{64}$/);
    expect(outcome.packet.postStateHash).toMatch(/^[0-9a-f]{64}$/);
    expect(outcome.packet.postStateHash).not.toBe(outcome.packet.preStateHash);

    // The packet binds a real anchor of this agent's lifecycle chain, and
    // the seal anchor names this packet — the cross-reference both ways.
    const anchors = await store.listAnchorsForAgent(JARVIS_DID);
    expect(anchors.map((a) => a.anchorHash)).toContain(outcome.packet.anchorHash);
    const seal = anchors.find((a) => a.anchorId === outcome.sealAnchorId);
    expect(seal?.payload.packetHash).toBe(outcome.packet.packetHash);

    const report = await verifier.verifyAgent(JARVIS_DID);
    expect(report.crossConsistent).toBe(true);
  });
});

describe("QA-EXP-08: multi-format export dossiers", () => {
  it("jsonl parses per line, csv escapes RFC-4180, dossier certifies and verifies", async () => {
    const registry = new IdentityRegistry("qa-id-secret", { persist: false });
    const profile: AgentEmployeeProfile = await onboard(registry);
    const service = new AccountabilityService(new MemoryLedgerStorage(), MANIFEST);
    await service.executeGoverned({
      profile,
      rawPrompt: 'fly to "Delhi",\nfast',
      interpretedIntent: "fly_to_location",
      toolName: "fly_to_location",
      inputParams: { coords: [28.61, 77.2] },
      preExecutionState: PRE_STATE,
      execute: () => {},
    });
    const entries = await service.history(profile.agentId);
    const audit = await service.verifyAgentAuditTrail(profile.agentId);

    const lines = toJsonl(entries).trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toEqual(entries[0]);

    const csv = toAuditCsv(entries, audit);
    expect(csv).toContain('""Delhi""');
    expect(csv.split("\r\n")[0]).toContain('"Integrity_Valid"');

    const dossier = await buildMissionDossier({
      identity: profile,
      actionLedger: entries,
      actionChainVerification: audit,
    });
    expect(dossier.actionLedger[0].chainHash).toBe(entries[0].chainHash);
    await expect(verifyMissionDossier(dossier)).resolves.toBe(true);
  });
});

describe("QA-SEC-09: tamper rejection", () => {
  it("a mutated historical packet fails verifyEvidenceChain with the exact sequence", async () => {
    const { store, funnel } = await grantTierFixture();
    const fly = (prompt: string) =>
      funnel.execute({
        agentDid: JARVIS_DID,
        runtimeParameters: RUNTIME,
        rawPrompt: prompt,
        toolName: "fly_to_location",
        inputParams: {},
        preState: { camera: [0, 0, 1] },
        execute: () => {},
      });
    await fly("one");
    await fly("two");
    await fly("three");

    const packets = await store.listEvidenceForAgent(JARVIS_DID);
    packets[1].rawPrompt = "tampered";
    const verdict = await new EvidenceVerifier(store).verifyEvidenceChain(JARVIS_DID);
    expect(verdict.valid).toBe(false);
    if (!verdict.valid) {
      expect(verdict.brokenSequence).toBe(2);
      expect(verdict.totalPackets).toBe(3);
    }
  });
});
