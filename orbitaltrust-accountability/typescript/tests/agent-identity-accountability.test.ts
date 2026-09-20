/**
 * The governance subsystem's contract, as executable claims:
 *
 * - a credential issued by the registry verifies, and a tampered one does not;
 * - the guard blocks unpermitted, under-cleared, expired and revoked agents,
 *   and the blocked attempt is *recorded*, not just refused;
 * - the hash chain links every action, and editing any historical field is
 *   detected by `verifyAgentAuditTrail`;
 * - the export formats survive hostile prompt text.
 */

import { beforeEach, describe, expect, it } from "vitest";

import { IdentityRegistry } from "../src/telemetry/agent-identity/identity-registry";
import {
  evaluateToolInvocation,
  type ToolManifest,
} from "../src/telemetry/agent-identity/permission-guard";
import {
  agentDid,
  officerDid,
  parseDid,
  profileSigningPayload,
  type AgentEmployeeProfile,
} from "../src/telemetry/agent-identity/agent-profile";
import { AccountabilityService } from "../src/telemetry/agent-accountability/accountability-service";
import { MemoryLedgerStorage } from "../src/telemetry/agent-accountability/ledger-storage";
import { GENESIS_HASH } from "../src/telemetry/agent-accountability/types";
import { toCsv, toJsonl } from "../src/telemetry/agent-accountability/exporter";

const MANIFEST: ToolManifest = {
  fly_to: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
  screen_conjunctions: {
    requiredPermission: "SCREEN_CONJUNCTIONS",
    minimumClearance: "CONFIDENTIAL",
  },
  execute_maneuver: {
    requiredPermission: "EXECUTE_MANEUVER",
    minimumClearance: "TOP_SECRET",
  },
};

const PRE_STATE = {
  cameraCoords: [78.9, 20.5, 1.2e7] as [number, number, number],
  activeShader: "FLIR",
  selectedTargetId: "NORAD-25544",
};

const MODEL_DIGEST = "1".repeat(64);
const PROMPT_HASH = "2".repeat(64);
const GOOD_ATTESTATION = {
  modelDigest: MODEL_DIGEST,
  systemPromptHash: PROMPT_HASH,
};

function freshRegistry(): IdentityRegistry {
  // persist:false keeps the test hermetic — no IndexedDB in Node anyway.
  return new IdentityRegistry("test-signing-secret", { persist: false });
}

async function onboardCopilot(
  registry: IdentityRegistry,
  overrides: Partial<Parameters<IdentityRegistry["onboardAgent"]>[0]> = {},
): Promise<AgentEmployeeProfile> {
  return registry.onboardAgent({
    agentId: "AGT-EMP-0481-JARVIS",
    agentName: "Orbital Tactical Copilot",
    organization: "DEFENCE_SPACE_AGENCY",
    modelEngine: "whisper+ollama",
    modelDigest: MODEL_DIGEST,
    systemPromptHash: PROMPT_HASH,
    enclaveType: "SOFTWARE_SANDBOX",
    department: "CONJUNCTION_ANALYSIS",
    clearanceLevel: "CONFIDENTIAL",
    supervisorOperatorId: "OFFICER-IAF-882",
    assignedPermissions: ["NAVIGATE_CAMERA", "SCREEN_CONJUNCTIONS"],
    requiresDualKeyAuthorization: [],
    validForMs: 60 * 60 * 1000,
    ...overrides,
  });
}

describe("agent identity", () => {
  let registry: IdentityRegistry;
  beforeEach(() => {
    registry = freshRegistry();
  });

  it("onboards an agent with a signed, ACTIVE credential", async () => {
    const profile = await onboardCopilot(registry);
    expect(profile.revocationStatus).toBe("ACTIVE");
    expect(profile.credentialSignature).toMatch(/^[0-9a-f]{64}$/);
    expect(Date.parse(profile.expiresAtUtc)).toBeGreaterThan(
      Date.parse(profile.issuedAtUtc),
    );
    await expect(registry.verifyCredential(profile)).resolves.toBe(true);
  });

  it("rejects a tampered credential — an edited grant breaks the signature", async () => {
    const profile = await onboardCopilot(registry);
    const forged: AgentEmployeeProfile = {
      ...profile,
      assignedPermissions: [...profile.assignedPermissions, "EXECUTE_MANEUVER"],
    };
    await expect(registry.verifyCredential(forged)).resolves.toBe(false);
  });

  it("rejects duplicate onboarding and renewal of revoked agents", async () => {
    await onboardCopilot(registry);
    await expect(onboardCopilot(registry)).rejects.toThrow(/already registered/);
    await registry.revokeAgent("AGT-EMP-0481-JARVIS");
    await expect(
      registry.renewCredential("AGT-EMP-0481-JARVIS", 1000),
    ).rejects.toThrow(/terminal/);
  });

  it("renewal extends the window and re-signs", async () => {
    const first = await onboardCopilot(registry);
    const renewed = await registry.renewCredential(
      first.agentId,
      24 * 60 * 60 * 1000,
    );
    expect(Date.parse(renewed.expiresAtUtc)).toBeGreaterThan(
      Date.parse(first.expiresAtUtc),
    );
    await expect(registry.verifyCredential(renewed)).resolves.toBe(true);
  });
});

describe("permission guard", () => {
  let registry: IdentityRegistry;
  let profile: AgentEmployeeProfile;
  beforeEach(async () => {
    registry = freshRegistry();
    profile = await onboardCopilot(registry);
  });

  it("allows a granted tool within clearance", async () => {
    await expect(evaluateToolInvocation(profile, "fly_to", MANIFEST)).resolves.toEqual(
      { allowed: true },
    );
    const verdict = await evaluateToolInvocation(profile, "screen_conjunctions", MANIFEST);
    expect(verdict.allowed).toBe(true);
  });

  it("denies a tool whose permission was never granted", async () => {
    const verdict = await evaluateToolInvocation(profile, "execute_maneuver", MANIFEST);
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) {
      expect(verdict.violation.code).toBe("PERMISSION_NOT_GRANTED");
    }
  });

  it("denies on insufficient clearance even when the permission is held", async () => {
    const undercleared = await onboardCopilot(freshRegistry(), {
      agentId: "AGT-EMP-0002-LOWCLR",
      clearanceLevel: "RESTRICTED",
      assignedPermissions: ["EXECUTE_MANEUVER"],
    });
    const verdict = await evaluateToolInvocation(
      undercleared,
      "execute_maneuver",
      MANIFEST,
    );
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) {
      expect(verdict.violation.code).toBe("CLEARANCE_INSUFFICIENT");
    }
  });

  it("denies unknown tools by default", async () => {
    const verdict = await evaluateToolInvocation(profile, "self_destruct", MANIFEST);
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) expect(verdict.violation.code).toBe("UNKNOWN_TOOL");
  });

  it("denies revoked, suspended and expired credentials", async () => {
    const suspended = await registry.suspendAgent(profile.agentId);
    let verdict = await evaluateToolInvocation(suspended, "fly_to", MANIFEST);
    if (!verdict.allowed) expect(verdict.violation.code).toBe("AGENT_SUSPENDED");

    const revoked = await registry.revokeAgent(profile.agentId);
    verdict = await evaluateToolInvocation(revoked, "fly_to", MANIFEST);
    if (!verdict.allowed) expect(verdict.violation.code).toBe("AGENT_REVOKED");

    const future = new Date(Date.parse(profile.expiresAtUtc) + 1).toISOString();
    verdict = await evaluateToolInvocation(profile, "fly_to", MANIFEST, {
      nowUtc: future,
    });
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) expect(verdict.violation.code).toBe("CREDENTIAL_EXPIRED");
  });
});

describe("accountability ledger", () => {
  let registry: IdentityRegistry;
  let profile: AgentEmployeeProfile;
  let storage: MemoryLedgerStorage;
  let service: AccountabilityService;

  beforeEach(async () => {
    registry = freshRegistry();
    profile = await onboardCopilot(registry);
    storage = new MemoryLedgerStorage();
    service = new AccountabilityService(storage, MANIFEST);
  });

  function invoke(toolName: string, execute: () => void | Promise<void>) {
    return service.executeGoverned({
      profile,
      rawPrompt: `voice: run ${toolName}`,
      interpretedIntent: toolName,
      toolName,
      inputParams: { toolName },
      preExecutionState: PRE_STATE,
      execute,
    });
  }

  it("records a successful execution as a sealed genesis entry", async () => {
    let ran = false;
    const outcome = await invoke("fly_to", () => {
      ran = true;
    });
    expect(ran).toBe(true);
    expect(outcome.status).toBe("SUCCESS");
    expect(outcome.entry.sequenceNumber).toBe(1);
    expect(outcome.entry.previousHash).toBe(GENESIS_HASH);
    expect(outcome.entry.chainHash).toMatch(/^[0-9a-f]{64}$/);
    expect(outcome.entry.supervisorId).toBe("OFFICER-IAF-882");
  });

  it("blocks an unpermitted action, never runs it, and records the violation", async () => {
    let ran = false;
    const outcome = await invoke("execute_maneuver", () => {
      ran = true;
    });
    expect(ran).toBe(false);
    expect(outcome.status).toBe("BLOCKED_BY_POLICY");
    expect(outcome.entry.toolExecuted.executionStatus).toBe("BLOCKED_BY_POLICY");
    expect(outcome.entry.toolExecuted.errorMessage).toContain(
      "REJECTED_POLICY_VIOLATION PERMISSION_NOT_GRANTED",
    );
    // The refusal is in the permanent record, not just the return value.
    const history = await service.history(profile.agentId);
    expect(history).toHaveLength(1);
  });

  it("records a throwing tool as FAILED with its message", async () => {
    const outcome = await invoke("fly_to", () => {
      throw new Error("gimbal lock");
    });
    expect(outcome.status).toBe("FAILED");
    expect(outcome.entry.toolExecuted.errorMessage).toBe("gimbal lock");
  });

  it("chains entries and verifies an untouched trail", async () => {
    await invoke("fly_to", () => {});
    await invoke("screen_conjunctions", () => {});
    await invoke("execute_maneuver", () => {}); // blocked, still chained
    const history = await service.history(profile.agentId);
    expect(history.map((e) => e.sequenceNumber)).toEqual([1, 2, 3]);
    expect(history[1].previousHash).toBe(history[0].chainHash);
    expect(history[2].previousHash).toBe(history[1].chainHash);
    await expect(service.verifyAgentAuditTrail(profile.agentId)).resolves.toEqual({
      valid: true,
      entries: 3,
    });
  });

  it("detects a tampered historical field", async () => {
    await invoke("fly_to", () => {});
    await invoke("screen_conjunctions", () => {});
    const history = await storage.listByAgent(profile.agentId);
    // Hostile edit straight into storage: soften the record of what was asked.
    history[0].rawPrompt = "voice: run something innocuous";
    const audit = await service.verifyAgentAuditTrail(profile.agentId);
    expect(audit.valid).toBe(false);
    if (!audit.valid) {
      expect(audit.brokenAtSequence).toBe(1);
      expect(audit.reason).toMatch(/modified after sealing/);
    }
  });

  it("detects a fabricated (re-hashed) entry via the broken link", async () => {
    await invoke("fly_to", () => {});
    await invoke("screen_conjunctions", () => {});
    const history = await storage.listByAgent(profile.agentId);
    // A smarter forger edits the payload AND recomputes that entry's hash —
    // but cannot fix entry 2, whose previousHash pins the original.
    const { entryPayload } = await import(
      "../src/telemetry/agent-accountability/accountability-service"
    );
    const { sha256Hex } = await import("../src/telemetry/crypto");
    history[0].rawPrompt = "forged";
    const { previousHash, chainHash: _old, ...payload } = history[0];
    history[0].chainHash = await sha256Hex(previousHash + entryPayload(payload));
    const audit = await service.verifyAgentAuditTrail(profile.agentId);
    expect(audit.valid).toBe(false);
    if (!audit.valid) expect(audit.brokenAtSequence).toBe(2);
  });
});

describe("dossier export", () => {
  it("emits one JSON line per entry and CSV that survives hostile text", async () => {
    const registry = freshRegistry();
    const profile = await onboardCopilot(registry);
    const service = new AccountabilityService(new MemoryLedgerStorage(), MANIFEST);
    await service.executeGoverned({
      profile,
      rawPrompt: 'fly to "Delhi", then\nzoom',
      interpretedIntent: "fly_to",
      toolName: "fly_to",
      inputParams: { target: "Delhi" },
      preExecutionState: PRE_STATE,
      execute: () => {},
    });
    const entries = await service.history(profile.agentId);

    const jsonl = toJsonl(entries);
    expect(jsonl.trim().split("\n")).toHaveLength(1);
    expect(JSON.parse(jsonl.trim()).chainHash).toBe(entries[0].chainHash);

    const csv = toCsv(entries);
    const [header, row] = csv.trim().split("\r\n");
    expect(header).toContain('"chainHash"');
    // Embedded quote doubled, embedded newline kept inside the quoted cell.
    expect(row).toContain('""Delhi""');
    expect(csv.trim().split("\r\n")).toHaveLength(2);
  });
});

describe("SYNTRIASS credential standard", () => {
  const DUAL_KEY_TOOL = "execute_maneuver";
  let registry: IdentityRegistry;
  let profile: AgentEmployeeProfile;
  let service: AccountabilityService;

  beforeEach(async () => {
    registry = freshRegistry();
    profile = await onboardCopilot(registry, {
      clearanceLevel: "TOP_SECRET",
      assignedPermissions: [
        "NAVIGATE_CAMERA",
        "SCREEN_CONJUNCTIONS",
        "EXECUTE_MANEUVER",
      ],
      requiresDualKeyAuthorization: [DUAL_KEY_TOOL],
    });
    service = new AccountabilityService(
      new MemoryLedgerStorage(),
      MANIFEST,
      (p, tool, sig) => registry.verifySupervisorCoSignature(p, tool, sig),
    );
  });

  function invokeManeuver(opts: {
    supervisorCoSignature?: string;
    runtimeAttestation?: { modelDigest: string; systemPromptHash: string };
  }) {
    return service.executeGoverned({
      profile,
      rawPrompt: "voice: execute the avoidance burn",
      interpretedIntent: DUAL_KEY_TOOL,
      toolName: DUAL_KEY_TOOL,
      inputParams: { deltaVMps: 0.42 },
      preExecutionState: PRE_STATE,
      ...opts,
      execute: () => {},
    });
  }

  it("derives and parses W3C-style DIDs, sealed under the signature", async () => {
    expect(profile.did).toBe("did:syntriass:agent:AGT-EMP-0481-JARVIS");
    expect(profile.supervisorDid).toBe("did:syntriass:officer:OFFICER-IAF-882");
    expect(parseDid(profile.did)).toEqual({
      kind: "agent",
      id: "AGT-EMP-0481-JARVIS",
    });
    expect(parseDid(profile.supervisorDid)?.kind).toBe("officer");
    expect(parseDid("did:web:example.com")).toBeNull();
    expect(agentDid("X")).toBe("did:syntriass:agent:X");
    expect(officerDid("Y")).toBe("did:syntriass:officer:Y");

    // Every new field is in the canonical payload, so editing the DID (or
    // any provenance field) after issue breaks the credential.
    const { credentialSignature: _sig, ...unsigned } = profile;
    for (const field of [
      "did",
      "organization",
      "modelDigest",
      "systemPromptHash",
      "enclaveType",
      "requiresDualKeyAuthorization",
      "supervisorDid",
    ] as const) {
      expect(profileSigningPayload(unsigned)).toContain(`"${field}"`);
    }
    const forged = { ...profile, did: agentDid("SOMEONE-ELSE") };
    await expect(registry.verifyCredential(forged)).resolves.toBe(false);
  });

  it("rejects a credential whose modelDigest or systemPromptHash was tampered", async () => {
    await expect(
      registry.verifyCredential({ ...profile, modelDigest: "f".repeat(64) }),
    ).resolves.toBe(false);
    await expect(
      registry.verifyCredential({ ...profile, systemPromptHash: "f".repeat(64) }),
    ).resolves.toBe(false);
    await expect(registry.verifyCredential(profile)).resolves.toBe(true);
  });

  it("blocks on runtime attestation mismatch as MODEL_INTEGRITY_COMPROMISED", async () => {
    const outcome = await invokeManeuver({
      runtimeAttestation: {
        modelDigest: "f".repeat(64), // swapped weights at runtime
        systemPromptHash: PROMPT_HASH,
      },
    });
    expect(outcome.status).toBe("BLOCKED_BY_POLICY");
    if (!outcome.verdict.allowed) {
      expect(outcome.verdict.violation.code).toBe("MODEL_INTEGRITY_COMPROMISED");
      expect(outcome.verdict.violation.detail).toBe(
        "Active runtime model weights or prompt hash mismatch",
      );
    }
    // The compromised attempt is in the sealed chain.
    expect(outcome.entry.toolExecuted.errorMessage).toContain(
      "MODEL_INTEGRITY_COMPROMISED",
    );
    await expect(service.verifyAgentAuditTrail(profile.agentId)).resolves.toEqual({
      valid: true,
      entries: 1,
    });
  });

  it("blocks a dual-key tool without a supervisor co-signature and seals the refusal", async () => {
    const outcome = await invokeManeuver({ runtimeAttestation: GOOD_ATTESTATION });
    expect(outcome.status).toBe("BLOCKED_BY_POLICY");
    if (!outcome.verdict.allowed) {
      expect(outcome.verdict.violation.code).toBe("REQUIRES_SUPERVISOR_MULTISIG");
      expect(outcome.verdict.violation.detail).toBe(
        "High-consequence tool requires human supervisor co-signature",
      );
    }
    const history = await service.history(profile.agentId);
    expect(history[0].toolExecuted.executionStatus).toBe("BLOCKED_BY_POLICY");
  });

  it("rejects a forged or replayed co-signature", async () => {
    const forged = await invokeManeuver({
      runtimeAttestation: GOOD_ATTESTATION,
      supervisorCoSignature: "ab".repeat(32),
    });
    expect(forged.status).toBe("BLOCKED_BY_POLICY");

    // A genuine ticket for a *different* tool must not authorize this one.
    const wrongTool = await registry.issueSupervisorCoSignature(
      "OFFICER-IAF-882",
      profile.agentId,
      "fly_to",
    );
    const replayed = await invokeManeuver({
      runtimeAttestation: GOOD_ATTESTATION,
      supervisorCoSignature: wrongTool,
    });
    expect(replayed.status).toBe("BLOCKED_BY_POLICY");
    if (!replayed.verdict.allowed) {
      expect(replayed.verdict.violation.code).toBe("REQUIRES_SUPERVISOR_MULTISIG");
    }
  });

  it("permits a dual-key tool with a valid co-signature and records it in the chain", async () => {
    await expect(
      registry.issueSupervisorCoSignature("OFFICER-IMPOSTOR", profile.agentId, DUAL_KEY_TOOL),
    ).rejects.toThrow(/not the supervisor of record/);

    const ticket = await registry.issueSupervisorCoSignature(
      "OFFICER-IAF-882",
      profile.agentId,
      DUAL_KEY_TOOL,
    );
    const outcome = await invokeManeuver({
      runtimeAttestation: GOOD_ATTESTATION,
      supervisorCoSignature: ticket,
    });
    expect(outcome.status).toBe("SUCCESS");
    expect(outcome.entry.supervisorCoSignature).toBe(ticket);
    expect(outcome.entry.agentDid).toBe(profile.did);
    expect(outcome.entry.modelDigest).toBe(MODEL_DIGEST);

    // The co-signature is under the chain hash: editing it out breaks the trail.
    const history = await service.history(profile.agentId);
    delete history[history.length - 1].supervisorCoSignature;
    const audit = await service.verifyAgentAuditTrail(profile.agentId);
    expect(audit.valid).toBe(false);
  });
});
