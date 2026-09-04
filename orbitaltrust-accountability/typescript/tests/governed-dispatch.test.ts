/**
 * The copilot-governance binding, as executable claims:
 *
 * - the first governed dispatch onboards JARVIS as a credentialed employee
 *   with exactly the nine-verb grant, and every dispatch is sealed into the
 *   hash-chained ledger with the viewport state around it;
 * - a verb outside the grant (or outside the manifest) is refused before
 *   the capability runs, and the refusal is spoken *and* on the ledger;
 * - a revoked copilot goes silent immediately — the kill-switch works on
 *   the voice agent, not just on test fixtures.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  TacticalCapabilities,
  ViewportContext,
} from "../src/agent/capabilities";
import {
  ensureJarvisGoverned,
  ensureJarvisOnboarded,
  governedDispatchTool,
  JARVIS_AGENT_ID,
  type GovernanceDeps,
} from "../src/agent/governed-dispatch";
import { IdentityRegistry } from "../src/telemetry/agent-identity/identity-registry";
import { AccountabilityService } from "../src/telemetry/agent-accountability/accountability-service";
import { MemoryLedgerStorage } from "../src/telemetry/agent-accountability/ledger-storage";
import { CONSOLE_TOOL_MANIFEST } from "../src/telemetry/governance";
import { toAgentDid } from "../src/telemetry/agent-identity/persistent-identity";
import { MemoryNexoraStore } from "../src/telemetry/nexora/nexora-store";
import { NexoraAnchorChain } from "../src/telemetry/nexora/anchor-chain";
import { NexoraVerifier } from "../src/telemetry/nexora/nexora-verifier";
import {
  AipDelegationAuthority,
  AipDelegationGraph,
} from "../src/telemetry/nexora/delegation-graph";
import { AipEvidenceSealer } from "../src/telemetry/nexora/aip-evidence";

const VIEWPORT: ViewportContext = {
  camera: { latitudeDeg: 20.5, longitudeDeg: 78.9, altitudeKm: 12000, headingDeg: 0, pitchDeg: -90 },
  selected: { id: "SPACE-25544", kind: "space", name: "ISS" },
  enabledLayers: [],
  shaderMode: "flir",
  counts: { air: 0, sea: 0, orbit: 1, alertCells: 0 },
};

function mockCaps(overrides: Partial<TacticalCapabilities> = {}): TacticalCapabilities {
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
    ...overrides,
  };
}

let deps: GovernanceDeps;

beforeEach(() => {
  const registry = new IdentityRegistry("copilot-test-secret", { persist: false });
  deps = {
    registry,
    service: new AccountabilityService(new MemoryLedgerStorage(), CONSOLE_TOOL_MANIFEST),
  };
});

describe("governed copilot dispatch", () => {
  it("onboards JARVIS on first dispatch and seals the action with viewport state", async () => {
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

    const profile = deps.registry.getAgent(JARVIS_AGENT_ID);
    expect(profile?.department).toBe("TACTICAL_C2");
    expect(profile?.assignedPermissions).not.toContain("EXECUTE_MANEUVER");
    await expect(deps.registry.verifyCredential(profile!)).resolves.toBe(true);

    const history = await deps.service.history(JARVIS_AGENT_ID);
    expect(history).toHaveLength(1);
    expect(history[0].rawPrompt).toBe("jarvis, take me to the malacca strait");
    expect(history[0].preExecutionState.activeShader).toBe("flir");
    expect(history[0].preExecutionState.selectedTargetId).toBe("SPACE-25544");
    await expect(deps.service.verifyAgentAuditTrail(JARVIS_AGENT_ID)).resolves.toEqual({
      valid: true,
      entries: 1,
    });
  });

  it("refuses a verb outside the manifest before the capability runs, and ledgers it", async () => {
    const caps = mockCaps();
    const result = await governedDispatchTool(
      { name: "self_destruct", args: {} },
      caps,
      "jarvis, self destruct",
      "groq-fast",
      deps,
    );
    expect(result.ok).toBe(false);
    expect(result.summary).toMatch(/refused by governance/i);

    const history = await deps.service.history(JARVIS_AGENT_ID);
    expect(history).toHaveLength(1);
    expect(history[0].toolExecuted.executionStatus).toBe("BLOCKED_BY_POLICY");
    expect(history[0].toolExecuted.errorMessage).toContain("UNKNOWN_TOOL");
  });

  it("keeps maneuver EXECUTION outside the copilot's grant while planning is allowed", async () => {
    const caps = mockCaps();
    const plan = await governedDispatchTool(
      { name: "compute_avoidance_maneuver", args: { satelliteId: "1", missDistanceKm: 3 } },
      caps,
      "jarvis, plan an avoidance burn",
      "groq-fast",
      deps,
    );
    expect(plan.ok).toBe(true);

    // The console's own manifest knows execute_maneuver; JARVIS's grant
    // does not, so a model hallucinating an execution verb is refused as
    // PERMISSION_NOT_GRANTED — the default-deny holds at the grant level.
    const exec = await governedDispatchTool(
      { name: "execute_maneuver", args: {} },
      caps,
      "jarvis, execute the burn",
      "groq-fast",
      deps,
    );
    expect(exec.ok).toBe(false);
    const history = await deps.service.history(JARVIS_AGENT_ID);
    expect(history[1].toolExecuted.errorMessage).toContain("PERMISSION_NOT_GRANTED");
  });

  it("a failed capability is FAILED on the ledger, not blocked, and still spoken", async () => {
    const caps = mockCaps({
      flyToLocation: vi.fn(async () => {
        throw new Error("gimbal lock");
      }),
    });
    const result = await governedDispatchTool(
      { name: "fly_to_location", args: { query: "x" } },
      caps,
      "jarvis, fly",
      "groq-fast",
      deps,
    );
    expect(result.ok).toBe(false);
    const history = await deps.service.history(JARVIS_AGENT_ID);
    expect(history[0].toolExecuted.executionStatus).toBe("FAILED");
  });

  it("the kill-switch silences the copilot immediately", async () => {
    await ensureJarvisOnboarded("groq-fast", deps);
    await deps.registry.revokeAgent(JARVIS_AGENT_ID);
    const caps = mockCaps();
    const result = await governedDispatchTool(
      { name: "fly_to_location", args: { query: "x" } },
      caps,
      "jarvis, fly",
      "groq-fast",
      deps,
    );
    expect(result.ok).toBe(false);
    expect(caps.flyToLocation).not.toHaveBeenCalled();
    const history = await deps.service.history(JARVIS_AGENT_ID);
    expect(history[0].toolExecuted.errorMessage).toContain("AGENT_REVOKED");
  });

  it("concurrent arm-up shares one bring-up instead of racing genesis", async () => {
    // The reachable case: the operator arms the mic (ensureJarvisGoverned)
    // at the moment a console action dispatches. Both paths bring the agent
    // up, and bring-up is check-then-act at the credential, the genesis
    // anchor and the delegation edge — each of which refuses a second
    // write. Before they shared one in-flight arm-up, the loser's refusal
    // escaped as an unhandled rejection.
    const store = new MemoryNexoraStore();
    const anchors = new NexoraAnchorChain(store);
    const authority = new AipDelegationAuthority("concurrent-arm-up-test");
    const graph = new AipDelegationGraph(store, anchors, authority);
    const nexoraDeps: GovernanceDeps = {
      ...deps,
      nexora: {
        anchors,
        graph,
        sealer: new AipEvidenceSealer({
          store,
          anchors,
          graph,
          authority,
          manifest: CONSOLE_TOOL_MANIFEST,
        }),
      },
    };
    const caps = mockCaps();

    const [armed, ...dispatched] = await Promise.all([
      ensureJarvisGoverned("groq-fast", nexoraDeps),
      governedDispatchTool(
        { name: "fly_to_location", args: { query: "a" } },
        caps,
        "jarvis, fly",
        "groq-fast",
        nexoraDeps,
      ),
      governedDispatchTool(
        { name: "set_shader_mode", args: { mode: "nvg" } },
        caps,
        "jarvis, night vision",
        "groq-fast",
        nexoraDeps,
      ),
    ]);
    expect(armed.agentId).toBe(JARVIS_AGENT_ID);
    for (const result of dispatched) expect(result.ok).toBe(true);

    // Exactly one genesis, and one delegation: the invariants the race
    // would have violated (or crashed trying to uphold).
    const did = toAgentDid(JARVIS_AGENT_ID);
    const written = await store.listAnchorsForAgent(did);
    const count = (type: string) => written.filter((a) => a.anchorType === type).length;
    expect(count("AGENT_GENESIS")).toBe(1);
    expect(count("SUPERVISOR_DELEGATION")).toBe(1);
    expect(count("CAPABILITY_MODULATION")).toBe(1);
    // And the chain the auditor reads still verifies end to end.
    await expect(
      new NexoraVerifier(store).verifyAnchorChain(did),
    ).resolves.toMatchObject({ valid: true });
  });

  it("every copilot verb in TOOL_SCHEMAS has a mandate in the console manifest", async () => {
    const { TOOL_SCHEMAS } = await import("../src/agent/tactical-tools");
    for (const schema of TOOL_SCHEMAS) {
      expect(CONSOLE_TOOL_MANIFEST[schema.name], schema.name).toBeDefined();
    }
  });
});
