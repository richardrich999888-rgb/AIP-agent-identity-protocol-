/**
 * The console's default governance context: one registry, one ledger, one
 * accountability service, and the tool manifest they enforce — so the badge
 * HUD, the voice/task agent host, and any future governed surface all talk
 * about the same agents and append to the same chain.
 *
 * # Signing secret
 *
 * The default registry signs credentials with a random per-session secret
 * and keeps profiles in memory only. That is deliberate: a secret shipped in
 * the bundle would make every "signature" theatre, and persisting profiles
 * signed by a key that dies with the tab would leave rows that can never
 * verify again. A deployment that wants agents to survive reloads
 * constructs its own `IdentityRegistry` with an operator-configured secret
 * and passes it to the HUD. The *ledger* persists regardless — history must
 * outlive the session even when credentials do not.
 */

import { IdentityRegistry } from "./agent-identity/identity-registry";
import type { ToolManifest } from "./agent-identity/permission-guard";
import { AccountabilityService } from "./agent-accountability/accountability-service";
import { createLedgerStorage } from "./agent-accountability/ledger-storage";
import { createNexoraStore } from "./nexora/nexora-store";
import { NexoraAnchorChain } from "./nexora/anchor-chain";
import { AipDelegationAuthority, AipDelegationGraph } from "./nexora/delegation-graph";
import { AipEvidenceSealer } from "./nexora/aip-evidence";
import { NexoraVerifier } from "./nexora/nexora-verifier";

/**
 * The console's tool mandates. Default-deny lives in the guard: a tool
 * absent from this table cannot be invoked by any agent, so adding a
 * governed capability starts by naming its permission and clearance here.
 */
export const CONSOLE_TOOL_MANIFEST: ToolManifest = {
  fly_to: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
  set_shader: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
  read_sensors: { requiredPermission: "READ_SENSORS", minimumClearance: "RESTRICTED" },
  screen_conjunctions: {
    requiredPermission: "SCREEN_CONJUNCTIONS",
    minimumClearance: "CONFIDENTIAL",
  },
  task_sensor: { requiredPermission: "TASK_SENSORS", minimumClearance: "SECRET" },
  execute_maneuver: {
    // An orbital burn is the console's most consequential verb; the mandate
    // is intentionally the strictest row in the table.
    requiredPermission: "EXECUTE_MANEUVER",
    minimumClearance: "TOP_SECRET",
  },

  // ── Voice copilot (JARVIS) tool suite — src/agent/tactical-tools.ts ──
  // Camera and display verbs move the operator's view, nothing else.
  fly_to_location: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
  orbit_entity: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
  cockpit_mode: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
  set_shader_mode: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
  toggle_data_layer: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
  annotate_bounding_box: { requiredPermission: "ANNOTATE", minimumClearance: "RESTRICTED" },
  // Reads of the live picture carry the picture's own sensitivity.
  get_nearby_contacts: { requiredPermission: "READ_SENSORS", minimumClearance: "RESTRICTED" },
  screen_conjunction_threats: {
    requiredPermission: "SCREEN_CONJUNCTIONS",
    minimumClearance: "CONFIDENTIAL",
  },
  // Plans a burn but does not execute one — execution stays behind
  // execute_maneuver's TOP_SECRET dual-key posture.
  compute_avoidance_maneuver: {
    requiredPermission: "PLAN_MANEUVER",
    minimumClearance: "SECRET",
  },
};

function sessionSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export const agentRegistry = new IdentityRegistry(sessionSecret(), {
  persist: false,
});

export const accountability = new AccountabilityService(
  createLedgerStorage(),
  CONSOLE_TOOL_MANIFEST,
  // Dual-key tickets are minted and verified by the same registry that
  // issued the agent's credential — one key authority per session.
  (profile, toolName, signature) =>
    agentRegistry.verifySupervisorCoSignature(profile, toolName, signature),
);

// ── NEXORA tier: lifecycle anchors, delegation graph, AIP evidence ────────
//
// The store persists (nexora_lifecycle_db), so an agent's genesis and its
// sealed history survive reloads. The delegation authority's signing secret
// is per-session, like the registry's: edges from a previous session fail
// verification and are simply not usable authority — the new session
// delegates a fresh edge, and *that delegation is itself an anchored
// milestone*, so the chain honestly records each session's grant instead of
// pretending one credential lived forever.

export const nexoraStore = createNexoraStore();
export const nexoraAnchors = new NexoraAnchorChain(nexoraStore);
export const nexoraAuthority = new AipDelegationAuthority(sessionSecret());
export const nexoraGraph = new AipDelegationGraph(nexoraStore, nexoraAnchors, nexoraAuthority);
export const aipSealer = new AipEvidenceSealer({
  store: nexoraStore,
  anchors: nexoraAnchors,
  graph: nexoraGraph,
  authority: nexoraAuthority,
  manifest: CONSOLE_TOOL_MANIFEST,
});
export const nexoraVerifier = new NexoraVerifier(nexoraStore);

/** Change notifications for governance milestones that no store emits
 * itself (lifecycle anchors, delegation edges, evidence packets). The
 * governed dispatch path notifies after onboarding and after every sealed
 * action, so ledger UIs re-read the stores instead of polling. */
export class ChangeFeed {
  private readonly listeners = new Set<() => void>();
  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  notify(): void {
    for (const l of this.listeners) l();
  }
}

export const governanceFeed = new ChangeFeed();
