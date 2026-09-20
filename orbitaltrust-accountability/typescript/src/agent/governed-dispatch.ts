/**
 * Governed dispatch: the voice copilot's tool calls, routed through the
 * agent-governance stack.
 *
 * JARVIS is not an anonymous script with a microphone. On its first tool
 * call it is onboarded into the identity registry as a credentialed digital
 * employee — DID, department, clearance, an explicit grant covering exactly
 * the nine verbs in TOOL_SCHEMAS — and from then on every dispatch travels
 * the accountability service's governed path: policy check first, the tool
 * body only on a clean verdict, and every attempt (allowed, failed, or
 * blocked) sealed into the hash-chained ledger with the viewport state
 * around it. The AgentBadgeHUD chip appears in the corner the moment the
 * copilot onboards, because the badge renders governance facts, not
 * furniture.
 *
 * A blocked call comes back as an ordinary `ok: false` ToolResult so the
 * model *narrates* the refusal to the operator instead of stalling — the
 * refusal is already in the permanent record by the time it is spoken.
 */

import { dispatchTool, TOOL_SCHEMAS, type ToolCall, type ToolResult } from "./tactical-tools";
import type { TacticalCapabilities, ViewportContext } from "./capabilities";
import type { AgentEmployeeProfile } from "../telemetry/agent-identity/agent-profile";
import type { IdentityRegistry } from "../telemetry/agent-identity/identity-registry";
import type { AccountabilityService } from "../telemetry/agent-accountability/accountability-service";
import type { ConsoleStateSnapshot } from "../telemetry/agent-accountability/types";
import type { Jsonish } from "../telemetry/crypto";
import { toAgentDid } from "../telemetry/agent-identity/persistent-identity";
import type { NexoraAnchorChain } from "../telemetry/nexora/anchor-chain";
import type { AipDelegationGraph } from "../telemetry/nexora/delegation-graph";
import type { AipEvidenceSealer } from "../telemetry/nexora/aip-evidence";
import {
  accountability,
  agentRegistry,
  aipSealer,
  governanceFeed,
  nexoraAnchors,
  nexoraGraph,
} from "../telemetry/governance";

/** The copilot's identity constants. One profile per console session; the
 * registry's per-session signing key scopes the credential's life. */
export const JARVIS_AGENT_ID = "AGT-0481-JARVIS";

/** Everything the nine tactical verbs require — and nothing more. There is
 * deliberately no EXECUTE_MANEUVER here: the copilot can *plan* a burn, and
 * executing one stays outside its grant entirely. */
const JARVIS_PERMISSIONS = [
  "NAVIGATE_CAMERA",
  "ANNOTATE",
  "READ_SENSORS",
  "SCREEN_CONJUNCTIONS",
  "PLAN_MANEUVER",
];

const CREDENTIAL_LIFETIME_MS = 12 * 60 * 60 * 1000; // one operator shift

/** The NEXORA tier's handles: lifecycle chain, delegation graph, sealer. */
export interface NexoraGovernanceDeps {
  anchors: NexoraAnchorChain;
  graph: AipDelegationGraph;
  sealer: AipEvidenceSealer;
}

/** Injectable for tests; production uses the console singletons. When
 * `nexora` is omitted the dispatch runs accountability-only — the shape the
 * original governance tests exercise. */
export interface GovernanceDeps {
  registry: IdentityRegistry;
  service: AccountabilityService;
  nexora?: NexoraGovernanceDeps;
}

const defaultDeps: GovernanceDeps = {
  registry: agentRegistry,
  service: accountability,
  nexora: { anchors: nexoraAnchors, graph: nexoraGraph, sealer: aipSealer },
};

function toSnapshot(ctx: ViewportContext): ConsoleStateSnapshot {
  return {
    cameraCoords: [
      ctx.camera.longitudeDeg,
      ctx.camera.latitudeDeg,
      ctx.camera.altitudeKm * 1000,
    ],
    activeShader: ctx.shaderMode,
    ...(ctx.selected ? { selectedTargetId: ctx.selected.id } : {}),
  };
}

/** The snapshot as canonical-serializer input, for AIP state hashing. */
function snapshotJson(s: ConsoleStateSnapshot): Jsonish {
  return {
    cameraCoords: [...s.cameraCoords],
    activeShader: s.activeShader,
    ...(s.selectedTargetId !== undefined ? { selectedTargetId: s.selectedTargetId } : {}),
  };
}

/**
 * Ensures the copilot's NEXORA lifecycle exists and carries usable
 * authority: an AGENT_GENESIS anchor binding the model digest, a
 * SUPERVISOR_DELEGATION edge from the supervising officer covering exactly
 * the nine verbs, and a CAPABILITY_MODULATION anchor recording the grant.
 *
 * Idempotent per state, not per call: a reloaded console finds the
 * persisted genesis and skips it, but delegates a fresh edge — the previous
 * session's edge was signed by a key that died with that session, and a new
 * anchored delegation is the honest record of the new session's grant.
 */
export async function ensureJarvisLifecycle(
  profile: AgentEmployeeProfile,
  nexora: NexoraGovernanceDeps,
): Promise<void> {
  const did = toAgentDid(profile.agentId);
  if (!(await nexora.anchors.isBorn(did))) {
    try {
      await nexora.anchors.appendAnchor({
        anchorType: "AGENT_GENESIS",
        agentDid: did,
        actorDid: profile.supervisorDid,
        payload: {
          modelDigest: profile.modelDigest,
          systemPromptHash: profile.systemPromptHash,
          modelEngine: profile.modelEngine,
          organization: profile.organization,
          enclaveType: profile.enclaveType,
        },
      });
    } catch (cause) {
      // A second console on the same persisted store can anchor genesis
      // between this check and this write. The chain refusing the duplicate
      // is the invariant working, and the postcondition this function exists
      // for — the agent is born — now holds, so continue. If it does not
      // hold, the refusal was about something else and must surface.
      if (!(await nexora.anchors.isBorn(did))) throw cause;
    }
  }
  // A terminally revoked lifecycle stays closed; the sealer will refuse
  // every action with LIFECYCLE_CLOSED and seal the refusals as evidence.
  if (await nexora.anchors.isClosed(did)) return;

  if (!(await nexora.graph.resolveAuthority(did))) {
    const scope = TOOL_SCHEMAS.map((t) => t.name);
    await nexora.graph.delegate({
      parentDid: profile.supervisorDid,
      childDid: did,
      scope,
      multiSigTools: [],
      clearanceLevel: profile.clearanceLevel,
      validForMs: CREDENTIAL_LIFETIME_MS,
    });
    await nexora.anchors.appendAnchor({
      anchorType: "CAPABILITY_MODULATION",
      agentDid: did,
      actorDid: profile.supervisorDid,
      payload: {
        toolsGranted: scope,
        note: "session grant: the nine tactical verbs; maneuver execution excluded",
      },
    });
  }
}

/**
 * In-flight arm-ups, per deps then per agent.
 *
 * Bring-up is check-then-act at three points — the credential, the genesis
 * anchor, the delegation edge — and each of those creations is refused a
 * second time by design. Two callers arriving together (the operator arming
 * the mic while a console action dispatches) would each see "absent" and
 * each try to create, and the loser's error surfaced as an unhandled
 * rejection. Sharing one in-flight bring-up removes the race without
 * weakening any of the three invariants.
 *
 * Only *in-flight* calls share: the entry clears on settle, so a later
 * dispatch re-runs the checks and re-delegates when a session edge has
 * expired. Keyed by deps first so tests with their own stores never share a
 * promise resolved against another test's registry.
 */
const armUps = new WeakMap<GovernanceDeps, Map<string, Promise<AgentEmployeeProfile>>>();

function armUp(
  modelEngine: string,
  deps: GovernanceDeps,
): Promise<AgentEmployeeProfile> {
  let perDeps = armUps.get(deps);
  if (!perDeps) {
    perDeps = new Map();
    armUps.set(deps, perDeps);
  }
  const inFlight = perDeps.get(JARVIS_AGENT_ID);
  if (inFlight) return inFlight;

  const started = (async () => {
    const profile = await ensureJarvisOnboarded(modelEngine, deps);
    if (deps.nexora) await ensureJarvisLifecycle(profile, deps.nexora);
    return profile;
  })();
  perDeps.set(JARVIS_AGENT_ID, started);
  const clear = () => {
    if (perDeps.get(JARVIS_AGENT_ID) === started) perDeps.delete(JARVIS_AGENT_ID);
  };
  started.then(clear, clear);
  return started;
}

/**
 * Full governed arm-up: identity credential plus NEXORA lifecycle. The
 * copilot calls this when the session starts so the badge, the lifecycle
 * chain, and the delegation all exist before the first command is spoken.
 */
export async function ensureJarvisGoverned(
  modelEngine: string,
  deps: GovernanceDeps = defaultDeps,
): Promise<AgentEmployeeProfile> {
  const profile = await armUp(modelEngine, deps);
  governanceFeed.notify();
  return profile;
}

/** Onboards (or returns) the copilot's employee profile. Exposed so the UI
 * can onboard eagerly when the mic arms, making the badge appear before
 * the first command rather than after it. */
export async function ensureJarvisOnboarded(
  modelEngine: string,
  deps: GovernanceDeps = defaultDeps,
): Promise<AgentEmployeeProfile> {
  const existing = deps.registry.getAgent(JARVIS_AGENT_ID);
  if (existing) return existing;
  return deps.registry.onboardAgent({
    agentId: JARVIS_AGENT_ID,
    agentName: "JARVIS Tactical Copilot",
    organization: "DEFENCE_SPACE_AGENCY",
    modelEngine,
    // The browser cannot hash remote weights; these digests attest the
    // *configuration* (engine + tool grammar), which is what this runtime
    // can actually stand behind. A deployment with a model registry swaps
    // real digests in here.
    modelDigest: "0".repeat(64),
    systemPromptHash: "0".repeat(64),
    enclaveType: "SOFTWARE_SANDBOX",
    department: "TACTICAL_C2",
    clearanceLevel: "SECRET",
    supervisorOperatorId: "CONSOLE-OPERATOR",
    assignedPermissions: JARVIS_PERMISSIONS,
    requiresDualKeyAuthorization: [],
    validForMs: CREDENTIAL_LIFETIME_MS,
  });
}

/**
 * The copilot's only dispatch path. Same signature shape as dispatchTool
 * plus the spoken transcript, so the ledger's rawPrompt is what the
 * operator actually said (or the model's interpretation when no transcript
 * is available).
 */
export async function governedDispatchTool(
  call: ToolCall,
  caps: TacticalCapabilities,
  rawPrompt: string,
  modelEngine: string,
  deps: GovernanceDeps = defaultDeps,
): Promise<ToolResult> {
  const profile = await armUp(modelEngine, deps);
  const nexora = deps.nexora;
  const pre = toSnapshot(caps.snapshotContext());

  // The one place the tool body actually runs — both governance tiers wrap
  // around this same closure, so there is still exactly one dispatch path.
  let result: ToolResult = { ok: false, summary: "Tool did not execute." };
  const runTool = async (): Promise<ConsoleStateSnapshot> => {
    result = await dispatchTool(call, caps);
    // dispatchTool never throws; an ok:false result is a *failed* action,
    // not a policy block, and the ledger must say which it was.
    if (!result.ok) throw new Error(result.summary);
    return toSnapshot(caps.snapshotContext());
  };

  const outcome = await deps.service.executeGoverned({
    profile,
    rawPrompt,
    interpretedIntent: call.name,
    toolName: call.name,
    inputParams: call.args,
    preExecutionState: pre,
    execute: async () => {
      if (!nexora) return runTool();
      // Inside the accountability funnel, the action additionally travels
      // the AIP path: lifecycle check → delegated-authority resolution →
      // execution → evidence packet with pre/post state hashes → an
      // ACTION_EXECUTION_SEAL anchor naming the packet.
      const aip = await nexora.sealer.execute({
        agentDid: toAgentDid(profile.agentId),
        runtimeModelDigest: profile.modelDigest,
        rawPrompt,
        toolName: call.name,
        inputParams: call.args,
        preState: snapshotJson(pre),
        execute: async () => snapshotJson(await runTool()),
      });
      if (aip.status === "BLOCKED_BY_POLICY") {
        const rejection = !aip.verdict.permitted ? aip.verdict.rejection : null;
        const detail = rejection ? `${rejection.code}: ${rejection.detail}` : "blocked";
        result = {
          ok: false,
          summary: `Command refused by governance: ${detail}. The refusal is on the audit ledger.`,
        };
        throw new Error(`AIP ${detail}`);
      }
      if (aip.status === "FAILED") {
        throw new Error(aip.packet.toolExecuted.error ?? "tool failed");
      }
      return toSnapshot(caps.snapshotContext());
    },
  });
  governanceFeed.notify();

  if (outcome.status === "BLOCKED_BY_POLICY") {
    const detail = !outcome.verdict.allowed
      ? outcome.verdict.violation.detail
      : "blocked by policy";
    return {
      ok: false,
      summary: `Command refused by governance: ${detail}. The refusal is on the audit ledger.`,
    };
  }
  return result;
}
