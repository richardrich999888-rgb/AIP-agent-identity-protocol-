/**
 * The policy gatekeeper: every tool invocation is checked here before it
 * runs, against the agent's permission grant, clearance, credential window,
 * revocation state, runtime model attestation, and — for high-consequence
 * tools — the human supervisor's per-invocation co-signature.
 *
 * # Default-deny, and why the verdict is a value
 *
 * A tool not in the manifest is refused, not waved through — an unmapped
 * tool is a governance gap, and the safe reading of a gap is "nobody
 * authorized this". The guard returns a verdict object rather than throwing:
 * a denial is not an exceptional program state, it is a *result* that the
 * accountability service must record as a REJECTED_POLICY_VIOLATION event,
 * and results that must be logged should be impossible to lose in a catch
 * block somewhere above.
 *
 * # Order of checks
 *
 * Revocation first: a revoked agent with a perfectly valid permission list
 * is still revoked, and the violation code should say so. Then the
 * credential window (a dead credential's grants are moot), then runtime
 * model integrity — an agent whose weights or system prompt no longer match
 * the signed credential is not the credentialed employee at all, so no
 * tool-level reasoning applies. The per-tool mandate follows, and the
 * dual-key check comes last: multi-sig is an *additional* requirement on an
 * invocation that is otherwise fully permitted, and reporting it first
 * would mask a missing permission behind a request for a co-signature.
 *
 * # Why the guard is async now
 *
 * The supervisor co-signature is a cryptographic object (HMAC issued by the
 * identity registry), and verifying it goes through WebCrypto. A guard that
 * only checked the signature's *presence* would accept any pasted string as
 * supervisor consent, which is theatre.
 */

import {
  meetsClearance,
  type AgentEmployeeProfile,
  type ClearanceLevel,
} from "./agent-profile";

/** What a tool demands of its caller. */
export interface ToolMandate {
  /** Permission verb the agent must hold, e.g. "EXECUTE_MANEUVER". */
  requiredPermission: string;
  /** Minimum clearance for the data the tool touches. */
  minimumClearance: ClearanceLevel;
}

/** Tool name → mandate. Tools absent from the manifest are denied. */
export type ToolManifest = Record<string, ToolMandate>;

export type PolicyViolationCode =
  | "AGENT_REVOKED"
  | "AGENT_SUSPENDED"
  | "CREDENTIAL_EXPIRED"
  | "CREDENTIAL_NOT_YET_VALID"
  | "MODEL_INTEGRITY_COMPROMISED"
  | "UNKNOWN_TOOL"
  | "PERMISSION_NOT_GRANTED"
  | "CLEARANCE_INSUFFICIENT"
  | "REQUIRES_SUPERVISOR_MULTISIG";

export interface PolicyViolation {
  code: PolicyViolationCode;
  /** Human-readable line for the ledger and the HUD. */
  detail: string;
}

export type PolicyVerdict =
  | { allowed: true }
  | { allowed: false; violation: PolicyViolation };

/** What the runtime claims to be executing right now. Produced by the agent
 * host (hashing its loaded weights profile and system prompt), compared
 * against the values sealed into the credential. */
export interface RuntimeAttestation {
  modelDigest: string;
  systemPromptHash: string;
}

/** Verifies a supervisor co-signature for one (agent, tool) invocation.
 * Injected — typically `IdentityRegistry.verifySupervisorCoSignature` — so
 * the guard stays decoupled from where supervisor keys live. */
export type CoSignatureVerifier = (
  profile: AgentEmployeeProfile,
  toolName: string,
  signatureHex: string,
) => Promise<boolean> | boolean;

export interface InvocationContext {
  /** Clock override for tests; defaults to now. */
  nowUtc?: string;
  /** What the runtime is actually executing. When omitted, the host did not
   * attest and the integrity check is skipped — see the note on
   * {@link evaluateToolInvocation}. */
  runtimeAttestation?: RuntimeAttestation;
  /** Human supervisor's per-invocation co-signature, required for tools in
   * the profile's requiresDualKeyAuthorization list. */
  supervisorCoSignature?: string;
  /** How to verify that co-signature. Without one, no co-signature can be
   * accepted — unverifiable consent is treated as absent. */
  verifyCoSignature?: CoSignatureVerifier;
}

/**
 * Validates one prospective tool invocation. No logging, no side effects —
 * recording the outcome is the accountability service's job, so that a
 * denial and its ledger entry cannot drift apart.
 *
 * Runtime attestation is checked when supplied. A host that does not attest
 * is not failed outright — existing callers predate attestation and a
 * console-wide hard requirement is a deployment decision — but when the host
 * *does* attest, any mismatch against the signed credential is an immediate
 * MODEL_INTEGRITY_COMPROMISED denial.
 */
export async function evaluateToolInvocation(
  profile: AgentEmployeeProfile,
  toolName: string,
  manifest: ToolManifest,
  context: InvocationContext = {},
): Promise<PolicyVerdict> {
  if (profile.revocationStatus === "REVOKED") {
    return deny("AGENT_REVOKED", `agent ${profile.agentId} credential is revoked`);
  }
  if (profile.revocationStatus === "SUSPENDED") {
    return deny(
      "AGENT_SUSPENDED",
      `agent ${profile.agentId} is suspended pending supervisor review`,
    );
  }

  const now = Date.parse(context.nowUtc ?? new Date().toISOString());
  const issued = Date.parse(profile.issuedAtUtc);
  const expires = Date.parse(profile.expiresAtUtc);
  if (!Number.isFinite(now) || !Number.isFinite(issued) || !Number.isFinite(expires)) {
    // An unparseable credential window is treated as expired: a guard that
    // cannot read the clock must fail closed.
    return deny(
      "CREDENTIAL_EXPIRED",
      `credential window for ${profile.agentId} is unreadable`,
    );
  }
  if (now < issued) {
    return deny(
      "CREDENTIAL_NOT_YET_VALID",
      `credential for ${profile.agentId} is not valid until ${profile.issuedAtUtc}`,
    );
  }
  if (now >= expires) {
    return deny(
      "CREDENTIAL_EXPIRED",
      `credential for ${profile.agentId} expired at ${profile.expiresAtUtc}`,
    );
  }

  const att = context.runtimeAttestation;
  if (
    att &&
    (att.modelDigest !== profile.modelDigest ||
      att.systemPromptHash !== profile.systemPromptHash)
  ) {
    return deny(
      "MODEL_INTEGRITY_COMPROMISED",
      "Active runtime model weights or prompt hash mismatch",
    );
  }

  const mandate = manifest[toolName];
  if (!mandate) {
    return deny("UNKNOWN_TOOL", `tool "${toolName}" has no mandate in the manifest`);
  }
  if (!profile.assignedPermissions.includes(mandate.requiredPermission)) {
    return deny(
      "PERMISSION_NOT_GRANTED",
      `tool "${toolName}" requires permission "${mandate.requiredPermission}", ` +
        `which ${profile.agentId} does not hold`,
    );
  }
  if (!meetsClearance(profile.clearanceLevel, mandate.minimumClearance)) {
    return deny(
      "CLEARANCE_INSUFFICIENT",
      `tool "${toolName}" requires ${mandate.minimumClearance}; ` +
        `${profile.agentId} holds ${profile.clearanceLevel}`,
    );
  }

  if (profile.requiresDualKeyAuthorization.includes(toolName)) {
    const sig = context.supervisorCoSignature;
    if (!sig || !context.verifyCoSignature) {
      return deny(
        "REQUIRES_SUPERVISOR_MULTISIG",
        "High-consequence tool requires human supervisor co-signature",
      );
    }
    if (!(await context.verifyCoSignature(profile, toolName, sig))) {
      return deny(
        "REQUIRES_SUPERVISOR_MULTISIG",
        `supervisor co-signature for "${toolName}" failed verification`,
      );
    }
  }

  return { allowed: true };
}

function deny(code: PolicyViolationCode, detail: string): PolicyVerdict {
  return { allowed: false, violation: { code, detail } };
}
