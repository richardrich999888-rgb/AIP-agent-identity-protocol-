/**
 * The digital-worker identity contract.
 *
 * An autonomous agent on this console is not an anonymous script: it is a
 * credentialed digital employee with a department, a clearance, a named human
 * supervisor, an explicit permission grant, and an expiring, signed
 * credential. Everything the permission guard and the accountability ledger
 * do downstream keys off this profile, so the shape is defined once here.
 */

import { canonicalJson, type Jsonish } from "../crypto";

/** Tactical operational unit the agent is assigned to. */
export type AgentDepartment =
  | "AEROSPACE_OPS"
  | "CONJUNCTION_ANALYSIS"
  | "TACTICAL_C2"
  | "ELECTRONIC_SURVEILLANCE"
  | "FLIGHT_DISPATCH";

/** Clearance ladder, low to high. Order matters: see {@link CLEARANCE_RANK}. */
export type ClearanceLevel =
  | "UNCLASSIFIED"
  | "RESTRICTED"
  | "CONFIDENTIAL"
  | "SECRET"
  | "TOP_SECRET";

/** Lifecycle state of the credential. SUSPENDED is reversible; REVOKED is
 * the kill-switch and is terminal. */
export type RevocationStatus = "ACTIVE" | "SUSPENDED" | "REVOKED";

/** Issuing organisation. An enumerated union rather than free text: a
 * credential naming an organisation nobody recognises should fail the
 * typecheck, not surface at audit time. */
export type AgentOrganization =
  | "SYNTRIASS_LABS"
  | "DEFENCE_SPACE_AGENCY"
  | "INDIAN_AIR_FORCE";

/** Where the agent's inference actually runs. SOFTWARE_SANDBOX is the
 * honest label for "no hardware root of trust" — a browser console must be
 * able to say so rather than imply attestation it does not have. */
export type EnclaveType =
  | "SOFTWARE_SANDBOX"
  | "TPM_2_0"
  | "APPLE_SECURE_ENCLAVE"
  | "AWS_NITRO";

/** DID method for this standard. */
export const DID_METHOD = "syntriass";

/** Parsed form of a `did:syntriass:<kind>:<id>` identifier. */
export interface SyntriassDid {
  kind: "agent" | "officer";
  id: string;
}

/** `did:syntriass:agent:<id>` for a digital worker. */
export function agentDid(agentId: string): string {
  return `did:${DID_METHOD}:agent:${agentId}`;
}

/** `did:syntriass:officer:<id>` for a human supervisor. */
export function officerDid(operatorId: string): string {
  return `did:${DID_METHOD}:officer:${operatorId}`;
}

/** Parses a SYNTRIASS DID, or returns null for anything else — including
 * other DID methods, which this console does not resolve. The id segment may
 * itself contain colons (UUID-free operator ids sometimes do), so only the
 * first three segments are structural. */
export function parseDid(did: string): SyntriassDid | null {
  const m = /^did:syntriass:(agent|officer):(.+)$/.exec(did);
  if (!m) return null;
  return { kind: m[1] as SyntriassDid["kind"], id: m[2] };
}

/**
 * SYNTRIASS Agent Credential Standard: the digital worker's full identity
 * contract — W3C-style DID, organisation, model/enclave provenance, and the
 * multi-sig rules for high-consequence tools, all under one signature.
 */
export interface AgentEmployeeProfile {
  /** e.g. "AGT-EMP-0481-JARVIS" */
  agentId: string;
  /** W3C-style DID: `did:syntriass:agent:<agentId>`. */
  did: string;
  /** e.g. "Orbital Tactical Copilot" */
  agentName: string;
  organization: AgentOrganization;
  /** e.g. "llama-3.3-70b" or "whisper+ollama" */
  modelEngine: string;
  /** SHA-256 of the active LLM weights / quantization profile (hex). */
  modelDigest: string;
  /** SHA-256 of the system guardrails and base instructions (hex). */
  systemPromptHash: string;
  /** Execution environment the inference is attested to run in. */
  enclaveType: EnclaveType;
  department: AgentDepartment;
  clearanceLevel: ClearanceLevel;
  /** Human operator/commander in charge, e.g. "OFFICER-IAF-882". */
  supervisorOperatorId: string;
  /** `did:syntriass:officer:<supervisorOperatorId>`. */
  supervisorDid: string;
  /** Granted tool verbs, e.g. ['fly_to', 'screen_conjunctions']. */
  assignedPermissions: string[];
  /** Tools that additionally demand a human supervisor co-signature per
   * invocation, e.g. ['execute_thruster_burn', 'deorbit_satellite']. */
  requiresDualKeyAuthorization: string[];
  revocationStatus: RevocationStatus;
  issuedAtUtc: string;
  expiresAtUtc: string;
  /** HMAC-SHA-256 over the canonical profile payload (hex). */
  credentialSignature: string;
}

/** The standard's name for the credential; the profile alias remains for the
 * subsystem's original vocabulary. */
export type SyntriassAgentCredential = AgentEmployeeProfile;

/** Numeric rank per clearance so "at least SECRET" is a comparison, not a
 * hand-maintained list of allowed strings at every call site. */
export const CLEARANCE_RANK: Record<ClearanceLevel, number> = {
  UNCLASSIFIED: 0,
  RESTRICTED: 1,
  CONFIDENTIAL: 2,
  SECRET: 3,
  TOP_SECRET: 4,
};

/** True when `held` grants access to material requiring `required`. */
export function meetsClearance(
  held: ClearanceLevel,
  required: ClearanceLevel,
): boolean {
  return CLEARANCE_RANK[held] >= CLEARANCE_RANK[required];
}

/**
 * The exact bytes the credential signature covers: every profile field
 * except the signature itself, canonically serialized. Signing the
 * revocation status, the permission list, the DIDs, the model/enclave
 * provenance and the dual-key list means any in-flight edit — an extra
 * permission, a swapped model digest, a tool quietly dropped from the
 * multi-sig roster, a REVOKED flipped back to ACTIVE — breaks the signature
 * rather than passing as issued.
 */
export function profileSigningPayload(
  profile: Omit<AgentEmployeeProfile, "credentialSignature">,
): string {
  const payload: Jsonish = {
    agentId: profile.agentId,
    did: profile.did,
    agentName: profile.agentName,
    organization: profile.organization,
    modelEngine: profile.modelEngine,
    modelDigest: profile.modelDigest,
    systemPromptHash: profile.systemPromptHash,
    enclaveType: profile.enclaveType,
    department: profile.department,
    clearanceLevel: profile.clearanceLevel,
    supervisorOperatorId: profile.supervisorOperatorId,
    supervisorDid: profile.supervisorDid,
    assignedPermissions: [...profile.assignedPermissions],
    requiresDualKeyAuthorization: [...profile.requiresDualKeyAuthorization],
    revocationStatus: profile.revocationStatus,
    issuedAtUtc: profile.issuedAtUtc,
    expiresAtUtc: profile.expiresAtUtc,
  };
  return canonicalJson(payload);
}
