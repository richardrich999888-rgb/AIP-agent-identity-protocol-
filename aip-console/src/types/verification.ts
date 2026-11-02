/**
 * Normative Verification and Trust Floor Types for AIP Console
 * Target: aip-console/src/types/verification.ts
 *
 * Direct 1:1 mapping to Rust engine structures in:
 * - aip-protocol::verification_report::VerificationReport
 * - aip-protocol::evidence_packet::TrustFloor
 * - aip-protocol::verification::VerificationContext
 */

export type TrustFloor =
  | "UNVERIFIED"
  | "AGENT_SIGNED"
  | "AUTHORITY_BOUND"
  | "COUNTERPARTY_SIGNED";

export const TRUST_FLOOR_ORDER: Record<TrustFloor, number> = {
  UNVERIFIED: 0,
  AGENT_SIGNED: 1,
  AUTHORITY_BOUND: 2,
  COUNTERPARTY_SIGNED: 3,
};

export const TRUST_FLOOR_META: Record<
  TrustFloor,
  {
    level: number;
    label: string;
    description: string;
    color: string;
    badgeClass: string;
    borderClass: string;
    bgClass: string;
  }
> = {
  UNVERIFIED: {
    level: 0,
    label: "UNVERIFIED",
    description: "Structure parses but cryptographic signatures invalid or unverified",
    color: "#94A3B8",
    badgeClass: "bg-slate-500/10 text-slate-400 border-slate-500/30",
    borderClass: "border-slate-700",
    bgClass: "bg-slate-900/40",
  },
  AGENT_SIGNED: {
    level: 1,
    label: "AGENT_SIGNED",
    description: "Payload sealed and cryptographically signed by acting agent",
    color: "#F59E0B",
    badgeClass: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    borderClass: "border-amber-500/50",
    bgClass: "bg-amber-950/20",
  },
  AUTHORITY_BOUND: {
    level: 2,
    label: "AUTHORITY_BOUND",
    description: "Authorized via valid delegation chain from trusted human principal",
    color: "#607D8B",
    badgeClass: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
    borderClass: "border-cyan-500/50",
    bgClass: "bg-cyan-950/20",
  },
  COUNTERPARTY_SIGNED: {
    level: 3,
    label: "COUNTERPARTY_SIGNED",
    description: "Bilateral accountability verified with external countersignature",
    color: "#2E7D32",
    badgeClass: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    borderClass: "border-emerald-500/50",
    bgClass: "bg-emerald-950/20",
  },
};

export type RuleIdentifier =
  | "STRUCTURE"
  | "AGENT_ID_BINDING"
  | "CANONICAL_HASH"
  | "AGENT_SIGNATURE"
  | "ROOT_TOKEN_SIGNATURE"
  | "DELEGATION_CHAIN"
  | "AUTHORITY_CHAIN"
  | "SCOPE_AUTHORITY"
  | "REVOCATION"
  | "TEMPORAL_VALIDITY"
  | "ACTION_ATTESTATIONS"
  | "TRACE_BINDING"
  | "RECEIPT_BINDING"
  | "TRUST_FLOOR";

export type RuleLayer =
  | "INTEGRITY"
  | "AUTHORITY"
  | "VALIDITY"
  | "BILATERAL";

export interface RuleMeta {
  index: number;
  identifier: RuleIdentifier;
  name: string;
  summary: string;
  layer: RuleLayer;
  layerName: string;
  specSection: string;
  isTamperCritical: boolean;
}

export const AIP_RULES_REGISTRY: Record<RuleIdentifier, RuleMeta> = {
  STRUCTURE: {
    index: 1,
    identifier: "STRUCTURE",
    name: "Wire Format Structure",
    summary: "Magic header 'AEP1', version 1, and mandatory non-empty record fields",
    layer: "INTEGRITY",
    layerName: "Layer 1: Cryptographic Integrity & Identity",
    specSection: "AIP_SPEC.md §4.1",
    isTamperCritical: false,
  },
  AGENT_ID_BINDING: {
    index: 2,
    identifier: "AGENT_ID_BINDING",
    name: "Agent Identity Binding",
    summary: "Base58 checksum validation and derivation from public key and provenance triple",
    layer: "INTEGRITY",
    layerName: "Layer 1: Cryptographic Integrity & Identity",
    specSection: "AIP_SPEC.md §4.2",
    isTamperCritical: false,
  },
  CANONICAL_HASH: {
    index: 3,
    identifier: "CANONICAL_HASH",
    name: "Deterministic Canonical Hash",
    summary: "Recomputed SHA-256 over deterministic canonical serialization matches packet_hash",
    layer: "INTEGRITY",
    layerName: "Layer 1: Cryptographic Integrity & Identity",
    specSection: "AIP_SPEC.md §4.3",
    isTamperCritical: true,
  },
  AGENT_SIGNATURE: {
    index: 4,
    identifier: "AGENT_SIGNATURE",
    name: "Agent Signature Verification",
    summary: "Ed25519 digital signature of the agent covers the recomputed canonical bytes",
    layer: "INTEGRITY",
    layerName: "Layer 1: Cryptographic Integrity & Identity",
    specSection: "AIP_SPEC.md §4.4",
    isTamperCritical: true,
  },
  ROOT_TOKEN_SIGNATURE: {
    index: 5,
    identifier: "ROOT_TOKEN_SIGNATURE",
    name: "Root Principal Token Signature",
    summary: "Ed25519 signature on root token verified against verifier-trusted principal key",
    layer: "AUTHORITY",
    layerName: "Layer 2: Organizational Authority & Attenuation",
    specSection: "AIP_SPEC.md §4.5",
    isTamperCritical: true,
  },
  DELEGATION_CHAIN: {
    index: 6,
    identifier: "DELEGATION_CHAIN",
    name: "Delegation Chain Attenuation",
    summary: "N-hop delegation linkage, depth monotonicity (< 8), and lattice scope subset (⊆)",
    layer: "AUTHORITY",
    layerName: "Layer 2: Organizational Authority & Attenuation",
    specSection: "AIP_SPEC.md §4.6",
    isTamperCritical: true,
  },
  AUTHORITY_CHAIN: {
    index: 7,
    identifier: "AUTHORITY_CHAIN",
    name: "Authority Chain Connectivity",
    summary: "Unbroken path from root principal through delegation hops to acting agent",
    layer: "AUTHORITY",
    layerName: "Layer 2: Organizational Authority & Attenuation",
    specSection: "AIP_SPEC.md §4.7",
    isTamperCritical: false,
  },
  SCOPE_AUTHORITY: {
    index: 8,
    identifier: "SCOPE_AUTHORITY",
    name: "Effective Scope Permission",
    summary: "Authorizing decision and all action kinds fall strictly within effective lattice scope",
    layer: "AUTHORITY",
    layerName: "Layer 2: Organizational Authority & Attenuation",
    specSection: "AIP_SPEC.md §4.8",
    isTamperCritical: false,
  },
  REVOCATION: {
    index: 9,
    identifier: "REVOCATION",
    name: "Revocation Registry Clearance",
    summary: "Zero JTIs in root token or delegation hops match verifier's revocation set",
    layer: "VALIDITY",
    layerName: "Layer 3: Temporal Validity & Action Attestations",
    specSection: "AIP_SPEC.md §4.9",
    isTamperCritical: false,
  },
  TEMPORAL_VALIDITY: {
    index: 10,
    identifier: "TEMPORAL_VALIDITY",
    name: "Temporal Window Validity",
    summary: "Decision within token issuance/expiry windows; actions strictly chronological",
    layer: "VALIDITY",
    layerName: "Layer 3: Temporal Validity & Action Attestations",
    specSection: "AIP_SPEC.md §4.10",
    isTamperCritical: false,
  },
  ACTION_ATTESTATIONS: {
    index: 11,
    identifier: "ACTION_ATTESTATIONS",
    name: "Action Attestation Signatures",
    summary: "Every individual action is signed by agent and cryptographically bound to decision_id",
    layer: "VALIDITY",
    layerName: "Layer 3: Temporal Validity & Action Attestations",
    specSection: "AIP_SPEC.md §4.11",
    isTamperCritical: true,
  },
  TRACE_BINDING: {
    index: 12,
    identifier: "TRACE_BINDING",
    name: "Distributed Trace Binding",
    summary: "Optional W3C distributed trace ID and SHA-256 hash match supplied external trace",
    layer: "BILATERAL",
    layerName: "Layer 4: External Bindings & Trust Floor Proof",
    specSection: "AIP_SPEC.md §4.12",
    isTamperCritical: true,
  },
  RECEIPT_BINDING: {
    index: 13,
    identifier: "RECEIPT_BINDING",
    name: "External Receipt & Countersignature",
    summary: "External system receipt hash verified; counterparty Ed25519 signature validated",
    layer: "BILATERAL",
    layerName: "Layer 4: External Bindings & Trust Floor Proof",
    specSection: "AIP_SPEC.md §4.13",
    isTamperCritical: true,
  },
  TRUST_FLOOR: {
    index: 14,
    identifier: "TRUST_FLOOR",
    name: "Trust Floor Mathematical Proof",
    summary: "Derives supported trust floor; proves packet's claimed floor does not exceed evidence",
    layer: "BILATERAL",
    layerName: "Layer 4: External Bindings & Trust Floor Proof",
    specSection: "AIP_SPEC.md §4.14",
    isTamperCritical: false,
  },
};

export interface RuleResult {
  rule: RuleIdentifier | string;
  pass: boolean;
  detail: string;
}

export interface VerificationReport {
  overall_valid: boolean;
  valid?: boolean;
  trust_floor?: TrustFloor;
  derived_trust_floor: TrustFloor;
  claimed_trust_floor: TrustFloor;
  tamper_evidence: boolean;
  tampered?: boolean;
  authority_chain_verified?: boolean;
  delegation_chain_verified?: boolean;
  scope_verified?: boolean;
  receipt_verified?: boolean;
  trace_verified?: boolean;
  revocation_clear?: boolean;
  packet_id: string;
  agent_id: string;
  verified_at: number;
  checks: RuleResult[];
}

export interface VerificationContext {
  trusted_issuers?: Record<string, string>;
  issuer_public_keys?: Record<string, string>;
  trusted_counterparties?: Record<string, string>;
  counterparty_public_keys?: Record<string, string>;
  revoked_jtis?: string[];
  trace_data?: string | null;
  receipt_data?: string | null;
}
