/**
 * Normative Type Definitions for AIP Enterprise Accountability Console
 * Matches Rust aip-protocol, aip-types, and aip-wasm definitions.
 */

export type TrustFloor =
  | "UNVERIFIED"
  | "AGENT_SIGNED"
  | "AUTHORITY_BOUND"
  | "COUNTERPARTY_SIGNED";

export type VerificationRule =
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

export interface RuleResult {
  rule: VerificationRule;
  pass: boolean;
  detail: string;
}

export interface VerificationReport {
  overall_valid: boolean;
  claimed_trust_floor: TrustFloor;
  derived_trust_floor: TrustFloor;
  tamper_evidence: boolean;
  verified_at: number;
  checks: RuleResult[];
}

export interface VerificationContext {
  issuer_public_keys?: Record<string, string>;
  counterparty_public_keys?: Record<string, string>;
  revoked_jtis?: string[];
  trace_data?: string;
  receipt_data?: string;
}

export interface AgentIdentity {
  aip_id: string;
  algorithm: string;
  public_key: {
    key_bytes: string;
  };
  provenance: {
    model: string;
    environment: string;
    toolchain: string;
  };
}

export interface CapabilityScope {
  allowed: string[];
  denied: string[];
}

export interface ScopedToken {
  jti: string;
  issuer_id: string;
  agent_id: string;
  scope: CapabilityScope;
  issued_at: number;
  expires_at?: number | null;
  issuer_sig: {
    signer_id: string;
    payload_hash: string;
    sig_hex: string;
  };
}

export interface DelegationHop {
  jti: string;
  parent_jti: string;
  issuer_id: string;
  grantee_id: string;
  scope: CapabilityScope;
  depth: number;
  issued_at: number;
  expires_at?: number | null;
  issuer_sig: {
    signer_id: string;
    payload_hash: string;
    sig_hex: string;
  };
}

export interface DecisionRecord {
  decision_id: string;
  action_kind: string;
  summary: string;
  input_hash: string;
  rationale_hash: string;
  decided_at: number;
}

export interface ActionAttestation {
  action_id: string;
  action_kind: string;
  description: string;
  payload_hash: string;
  performed_at: number;
  agent_sig: {
    signer_id: string;
    payload_hash: string;
    sig_hex: string;
  };
}

export interface TraceBinding {
  trace_id: string;
  trace_system: string;
  trace_hash: string;
}

export interface ReceiptBinding {
  receipt_id: string;
  receipt_system: string;
  receipt_hash: string;
  counterparty_id?: string | null;
  counterparty_sig?: {
    signer_id: string;
    payload_hash: string;
    sig_hex: string;
  } | null;
}

export interface EvidencePacket {
  magic: number[];
  version: number;
  packet_hash: string;
  agent: AgentIdentity;
  root_authority: {
    principal_id: string;
    display_role: string;
    root_token: ScopedToken;
  };
  delegation_chain: DelegationHop[];
  decision: DecisionRecord;
  actions: ActionAttestation[];
  trace_binding?: TraceBinding | null;
  receipt_binding?: ReceiptBinding | null;
  claimed_trust_floor: TrustFloor;
  agent_sig: {
    signer_id: string;
    payload_hash: string;
    sig_hex: string;
  };
}

export type ConsoleTab =
  | "ingestion"
  | "graph"
  | "tamper"
  | "authority"
  | "vault";

export interface FixtureMetadata {
  id: string;
  title: string;
  description: string;
  filename: string;
  context_filename: string;
  category: "valid" | "unverified_authority" | "adversarial";
  claimed_trust_floor: TrustFloor;
  expected_derived_floor: TrustFloor;
  expected_valid: boolean;
  expected_tampered: boolean;
  expected_failed_rules: VerificationRule[];
}
