/**
 * Normative Type Definitions for AIP Enterprise Accountability Console
 * Matches Rust aip-protocol, aip-types, and aip-wasm definitions.
 */

export * from "@/types/verification";

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
  claimed_trust_floor: import("@/types/verification").TrustFloor;
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
  claimed_trust_floor: import("@/types/verification").TrustFloor;
  expected_derived_floor: import("@/types/verification").TrustFloor;
  expected_valid: boolean;
  expected_tampered: boolean;
  expected_failed_rules: import("@/types/verification").RuleIdentifier[];
}
