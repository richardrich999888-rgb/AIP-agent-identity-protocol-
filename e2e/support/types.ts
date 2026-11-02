/**
 * AIP Normative Wire Types and Verification Contracts
 * Conforms to AIP_SPEC.md, AUDIT_EXPORT_SPEC.md, and PROJECT.md
 */

export type TrustFloor = "UNVERIFIED" | "AGENT_SIGNED" | "AUTHORITY_BOUND" | "COUNTERPARTY_SIGNED";

export type RuleName =
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
  rule: RuleName;
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

export interface StandardAction {
  kind: "Standard";
  action: "Read" | "Write" | "Delete" | "Admin" | "Execute" | "Delegate";
}

export interface CustomAction {
  kind: "Custom";
  name: string;
}

export type ActionVerb = StandardAction | CustomAction;

export interface CapabilityScope {
  allowed: ActionVerb[];
  denied: ActionVerb[];
  depth_remaining?: number;
}

export interface CryptographicSignature {
  signer_id: string;
  algorithm: string;
  signature_bytes: string; // hex
  payload_hash: string;    // hex
  signed_at: number;
}

export interface ProvenanceCommitment {
  model_hash: string;
  environment_hash: string;
  toolchain_hash: string;
}

export interface AgentIdentity {
  aip_id: string;
  public_key: {
    algorithm: string;
    key_bytes: string; // hex
  };
  provenance: ProvenanceCommitment;
}

export interface ScopedToken {
  jti: string; // 16-byte hex
  issuer_id: string;
  agent_id: string;
  scope: CapabilityScope;
  issued_at: number;
  expires_at?: number;
  issuer_sig: CryptographicSignature;
}

export interface RootAuthority {
  principal_id: string;
  display_role: string;
  root_token: ScopedToken;
}

export interface DelegationToken {
  jti: string; // 16-byte hex
  parent_jti: string;
  issuer_id: string;
  grantee_id: string;
  depth: number;
  scope: CapabilityScope;
  issued_at: number;
  expires_at?: number;
  issuer_sig: CryptographicSignature;
}

export interface DecisionRecord {
  decision_id: string;
  action_kind: ActionVerb;
  summary: string;
  input_hash: string;
  rationale_hash: string;
  decided_at: number;
}

export interface ActionAttestation {
  action_id: string;
  action_kind: ActionVerb;
  description: string;
  payload_hash: string;
  performed_at: number;
  agent_sig: CryptographicSignature;
}

export interface TraceBinding {
  trace_id: string;
  trace_hash: string; // SHA-256 hex
}

export interface ReceiptBinding {
  receipt_system: string;
  receipt_id: string;
  receipt_hash: string; // SHA-256 hex
  counterparty_id?: string;
  counterparty_sig?: CryptographicSignature;
}

export interface EvidencePacket {
  magic: number[]; // [0x41, 0x45, 0x50, 0x31]
  version: number; // 1
  packet_hash: string; // SHA-256 hex of canonical bytes
  agent_sig: CryptographicSignature;
  claimed_trust_floor: TrustFloor;
  agent: AgentIdentity;
  root_authority: RootAuthority;
  delegation_chain: DelegationToken[];
  decision: DecisionRecord;
  actions: ActionAttestation[];
  trace_binding?: TraceBinding;
  receipt_binding?: ReceiptBinding;
}

export interface VerificationContext {
  issuer_public_keys: Record<string, string>; // issuer_id -> hex pubkey
  counterparty_public_keys?: Record<string, string>; // counterparty_id -> hex pubkey
  revoked_jtis: string[]; // list of hex JTIs
  trace_data?: string;    // raw trace bytes / text
  receipt_data?: string;  // raw receipt bytes / text
  now?: number;           // verification timestamp for testing
}

export interface GraphNode {
  id: string;
  kind: "principal" | "authority_grant" | "delegation" | "agent" | "decision" | "action" | "receipt";
  label: string;
  verified: boolean;
  data: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: "Issues" | "Delegates" | "ActsUnder" | "Decides" | "Performs" | "Produces";
}

export interface AccountabilityGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  claimed_trust_floor: TrustFloor;
  derived_trust_floor: TrustFloor;
}

export interface BundleVerificationCheck {
  name: string;
  pass: boolean;
  detail: string;
}

export interface BundleVerificationResult {
  overall: "PASS" | "WARNING" | "FAIL";
  checks: BundleVerificationCheck[];
}

export interface EvidenceSummary {
  id: string;
  tenant_id: string;
  agent_id: string;
  principal_id: string;
  decision_summary: string;
  trust_floor: TrustFloor;
  created_at: number;
}

export interface EvidenceFilter {
  tenant_id?: string;
  trust_floor?: TrustFloor;
  query?: string;
  limit?: number;
  offset?: number;
}

export interface IEvidenceVaultClient {
  isLive(): boolean;
  listEvidence(filter?: EvidenceFilter): Promise<EvidenceSummary[]>;
  getEvidence(id: string): Promise<EvidencePacket>;
  verifyEvidence(packet: EvidencePacket, context?: VerificationContext): Promise<VerificationReport>;
  getAuthorityGraph(id: string): Promise<AccountabilityGraph>;
  exportBundle(id: string): Promise<Uint8Array>;
}
