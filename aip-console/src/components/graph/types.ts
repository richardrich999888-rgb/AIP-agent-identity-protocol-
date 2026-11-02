import type { Node, Edge } from "@xyflow/react";
import type {
  TrustFloor,
  RuleIdentifier,
  RuleResult,
  VerificationReport,
} from "@/types/verification";
import type {
  EvidencePacket,
  CapabilityScope,
  AgentIdentity,
  ScopedToken,
  DelegationHop,
  DecisionRecord,
  ActionAttestation,
  ReceiptBinding,
} from "@/lib/types";

export type LayoutDirection = "LR" | "TB";

export type AccountabilityNodeKind =
  | "principal"
  | "authority_grant"
  | "delegation"
  | "agent"
  | "decision"
  | "action"
  | "receipt";

export type AccountabilityRelation =
  | "Issues"
  | "Delegates"
  | "ActsUnder"
  | "Decides"
  | "Performs"
  | "Produces";

export type FlowNodeKind = AccountabilityNodeKind;
export type FlowRelation = AccountabilityRelation;

export interface AccountabilityNodeData extends Record<string, unknown> {
  id: string;
  kind: AccountabilityNodeKind;
  label: string;
  verified: boolean;
  layoutDirection: LayoutDirection;
  ruleName?: RuleIdentifier | string;
  ruleDetail?: string;
  error?: string;

  // Metadata bundle for inspection sheet and export
  metadata?: Record<string, unknown>;

  // Principal-specific
  principal_id?: string;
  display_role?: string;
  isTrustedAnchor?: boolean;
  algorithm?: string;

  // AuthorityGrant & Delegation specific
  jti?: string;
  parent_jti?: string;
  issuer_id?: string;
  grantee_id?: string;
  agent_id?: string;
  scope?: CapabilityScope;
  issued_at?: number;
  expires_at?: number | null;
  hop_index?: number;
  depth?: number;
  attenuationDelta?: number;
  isRevoked?: boolean;

  // Agent-specific
  aip_id?: string;
  public_key?: string;
  public_key_hex?: string;
  fingerprint?: string;
  provenance?: {
    model?: string;
    environment?: string;
    toolchain?: string;
    model_hash?: string;
  };

  // Decision-specific
  decision_id?: string;
  action_kind?: any;
  summary?: string;
  input_hash?: string;
  rationale_hash?: string;
  decided_at?: number;
  decided_at_iso?: string;

  // Action-specific
  action_id?: string;
  description?: string;
  payload_hash?: string;
  performed_at?: number;
  performed_at_iso?: string;
  index?: number;

  // Receipt-specific
  receipt_id?: string;
  receipt_system?: string;
  receipt_hash?: string;
  counterparty_id?: string | null;
  countersigned?: boolean;
  verified_status?: "COUNTERSIGNED" | "HASH_ONLY" | "UNVERIFIED";

  // Optional selection callback
  onSelectNode?: (nodeId: string) => void;
}

export type AccountabilityFlowNode = Node<AccountabilityNodeData, AccountabilityNodeKind>;

export interface AccountabilityEdgeData extends Record<string, unknown> {
  relation: AccountabilityRelation;
  verified: boolean;
  ruleName?: RuleIdentifier | string;
  sourceKind?: AccountabilityNodeKind;
  targetKind?: AccountabilityNodeKind;
}

export type AccountabilityFlowEdge = Edge<AccountabilityEdgeData, "accountability">;

export interface ReachabilityResult {
  valid: boolean;
  error?: string;
  rootPrincipalId?: string;
  reachableNodeIds: string[];
  orphanNodeIds: string[];
  totalNodes: number;
}

export interface FlowGraphResult {
  nodes: AccountabilityFlowNode[];
  edges: AccountabilityFlowEdge[];
  reachability: ReachabilityResult;
  claimedTrustFloor: TrustFloor;
  derivedTrustFloor: TrustFloor;
  packetId: string;
  dotString: string;
}

export interface TransformOptions {
  packet: EvidencePacket;
  report?: VerificationReport | null;
  direction?: LayoutDirection;
  onSelectNode?: (nodeId: string) => void;
  horizontalSpacing?: number;
  verticalSpacing?: number;
}
