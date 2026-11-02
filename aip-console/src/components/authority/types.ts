/**
 * Authority Management & Capability Lattice Type Definitions
 * Target: aip-console/src/components/authority/types.ts
 */

export type StandardActionName =
  | "Read"
  | "Write"
  | "Delete"
  | "Admin"
  | "Execute"
  | "Delegate";

export type ActionVerb =
  | { kind: "Standard"; action: StandardActionName }
  | { kind: "Custom"; name: string };

export interface CapabilityScope {
  allowed: ActionVerb[];
  denied: ActionVerb[];
}

export type StandardScopePreset =
  | "ADMIN"
  | "ORCHESTRATOR"
  | "AUDITOR"
  | "WORKER"
  | "READ_ONLY";

export interface ScopePresetDefinition {
  name: string;
  roleId: StandardScopePreset;
  protocolScope: "ADMIN" | "ORCHESTRATOR" | "AUDIT_READER" | "SUBMITTER" | "CUSTOM";
  description: string;
  scope: CapabilityScope;
  constraints?: Record<string, string>;
  resource_patterns?: string[];
}

export interface MatrixScopeState {
  allowed: ActionVerb[];
  denied: ActionVerb[];
  constraints: Record<string, string>;
  resource_patterns: string[];
  depth_remaining?: number;
}

export interface LatticeMeetResult {
  scope: CapabilityScope | null;
  isBottom: boolean;
  allowed: ActionVerb[];
  denied: ActionVerb[];
  retainedByParent: ActionVerb[];
  attenuatedGrant: ActionVerb[];
  escalationAttempts: ActionVerb[];
  cumulativeDenials: ActionVerb[];
  isSubset: boolean;
}

export type TokenStatus = "VALID" | "EXPIRED" | "REVOKED" | "CASCADE_REVOKED";

export interface DelegationTreeNode {
  jti: string;
  parent_jti?: string;
  type: "root" | "intermediate" | "leaf";
  depth: number;
  issuer_id: string;
  grantee_id: string;
  role: string;
  scope?: CapabilityScope;
  issued_at: number;
  expires_at?: number | null;
  status: TokenStatus;
  revocationReason?: string;
  revoked_at?: number;
  revoked_by?: string;
  children?: DelegationTreeNode[];
}

export interface RevocationEntry {
  jti: string;
  revoked_at: number;
  reason: "Compromise" | "AdminRevocation" | "KeyRotation" | "Expired";
  cascade: boolean;
  revoked_by: string;
}

export interface RevocationImpact {
  totalRevoked: number;
  primaryRevocations: number;
  cascadedRevocations: number;
  affectedAgents: string[];
  brokenDelegations: number;
  maxCascadeDepth: number;
}
