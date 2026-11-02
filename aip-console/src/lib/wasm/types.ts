import type {
  TrustFloor,
  RuleIdentifier,
  RuleResult,
  VerificationReport,
  VerificationContext,
} from "@/types/verification";

export * from "@/types/verification";

export type BundleStatus = "VALID" | "TAMPERED" | "CORRUPTED" | "INVALID";

export interface BundleCheckResult {
  name: string;
  status: "PASS" | "FAIL";
  pass: boolean;
  detail: string;
}

export interface BundleVerificationResult {
  overall: BundleStatus;
  overall_pass: boolean;
  bundle_id: string;
  packet_id: string;
  signer_fingerprint: string;
  checks: BundleCheckResult[];
}

export type GraphNodeKind =
  | "Principal"
  | "AuthorityGrant"
  | "DelegationHop"
  | "Agent"
  | "Decision"
  | "ActionAttestation"
  | "CountersignedReceipt"
  | string;

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  [key: string]: unknown;
}

export interface GraphEdge {
  from: string;
  to: string;
  source: string;
  target: string;
  relation: string;
}

export interface AccountabilityGraph {
  packet_id: string;
  claimed_trust_floor: TrustFloor;
  derived_trust_floor: TrustFloor;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface KeypairResult {
  aip_id: string;
  public_key_hex: string;
  private_key_hex: string;
  public_key_base58: string;
  algorithm: string;
}

export type FixtureCategory =
  | "valid"
  | "unverified_authority"
  | "adversarial"
  | "revocation"
  | "bundle";

export interface FixtureItem {
  id: string;
  title: string;
  category: FixtureCategory;
  description: string;
  filename: string;
  context_filename?: string;
  format?: "json" | "zip";
  claimed_trust_floor?: TrustFloor;
  expected_derived_floor?: TrustFloor;
  expected_valid: boolean;
  expected_tampered?: boolean;
  expected_failed_rules?: RuleIdentifier[];
  expected_checks?: string[];
  expected_failed_checks?: string[];
}

export interface LoadedEvidence {
  fileName: string;
  fileType: "json" | "zip";
  packetJson: string;
  contextJson?: string;
  rawBytes?: Uint8Array;
  report?: VerificationReport;
  bundleResult?: BundleVerificationResult;
  graph?: AccountabilityGraph;
  extractedFiles?: Record<string, string>;
}

export interface AipVerifierContextValue {
  isReady: boolean;
  isLoading: boolean;
  error: string | null;
  verifyPacket: (packetJson: string, contextJson?: string) => VerificationReport;
  verifyBundleZip: (zipBytes: Uint8Array, contextJson?: string) => BundleVerificationResult;
  getAccountabilityGraph: (packetJson: string, reportJson?: string) => AccountabilityGraph;
  recomputeHash: (packetJson: string) => string;
  getCanonicalBytesHex: (packetJson: string) => string;
  checkScope: (scopeJson: string, actionJson: string) => boolean;
  meetScopes: (parentJson: string, childJson: string) => string;
  extractBundle: (zipBytes: Uint8Array) => Record<string, string>;
  getSample: (sampleType: string) => string;
  generateKeypair: () => KeypairResult;
  initVerifier: () => Promise<void>;
}
