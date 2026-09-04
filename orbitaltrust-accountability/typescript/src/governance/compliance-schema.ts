/**
 * Regulatory compliance mapping: NIST AI RMF 1.0, EU AI Act, ISO/IEC 42001.
 *
 * Every governed action the console seals is *already* the evidence these
 * frameworks ask for — a credentialed agent under a named human supervisor
 * (GOVERN / Article 14 / Clause 8.5), acting inside an explicit risk-managed
 * grant (MAP, MEASURE / Article 9 / Clause 6), with a tamper-evident record
 * (MANAGE / Article 12 / Clause 9). This module makes that correspondence
 * explicit and machine-readable: each evidence packet (or ledger entry, on
 * deployments without the AIP tier) maps to the controls its execution
 * satisfies, keyed by the packet's own sealed hash so the mapping cannot be
 * detached from the cryptographic record it describes.
 *
 * The mapping is deterministic — same packet, same controls — because a
 * compliance matrix that varies run to run is an opinion, not evidence.
 */

import type { AgentEmployeeProfile } from "../telemetry/agent-identity/agent-profile";
import type { AgentActionLog } from "../telemetry/agent-accountability/types";
import type { AipEvidencePacket } from "../telemetry/nexora/types";

export type NistAiRmfFunction = "GOVERN-1.2" | "MAP-1.5" | "MEASURE-2.4" | "MANAGE-2.4";

export type EuAiActArticle =
  | "Article 9 (Risk Management)"
  | "Article 12 (Record-Keeping)"
  | "Article 14 (Human Oversight)";

export type Iso42001Clause =
  | "Clause 6 (Risk Treatment)"
  | "Clause 8.5 (Human Oversight)"
  | "Clause 9 (Performance & Audit)";

export interface RegulatoryComplianceMapping {
  nistAiRmf: {
    functions: NistAiRmfFunction[];
    rationale: string;
  };
  euAiAct: {
    articles: EuAiActArticle[];
    conformityStatus: "CONFORMANT" | "GATED_BY_MULTISIG";
  };
  iso42001: {
    clauses: Iso42001Clause[];
  };
  /** SHA-256 of the sealed execution packet (or ledger entry) this mapping
   * describes — the cryptographic tether between claim and evidence. */
  auditProofHash: string;
}

/** One mapped action row in the aggregated matrix. */
export interface ComplianceMatrixRow extends RegulatoryComplianceMapping {
  sequenceNumber: number;
  toolName: string;
  executionStatus: string;
  timestampUtc: string;
}

/** The dossier's embedded compliance section. */
export interface ComplianceMatrix {
  standardsVersions: {
    nistAiRmf: "NIST AI 100-1 (AI RMF 1.0)";
    euAiAct: "Regulation (EU) 2024/1689";
    iso42001: "ISO/IEC 42001:2023";
  };
  /** Per-action control mappings, in sealed order. */
  controls: ComplianceMatrixRow[];
  /** Union of every control the record satisfies, for the summary badge. */
  aggregated: {
    nistAiRmfFunctions: NistAiRmfFunction[];
    euAiActArticles: EuAiActArticle[];
    iso42001Clauses: Iso42001Clause[];
  };
  /** The human-oversight facts the articles/clauses key off. */
  humanOversight: {
    supervisorDid: string;
    coSignedActions: number;
    blockedByPolicy: number;
    totalActions: number;
  };
  /** Every sealed hash the matrix references — the attestation digest set. */
  attestationDigests: string[];
}

/** Tool taxonomy for control selection. Screening/measuring verbs carry the
 * risk-measurement controls; maneuver planning carries risk-treatment and
 * the human-oversight gate (execution stays outside the grant entirely). */
const RISK_MEASUREMENT_TOOLS = new Set(["screen_conjunction_threats", "get_nearby_contacts"]);
const RISK_TREATMENT_TOOLS = new Set(["compute_avoidance_maneuver"]);

interface ActionFacts {
  sequenceNumber: number;
  toolName: string;
  executionStatus: string;
  timestampUtc: string;
  coSigned: boolean;
  blocked: boolean;
  auditProofHash: string;
}

function mapFacts(facts: ActionFacts, gatedTools: ReadonlySet<string>): ComplianceMatrixRow {
  const functions: NistAiRmfFunction[] = ["GOVERN-1.2", "MAP-1.5"];
  const articles: EuAiActArticle[] = ["Article 12 (Record-Keeping)"];
  const clauses: Iso42001Clause[] = ["Clause 9 (Performance & Audit)"];
  const rationale: string[] = [
    "executed under a signed credential with a named human supervisor, sealed into a hash-chained ledger",
  ];

  if (RISK_MEASUREMENT_TOOLS.has(facts.toolName)) {
    functions.push("MEASURE-2.4");
    articles.push("Article 9 (Risk Management)");
    clauses.push("Clause 6 (Risk Treatment)");
    rationale.push("performs risk measurement over the operational picture");
  }
  if (RISK_TREATMENT_TOOLS.has(facts.toolName)) {
    functions.push("MEASURE-2.4", "MANAGE-2.4");
    articles.push("Article 9 (Risk Management)", "Article 14 (Human Oversight)");
    clauses.push("Clause 6 (Risk Treatment)", "Clause 8.5 (Human Oversight)");
    rationale.push(
      "plans a risk treatment; execution is excluded from the agent's grant and reserved to human authority",
    );
  }
  if (facts.blocked) {
    functions.push("MANAGE-2.4");
    articles.push("Article 14 (Human Oversight)");
    clauses.push("Clause 8.5 (Human Oversight)");
    rationale.push("policy refusal enforced and sealed — the oversight mechanism demonstrably operates");
  }
  if (facts.coSigned || gatedTools.has(facts.toolName)) {
    if (!functions.includes("MANAGE-2.4")) functions.push("MANAGE-2.4");
    if (!articles.includes("Article 14 (Human Oversight)")) {
      articles.push("Article 14 (Human Oversight)");
    }
    if (!clauses.includes("Clause 8.5 (Human Oversight)")) {
      clauses.push("Clause 8.5 (Human Oversight)");
    }
    rationale.push("clearance-gated verb under per-invocation supervisor co-signature");
  }

  return {
    sequenceNumber: facts.sequenceNumber,
    toolName: facts.toolName,
    executionStatus: facts.executionStatus,
    timestampUtc: facts.timestampUtc,
    nistAiRmf: { functions: dedupe(functions), rationale: rationale.join("; ") },
    euAiAct: {
      articles: dedupe(articles),
      conformityStatus:
        facts.coSigned || gatedTools.has(facts.toolName) ? "GATED_BY_MULTISIG" : "CONFORMANT",
    },
    iso42001: { clauses: dedupe(clauses) },
    auditProofHash: facts.auditProofHash,
  };
}

function dedupe<T>(values: T[]): T[] {
  return [...new Set(values)];
}

/** Maps one sealed AIP evidence packet to the controls it satisfies. */
export function mapPacketToCompliance(
  packet: AipEvidencePacket,
  gatedTools: ReadonlySet<string>,
): ComplianceMatrixRow {
  return mapFacts(
    {
      sequenceNumber: packet.sequenceNumber,
      toolName: packet.toolExecuted.name,
      executionStatus: packet.toolExecuted.status,
      timestampUtc: packet.timestampUtc,
      coSigned: packet.toolExecuted.supervisorCoSignature !== undefined,
      blocked: packet.toolExecuted.status === "BLOCKED_BY_POLICY",
      auditProofHash: packet.packetHash,
    },
    gatedTools,
  );
}

/** Maps one action-ledger entry — the fallback on deployments without the
 * AIP tier, keyed by the entry's chainHash instead of a packet hash. */
export function mapLedgerEntryToCompliance(
  entry: AgentActionLog,
  gatedTools: ReadonlySet<string>,
): ComplianceMatrixRow {
  return mapFacts(
    {
      sequenceNumber: entry.sequenceNumber,
      toolName: entry.toolExecuted.name,
      executionStatus: entry.toolExecuted.executionStatus,
      timestampUtc: entry.timestampUtc,
      coSigned: entry.supervisorCoSignature !== undefined,
      blocked: entry.toolExecuted.executionStatus === "BLOCKED_BY_POLICY",
      auditProofHash: entry.chainHash,
    },
    gatedTools,
  );
}

export interface ComplianceMatrixInput {
  identity: AgentEmployeeProfile | Record<string, unknown> | null;
  evidencePackets: AipEvidencePacket[];
  actionLedger: AgentActionLog[];
}

/**
 * Aggregates the full matrix. Evidence packets are the preferred substrate
 * (they carry delegation paths and state hashes); the action ledger stands
 * in when the AIP tier is absent, so the matrix never silently shrinks to
 * nothing on an accountability-only deployment.
 */
export function buildComplianceMatrix(input: ComplianceMatrixInput): ComplianceMatrix {
  const identity = input.identity as Partial<AgentEmployeeProfile> | null;
  const gatedTools = new Set<string>(identity?.requiresDualKeyAuthorization ?? []);
  const supervisorDid = identity?.supervisorDid ?? "";

  const controls =
    input.evidencePackets.length > 0
      ? input.evidencePackets.map((p) => mapPacketToCompliance(p, gatedTools))
      : input.actionLedger.map((e) => mapLedgerEntryToCompliance(e, gatedTools));

  return {
    standardsVersions: {
      nistAiRmf: "NIST AI 100-1 (AI RMF 1.0)",
      euAiAct: "Regulation (EU) 2024/1689",
      iso42001: "ISO/IEC 42001:2023",
    },
    controls,
    aggregated: {
      nistAiRmfFunctions: dedupe(controls.flatMap((c) => c.nistAiRmf.functions)),
      euAiActArticles: dedupe(controls.flatMap((c) => c.euAiAct.articles)),
      iso42001Clauses: dedupe(controls.flatMap((c) => c.iso42001.clauses)),
    },
    humanOversight: {
      supervisorDid,
      coSignedActions: controls.filter((c) => c.euAiAct.conformityStatus === "GATED_BY_MULTISIG")
        .length,
      blockedByPolicy: controls.filter((c) => c.executionStatus === "BLOCKED_BY_POLICY").length,
      totalActions: controls.length,
    },
    attestationDigests: controls.map((c) => c.auditProofHash),
  };
}
