import { sha256Hex } from "../support/reference_oracle.js";
import { EvidencePacket, VerificationReport } from "../support/types.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "./evidence_packets.js";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import { reconstructAccountabilityGraph, toDot } from "../support/dag_oracle.js";

export interface AuditBundleFiles {
  "evidence.json": string;
  "verification.json": string;
  "audit_report.md": string;
  "accountability_graph.json": string;
  "accountability_graph.dot": string;
  "manifest.json": string;
  "bundle.sig": string;
}

/**
 * Creates canonical 7-file audit bundle map conforming to AUDIT_EXPORT_SPEC.md
 */
export function createSampleAuditBundleFiles(
  packet: EvidencePacket = validHonestCounterpartyPacket,
  report?: VerificationReport
): AuditBundleFiles {
  const rep = report || verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
  const graph = reconstructAccountabilityGraph(packet, rep);
  const dot = toDot(graph);

  const evidenceJson = JSON.stringify(packet, null, 2);
  const verificationJson = JSON.stringify(rep, null, 2);
  const auditReportMd = [
    "# AIP Enterprise Audit Report",
    `Decision: ${packet.decision.summary}`,
    `Overall Valid: ${rep.overall_valid}`,
    `Trust Floor: ${rep.derived_trust_floor}`,
    `Rules Evaluated: ${rep.checks.length}`,
  ].join("\n");
  const graphJson = JSON.stringify(graph, null, 2);

  const manifest = {
    bundle_version: "aip-bundle-1",
    created_at: Date.now(),
    files: {
      "evidence.json": sha256Hex(evidenceJson),
      "verification.json": sha256Hex(verificationJson),
      "audit_report.md": sha256Hex(auditReportMd),
      "accountability_graph.json": sha256Hex(graphJson),
      "accountability_graph.dot": sha256Hex(dot),
    },
  };

  const manifestJson = JSON.stringify(manifest, null, 2);
  const bundleSig = JSON.stringify({
    signer_id: "auditor-cert-authority-01",
    algorithm: "Ed25519",
    signature_bytes: "556677889900aabbccddeeff11223344556677889900aabbccddeeff55667788",
    payload_hash: sha256Hex(manifestJson),
  });

  return {
    "evidence.json": evidenceJson,
    "verification.json": verificationJson,
    "audit_report.md": auditReportMd,
    "accountability_graph.json": graphJson,
    "accountability_graph.dot": dot,
    "manifest.json": manifestJson,
    "bundle.sig": bundleSig,
  };
}
