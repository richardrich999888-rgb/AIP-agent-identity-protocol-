/**
 * Audit dossier export: one click to a .jsonl or .csv file for after-action
 * debriefs.
 *
 * JSONL is the machine format — one sealed entry per line, byte-faithful, so
 * a downstream verifier can re-run the chain math on the exported file. CSV
 * is the human format for the debrief table; nested structures are flattened
 * and the chain hashes are included so even the spreadsheet copy carries its
 * provenance.
 */

import { canonicalJson, sha256Hex, type Jsonish } from "../crypto";
import { officerDid } from "../agent-identity/agent-profile";
import type { AgentEmployeeProfile } from "../agent-identity/agent-profile";
import type { NexoraLifecycleAnchor } from "../nexora/types";
import type { AipEvidencePacket } from "../nexora/types";
import type { AgentActionLog, AuditVerification } from "./types";

export function toJsonl(entries: AgentActionLog[]): string {
  return entries.map((e) => JSON.stringify(e)).join("\n") + (entries.length ? "\n" : "");
}

const CSV_COLUMNS = [
  "sequenceNumber",
  "timestampUtc",
  "agentId",
  "agentDid",
  "modelDigest",
  "supervisorId",
  "supervisorCoSignature",
  "toolName",
  "executionStatus",
  "errorMessage",
  "interpretedIntent",
  "rawPrompt",
  "inputParams",
  "preCamera",
  "postCamera",
  "previousHash",
  "chainHash",
  "eventId",
] as const;

/** RFC-4180 quoting: always quote, double any embedded quote. Prompts are
 * free text — commas, quotes and newlines are the norm, not the edge case. */
function csvCell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

export function toCsv(entries: AgentActionLog[]): string {
  const rows = entries.map((e) =>
    [
      String(e.sequenceNumber),
      e.timestampUtc,
      e.agentId,
      e.agentDid,
      e.modelDigest,
      e.supervisorId,
      e.supervisorCoSignature ?? "",
      e.toolExecuted.name,
      e.toolExecuted.executionStatus,
      e.toolExecuted.errorMessage ?? "",
      e.interpretedIntent,
      e.rawPrompt,
      JSON.stringify(e.toolExecuted.inputParams),
      e.preExecutionState.cameraCoords.join(" "),
      e.postExecutionState?.cameraCoords.join(" ") ?? "",
      e.previousHash,
      e.chainHash,
      e.eventId,
    ]
      .map(csvCell)
      .join(","),
  );
  return [CSV_COLUMNS.map(csvCell).join(","), ...rows].join("\r\n") + "\r\n";
}

/**
 * RFC-4180 after-action tactical table, per-row integrity-verified.
 *
 * Column notes:
 * - Supervisor_DID derives from the entry's supervisorId — the ledger
 *   stores the plain operator id, the table speaks DID.
 * - Duration_MS is present for downstream tooling compatibility but always
 *   empty: the ledger records when an action was sealed, not how long its
 *   tool body ran, and inventing a number from inter-entry gaps would be a
 *   measurement of operator cadence, not execution time.
 * - Integrity_Valid is per-row honest: rows before the first broken link
 *   verified; the broken row and everything after it did not — one edit
 *   poisons the rest of the chain, and the table says so row by row.
 */
export function toAuditCsv(
  entries: AgentActionLog[],
  verification: AuditVerification,
): string {
  const columns = [
    "Sequence",
    "Timestamp_UTC",
    "Agent_DID",
    "Supervisor_DID",
    "Prompt",
    "Tool_Name",
    "Parameters",
    "Status",
    "Duration_MS",
    "Prev_Hash",
    "Packet_Hash",
    "Integrity_Valid",
  ];
  const brokenAt = verification.valid ? Infinity : verification.brokenAtSequence;
  const rows = entries.map((e) =>
    [
      String(e.sequenceNumber),
      e.timestampUtc,
      e.agentDid || e.agentId,
      officerDid(e.supervisorId),
      e.rawPrompt,
      e.toolExecuted.name,
      JSON.stringify(e.toolExecuted.inputParams),
      e.toolExecuted.executionStatus,
      "",
      e.previousHash,
      e.chainHash,
      String(e.sequenceNumber < brokenAt),
    ]
      .map(csvCell)
      .join(","),
  );
  return [columns.map(csvCell).join(","), ...rows].join("\r\n") + "\r\n";
}

/** The certified mission dossier: one self-verifying JSON archive. */
export interface MissionDossier {
  standard: "ASC-SENTINEL-MISSION-DOSSIER-v1";
  generatedAtUtc: string;
  agent: {
    /** The credential/persistent identity of the acting agent. */
    identity: AgentEmployeeProfile | Record<string, unknown> | null;
    /** The AGENT_GENESIS anchor, when a lifecycle chain exists. */
    genesisAttestation: NexoraLifecycleAnchor | null;
  };
  /** Full NEXORA lifecycle anchor trail (empty when the deployment does
   * not run the anchor tier — an empty trail is a fact, not an omission). */
  lifecycleAnchors: NexoraLifecycleAnchor[];
  /** Complete ordered AIP evidence packets, when the AIP tier is in use. */
  evidencePackets: AipEvidencePacket[];
  /** Complete ordered action ledger for the agent. */
  actionLedger: AgentActionLog[];
  /** The verification verdicts the dossier was certified against. */
  verification: {
    actionChain: AuditVerification;
  };
  certification: {
    algorithm: "SHA-256 over canonical JSON (sorted keys)";
    /** SHA-256 of the canonical serialization of everything above this
     * block. Recompute it to prove the dossier itself is unmodified. */
    rootDigest: string;
  };
}

export interface MissionDossierInput {
  identity: MissionDossier["agent"]["identity"];
  lifecycleAnchors?: NexoraLifecycleAnchor[];
  evidencePackets?: AipEvidencePacket[];
  actionLedger: AgentActionLog[];
  actionChainVerification: AuditVerification;
}

/**
 * Assembles and certifies the dossier. The root digest covers every field
 * except the certification block itself, so a verifier recomputes
 * `sha256(canonicalJson(dossier minus certification))` and compares.
 */
export async function buildMissionDossier(
  input: MissionDossierInput,
): Promise<MissionDossier> {
  const anchors = input.lifecycleAnchors ?? [];
  const body = {
    standard: "ASC-SENTINEL-MISSION-DOSSIER-v1" as const,
    generatedAtUtc: new Date().toISOString(),
    agent: {
      identity: input.identity,
      genesisAttestation:
        anchors.find((a) => a.anchorType === "AGENT_GENESIS") ?? null,
    },
    lifecycleAnchors: anchors,
    evidencePackets: input.evidencePackets ?? [],
    actionLedger: input.actionLedger,
    verification: {
      actionChain: input.actionChainVerification,
    },
  };
  const rootDigest = await sha256Hex(canonicalJson(body as unknown as Jsonish));
  return {
    ...body,
    certification: {
      algorithm: "SHA-256 over canonical JSON (sorted keys)",
      rootDigest,
    },
  };
}

/** Recomputes a dossier's root digest — the independent verifier's half of
 * the certification contract. */
export async function verifyMissionDossier(dossier: MissionDossier): Promise<boolean> {
  const { certification, ...body } = dossier;
  const recomputed = await sha256Hex(canonicalJson(body as unknown as Jsonish));
  return recomputed === certification.rootDigest;
}

export function toCertifiedDossierJson(dossier: MissionDossier): string {
  return JSON.stringify(dossier, null, 2) + "\n";
}

export type DossierFormat = "jsonl" | "csv";

/**
 * Triggers a browser download of the dossier. DOM-only by nature; callers
 * outside a document (tests) should use {@link toJsonl}/{@link toCsv}
 * directly.
 */
export function downloadAuditDossier(
  entries: AgentActionLog[],
  format: DossierFormat,
  filenameBase = "agent-audit-dossier",
): void {
  const body = format === "jsonl" ? toJsonl(entries) : toCsv(entries);
  const mime = format === "jsonl" ? "application/x-ndjson" : "text/csv";
  downloadTextFile(`${filenameBase}.${format}`, mime, body);
}

/** One browser-download path for every export format. DOM-only by nature;
 * headless callers use the to*() string builders directly. */
export function downloadTextFile(filename: string, mime: string, body: string): void {
  if (typeof document === "undefined") {
    throw new Error("downloadTextFile requires a DOM; use the string builders instead");
  }
  const url = URL.createObjectURL(new Blob([body], { type: `${mime};charset=utf-8` }));
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.rel = "noopener";
    a.click();
  } finally {
    // Give the click a tick to start the download before the URL dies.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
