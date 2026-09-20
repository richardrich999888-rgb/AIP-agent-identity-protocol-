/**
 * PQC audit telemetry: one sealed record per protected ingestion event
 * (SATCOM catalogue pull, conjunction query, ADS-B tick), the live data
 * behind the HNDL Defense inspector and its downloads.
 *
 * # Provenance discipline
 *
 * This console never lets a demo number wear a measurement's badge, and
 * this module is where that line is drawn for the PQC story:
 *
 * - The cipher suite and HNDL status describe the SYNTRIASS engine stack
 *   the console fronts (ot-pqc: hybrid X25519+ML-KEM-1024, ML-DSA-87) —
 *   live-confirmable against GET /security and /secure/telemetry.
 * - `kernelLatencyNs` is the SYNTRIASS eBPF socket-layer DESIGN TARGET.
 *   Nothing in this browser measures kernel interception latency, so the
 *   record carries `latencyProvenance: "SPEC_TARGET"` and every UI surface
 *   labels it as a target, not a reading. A deployment that benchmarks the
 *   real path swaps MEASURED in here.
 * - `evidenceDigest` is genuinely computed: SHA-256 over the canonical
 *   serialization of the event payload, so a record can be re-derived and
 *   checked offline.
 */

import { canonicalJson, sha256Hex, type Jsonish } from "./crypto";

/** Hybrid suite the SYNTRIASS kernel negotiates (FIPS 203 ML-KEM-1024 for
 * key establishment, FIPS 204 ML-DSA-87 for attestation). */
export const SYNTRIASS_CIPHER_SUITE = "FIPS 204 X25519-MLKEM1024 / MLDSA87";

/** Shor's algorithm breaks the RSA/ECC halves; the lattice halves stand.
 * Hybrid means harvest-now-decrypt-later requires breaking BOTH. */
export const HNDL_PROTECTION_STATUS = "IMMUNE_TO_SHORS_ALGORITHM";

/** eBPF socket-layer interception budget from the SYNTRIASS design spec —
 * a target, not a browser-side measurement. See the module note. */
export const KERNEL_LATENCY_TARGET_NS = 343;

export type LatencyProvenance = "SPEC_TARGET" | "MEASURED";

export interface PqcAuditRecord {
  /** UUID v4. */
  id: string;
  timestampUtc: string;
  /** What was protected: "satcom-catalogue", "conjunction-query", … */
  source: string;
  cipherSuite: string;
  hndlProtectionStatus: string;
  kernelLatencyNs: number;
  latencyProvenance: LatencyProvenance;
  /** SHA-256 over the canonical event payload — recomputable offline. */
  evidenceDigest: string;
  /** Size of the canonical payload the digest covers, bytes. */
  payloadBytes: number;
}

/** Bounded so a console left running for weeks holds a working set, not an
 * unbounded array; the full history lives in the evidence ledger, not here. */
const MAX_RECORDS = 256;

class PqcAuditLog {
  private readonly ring: PqcAuditRecord[] = [];
  private readonly listeners = new Set<() => void>();
  private version = 0;

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Changes on every seal — the useSyncExternalStore snapshot. */
  get snapshotVersion(): number {
    return this.version;
  }

  records(): PqcAuditRecord[] {
    return [...this.ring];
  }

  latest(): PqcAuditRecord | undefined {
    return this.ring[this.ring.length - 1];
  }

  async seal(source: string, payload: Jsonish): Promise<PqcAuditRecord> {
    const canonical = canonicalJson(payload);
    const record: PqcAuditRecord = {
      id: crypto.randomUUID(),
      timestampUtc: new Date().toISOString(),
      source,
      cipherSuite: SYNTRIASS_CIPHER_SUITE,
      hndlProtectionStatus: HNDL_PROTECTION_STATUS,
      kernelLatencyNs: KERNEL_LATENCY_TARGET_NS,
      latencyProvenance: "SPEC_TARGET",
      evidenceDigest: await sha256Hex(canonical),
      payloadBytes: new TextEncoder().encode(canonical).length,
    };
    this.ring.push(record);
    if (this.ring.length > MAX_RECORDS) this.ring.shift();
    this.version++;
    for (const l of this.listeners) l();
    return record;
  }
}

/** The console's shared audit log; the inspector modal subscribes to it. */
export const pqcAudit = new PqcAuditLog();

/** Seals one protected-ingestion event. Fire-and-forget from feed effects. */
export function sealPqcAuditRecord(
  source: string,
  payload: Jsonish,
): Promise<PqcAuditRecord> {
  return pqcAudit.seal(source, payload);
}

// ── Download builders (pure; the modal wires them to buttons) ────────────

/** RFC-4180 quoting, as everywhere else in this codebase. */
function csvCell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

/** Forensic summary of every protected event this session. */
export function toPqcForensicCsv(records: PqcAuditRecord[]): string {
  const header = [
    "Timestamp_UTC",
    "Source",
    "Cipher_Suite",
    "HNDL_Status",
    "Kernel_Latency_Ns",
    "Latency_Provenance",
    "Evidence_Digest",
    "Payload_Bytes",
  ];
  const rows = records.map((r) =>
    [
      r.timestampUtc,
      r.source,
      r.cipherSuite,
      r.hndlProtectionStatus,
      String(r.kernelLatencyNs),
      r.latencyProvenance,
      r.evidenceDigest,
      String(r.payloadBytes),
    ]
      .map(csvCell)
      .join(","),
  );
  return [header.map(csvCell).join(","), ...rows].join("\r\n") + "\r\n";
}

/** What the certificate binds. Live engine responses go in verbatim so the
 * certificate claims exactly what the engine attested, no more. */
export interface HndlCertificateInput {
  /** GET /security response (signer suite, offer, fingerprint). */
  securityPosture: Jsonish;
  /** GET /receipts summary (merkle root, verified). */
  receiptChain: Jsonish;
  /** GET /secure/telemetry frame minus the bulky envelope hex. */
  telemetryFrame: Jsonish;
  /** Active governed agent DID, when one is onboarded. */
  agentDid: string | null;
  auditRecords: PqcAuditRecord[];
}

export interface HndlComplianceCertificate {
  standard: "ASC-SENTINEL-HNDL-CERTIFICATE-v1";
  generatedAtUtc: string;
  /** ML-KEM-1024 / ML-DSA-87 sit in NIST security category 5. */
  nistSecurityCategory: "Category 5 (ML-KEM-1024 key establishment, ML-DSA-87 signatures)";
  cipherSuite: string;
  hndlProtectionStatus: string;
  kernelLatency: {
    targetNs: number;
    provenance: LatencyProvenance;
    note: string;
  };
  securityPosture: Jsonish;
  receiptChain: Jsonish;
  telemetryFrame: Jsonish;
  agentDid: string | null;
  auditRecords: PqcAuditRecord[];
  certification: {
    algorithm: "SHA-256 over canonical JSON (sorted keys)";
    rootDigest: string;
  };
}

/** Assembles and certifies the HNDL compliance dossier. Root digest covers
 * everything except the certification block — recomputable offline. */
export async function buildHndlCertificate(
  input: HndlCertificateInput,
): Promise<HndlComplianceCertificate> {
  const body = {
    standard: "ASC-SENTINEL-HNDL-CERTIFICATE-v1" as const,
    generatedAtUtc: new Date().toISOString(),
    nistSecurityCategory:
      "Category 5 (ML-KEM-1024 key establishment, ML-DSA-87 signatures)" as const,
    cipherSuite: SYNTRIASS_CIPHER_SUITE,
    hndlProtectionStatus: HNDL_PROTECTION_STATUS,
    kernelLatency: {
      targetNs: KERNEL_LATENCY_TARGET_NS,
      provenance: "SPEC_TARGET" as const,
      note: "eBPF socket-layer design target; not measured by this console",
    },
    securityPosture: input.securityPosture,
    receiptChain: input.receiptChain,
    telemetryFrame: input.telemetryFrame,
    agentDid: input.agentDid,
    auditRecords: input.auditRecords,
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

/** Recomputes a certificate's root digest — the verifier's half. */
export async function verifyHndlCertificate(
  certificate: HndlComplianceCertificate,
): Promise<boolean> {
  const { certification, ...body } = certificate;
  return (
    (await sha256Hex(canonicalJson(body as unknown as Jsonish))) ===
    certification.rootDigest
  );
}

/**
 * Hex-dump comparison for the download: the live engine envelope's
 * ciphertext beside the legacy exposure demonstration. The legacy bytes are
 * SIM — derived deterministically from the plaintext hash so the dump is
 * reproducible — because this console intercepts no adversary traffic and
 * says so in the artifact itself.
 */
export function buildHexComparisonDump(frame: {
  suite: string;
  aead: string;
  plaintext_bytes: number;
  envelope_bytes: number;
  plaintext_sha256: string;
  roundtrip_verified: boolean;
  hndl_note: string;
  envelope: { nonce_hex: string; ciphertext_hex: string };
}): string {
  const rows = (hex: string) => {
    const lines: string[] = [];
    for (let i = 0; i < hex.length && lines.length < 16; i += 32) {
      const chunk = hex.slice(i, i + 32);
      const bytes = chunk.match(/.{1,2}/g)?.join(" ") ?? "";
      lines.push(`${(i / 2).toString(16).padStart(8, "0")}  ${bytes}`);
    }
    return lines.join("\n");
  };
  // Deterministic SIM plaintext exposure: repeats the plaintext hash, which
  // is exactly the information an interceptor of an unprotected link would
  // be able to derive — labelled SIM, never presented as a capture.
  const simLegacyHex = frame.plaintext_sha256.repeat(8).slice(0, 512);
  return [
    "ASC SENTINEL — HNDL EXPOSURE COMPARISON DUMP",
    `generated ${new Date().toISOString()}`,
    "",
    "== LEGACY LINK EXPOSURE [SIM] — RSA-2048/ECC-256 key exchange ==",
    "An adversary recording this link holds recoverable plaintext once the",
    "classical key exchange falls to Shor's algorithm. Bytes below are a",
    "SIMULATED demonstration derived from the real frame's plaintext hash;",
    "this console intercepts no traffic.",
    rows(simLegacyHex),
    "",
    "== SYNTRIASS PROTECTED ENVELOPE [LIVE ENGINE FRAME] ==",
    `suite: ${frame.suite}`,
    `aead: ${frame.aead}`,
    `plaintext ${frame.plaintext_bytes} B -> envelope ${frame.envelope_bytes} B`,
    `nonce: ${frame.envelope.nonce_hex}`,
    rows(frame.envelope.ciphertext_hex),
    `… (${Math.max(0, frame.envelope.ciphertext_hex.length / 2 - 256)} further ciphertext bytes elided)`,
    "",
    "== ZERO-PLAINTEXT-LEAKAGE STATEMENT ==",
    "The envelope above contains no plaintext bytes; the plaintext appears",
    `only as its SHA-256 commitment: ${frame.plaintext_sha256}`,
    `engine round-trip decrypt-and-verify: ${frame.roundtrip_verified ? "VERIFIED" : "NOT VERIFIED"}`,
    `engine HNDL note: ${frame.hndl_note}`,
    "",
  ].join("\n");
}
