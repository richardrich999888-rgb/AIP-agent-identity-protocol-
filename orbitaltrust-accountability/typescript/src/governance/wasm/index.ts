/**
 * The WASM bridge: the Rust deterministic core (`ot-accountability-core`),
 * compiled to wasm32 and consumed here for byte-exact, high-speed chain
 * verification — with a Web Crypto fallback so the console degrades
 * gracefully when the module is absent or fails to initialize.
 *
 * # Loading
 *
 * The generated pkg (`src/wasm/pkg/`, produced by `npm run build:wasm`) is
 * discovered with `import.meta.glob`, so Vite bundles it when it exists and
 * resolves to nothing when it does not — the source tree typechecks and
 * builds either way, which is what lets CI build the console without a Rust
 * toolchain. On successful init the bridge also installs the core's SHA-256
 * into the telemetry crypto seam, so every seal the browser writes is
 * computed by the same Rust code the offline `ot-verifier` recomputes it
 * with.
 *
 * # Fallback
 *
 * The Web Crypto engine reimplements nothing novel: it reuses the same
 * canonical serializer the sealers use and mirrors the core's chain and
 * Merkle rules, so a fallback verdict differs from a WASM verdict only if
 * one of them is wrong — which the hybrid test suite exists to catch.
 */

import { canonicalJson, installSha256Provider, sha256Hex, type Jsonish } from "../../telemetry/crypto";

/** Chain verdict, camelCase — identical to the Rust `ChainVerdict`. */
export interface VerificationResult {
  valid: boolean;
  total: number;
  brokenSequence?: number;
  reason?: string;
}

export interface GovernanceVerifierEngine {
  /** Which implementation is actually running. */
  readonly engine: "wasm" | "webcrypto";
  verifyAnchorChain(anchors: unknown[]): Promise<VerificationResult>;
  verifyEvidencePackets(packets: unknown[]): Promise<VerificationResult>;
  /** SHA-256 over the canonical bytes of the record minus its chain fields. */
  computeCanonicalEvidenceHash(record: Record<string, unknown>): Promise<string>;
  /** Merkle root over an ordered set of hex leaf hashes. */
  merkleRoot(leaves: string[]): Promise<string>;
}

const GENESIS_HASH = "0".repeat(64);

/** The record's own chain-link fields, detected by tier. Order matters: a
 * packet carries an `anchorHash` too (its lifecycle *binding*, which is
 * payload, not a link), so the packet pair is checked first. Mirrors the
 * Rust core's detection exactly. */
function chainFieldsOf(record: Record<string, unknown>): [string, string] {
  if ("packetHash" in record) return ["previousPacketHash", "packetHash"];
  if ("anchorHash" in record) return ["previousAnchorHash", "anchorHash"];
  return ["previousHash", "chainHash"];
}

interface WasmExports {
  default: (input?: unknown) => Promise<unknown>;
  verify_anchor_chain_wasm(json: string): string;
  verify_evidence_packets_wasm(json: string): string;
  compute_canonical_evidence_hash_wasm(json: string): string;
  canonical_sha256_wasm(json: string): string;
  sha256_hex_wasm(text: string): string;
  merkle_root_wasm(json: string): string;
}

// Resolved at build time: {} when the pkg has not been generated.
const wasmModules = import.meta.glob("../../wasm/pkg/ot_accountability_core.js");

async function tryLoadWasm(): Promise<GovernanceVerifierEngine | null> {
  const loader = Object.values(wasmModules)[0];
  if (!loader) return null;
  try {
    const mod = (await loader()) as unknown as WasmExports;
    await mod.default();
    // Smoke-test before trusting it: an engine that cannot hash is not an
    // engine, whatever init claimed.
    if (mod.sha256_hex_wasm("") !== (await sha256Hex(""))) return null;
    // Route the telemetry stack's sealing digests through the core too.
    installSha256Provider((text) => mod.sha256_hex_wasm(text));
    return {
      engine: "wasm",
      verifyAnchorChain: async (anchors) =>
        JSON.parse(mod.verify_anchor_chain_wasm(JSON.stringify(anchors))),
      verifyEvidencePackets: async (packets) =>
        JSON.parse(mod.verify_evidence_packets_wasm(JSON.stringify(packets))),
      computeCanonicalEvidenceHash: async (record) =>
        mod.compute_canonical_evidence_hash_wasm(JSON.stringify(record)),
      merkleRoot: async (leaves) => mod.merkle_root_wasm(JSON.stringify(leaves)),
    };
  } catch {
    // Absent .wasm asset, CSP, non-browser runtime — the fallback covers it.
    return null;
  }
}

/** The Web Crypto fallback engine. */
function webCryptoEngine(): GovernanceVerifierEngine {
  const payloadBytes = (
    record: Record<string, unknown>,
    chainFields: [string, string],
  ): string => {
    const copy: Record<string, unknown> = { ...record };
    for (const field of chainFields) delete copy[field];
    return canonicalJson(copy as Jsonish);
  };

  const verifyChain = async (
    records: unknown[],
    prevField: string,
    hashField: string,
  ): Promise<VerificationResult> => {
    let expectedPrevious = GENESIS_HASH;
    for (let i = 0; i < records.length; i++) {
      const record = records[i] as Record<string, unknown>;
      const sequence = Number(record.sequenceNumber ?? 0);
      if (sequence !== i + 1) {
        return {
          valid: false,
          total: records.length,
          brokenSequence: sequence,
          reason: `sequence gap at index ${i}: expected ${i + 1}, found ${sequence}`,
        };
      }
      if (record[prevField] !== expectedPrevious) {
        return {
          valid: false,
          total: records.length,
          brokenSequence: sequence,
          reason: `${prevField} of sequence ${sequence} does not match the preceding record's hash`,
        };
      }
      const recorded = String(record[hashField] ?? "");
      const recomputed = await sha256Hex(
        expectedPrevious + payloadBytes(record, [prevField, hashField]),
      );
      if (recomputed !== recorded) {
        return {
          valid: false,
          total: records.length,
          brokenSequence: sequence,
          reason: `${hashField} mismatch at sequence ${sequence}: record modified after sealing`,
        };
      }
      expectedPrevious = recorded;
    }
    return { valid: true, total: records.length };
  };

  return {
    engine: "webcrypto",
    verifyAnchorChain: (anchors) => verifyChain(anchors, "previousAnchorHash", "anchorHash"),
    verifyEvidencePackets: (packets) =>
      verifyChain(packets, "previousPacketHash", "packetHash"),
    computeCanonicalEvidenceHash: (record) =>
      sha256Hex(payloadBytes(record, chainFieldsOf(record))),
    merkleRoot: async (leaves) => {
      if (leaves.length === 0) return GENESIS_HASH;
      let level = [...leaves];
      while (level.length > 1) {
        const next: string[] = [];
        for (let i = 0; i < level.length; i += 2) {
          next.push(
            i + 1 < level.length ? await sha256Hex(level[i] + level[i + 1]) : level[i],
          );
        }
        level = next;
      }
      return level[0];
    },
  };
}

let enginePromise: Promise<GovernanceVerifierEngine> | null = null;

/** The verification engine: WASM when the built pkg loads, Web Crypto
 * otherwise. Cached — the choice is made once per session. */
export function getVerifierEngine(): Promise<GovernanceVerifierEngine> {
  enginePromise ??= tryLoadWasm().then((wasm) => wasm ?? webCryptoEngine());
  return enginePromise;
}

/** Test seam: drops the cached engine so a suite can exercise both paths. */
export function resetVerifierEngineForTests(): void {
  enginePromise = null;
  installSha256Provider(null);
}
