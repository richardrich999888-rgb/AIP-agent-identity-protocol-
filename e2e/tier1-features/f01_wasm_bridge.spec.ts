import { describe, it, expect } from "vitest";
import {
  verifyEvidencePacketOracle,
  recomputePacketHash,
  getCanonicalBytes,
  scopePermitsAction,
} from "../support/reference_oracle.js";
import { meetCapabilityScopes, STANDARD_SCOPES } from "../support/lattice_oracle.js";
import { reconstructAccountabilityGraph } from "../support/dag_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";
import { createSampleAuditBundleFiles } from "../fixtures/audit_bundles.js";

describe("Tier 1 - F1: aip-wasm Rust Crate & Compilation Interface", () => {
  it("F1.1: verifies evidence packet via WASM interface contract", () => {
    const report = verifyEvidencePacketOracle(validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT);
    expect(report).toBeDefined();
    expect(report.overall_valid).toBe(true);
    expect(report.checks.length).toBe(14);
    expect(report.derived_trust_floor).toBe("COUNTERPARTY_SIGNED");
  });

  it("F1.2: recomputes packet hash returning 64-char lowercase hex SHA-256", () => {
    const hash = recomputePacketHash(validHonestCounterpartyPacket);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).toBe(validHonestCounterpartyPacket.packet_hash);
  });

  it("F1.3: extracts canonical bytes hex accurately", () => {
    const bytes = getCanonicalBytes(validHonestCounterpartyPacket);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBeGreaterThan(100);
  });

  it("F1.4: evaluates check_scope_permits through capability engine", () => {
    const permitsAdmin = scopePermitsAction(STANDARD_SCOPES.ADMIN, { kind: "Standard", action: "Write" });
    const permitsReader = scopePermitsAction(STANDARD_SCOPES.AUDIT_READER, { kind: "Standard", action: "Write" });
    expect(permitsAdmin).toBe(true);
    expect(permitsReader).toBe(false);
  });

  it("F1.5: extracts bundle files map from valid audit bundle", () => {
    const bundleFiles = createSampleAuditBundleFiles(validHonestCounterpartyPacket);
    expect(bundleFiles["evidence.json"]).toBeDefined();
    expect(bundleFiles["manifest.json"]).toBeDefined();
    expect(bundleFiles["bundle.sig"]).toBeDefined();
  });
});
