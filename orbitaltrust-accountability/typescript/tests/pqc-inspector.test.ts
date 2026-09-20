/**
 * The HNDL inspector's data layer, as executable claims:
 *
 * - audit records genuinely compute their evidence digest (recomputable);
 * - the latency figure always carries SPEC_TARGET provenance — the one
 *   number this console cannot measure must never wear a reading's badge;
 * - a funnel configured with a PQC context seals the stamp under the
 *   packet hash, so editing the stamp breaks the chain;
 * - certificate and CSV exports are verifiable and RFC-4180 clean;
 * - the hex comparison dump labels the adversary side SIM and carries the
 *   plaintext only as its hash.
 */

import { describe, expect, it } from "vitest";

import {
  buildHexComparisonDump,
  buildHndlCertificate,
  HNDL_PROTECTION_STATUS,
  KERNEL_LATENCY_TARGET_NS,
  pqcAudit,
  sealPqcAuditRecord,
  SYNTRIASS_CIPHER_SUITE,
  toPqcForensicCsv,
  verifyHndlCertificate,
} from "../src/telemetry/pqc-audit";
import { canonicalJson, sha256Hex } from "../src/telemetry/crypto";
import { MemoryIdentityStore } from "../src/telemetry/agent-identity/identity-store";
import {
  DelegationAuthority,
  toAgentDid,
  toOfficerDid,
} from "../src/telemetry/agent-identity/persistent-identity";
import { GovernedExecutionFunnel } from "../src/telemetry/agent-accountability/governed-execution";
import { EvidenceVerifier } from "../src/telemetry/agent-accountability/verifier";

const AGENT_DID = toAgentDid("AGT-PQC-01");
const RUNTIME = { modelDigest: "a1".repeat(32), systemPromptHash: "b2".repeat(32) };

async function pqcFunnelFixture(withContext: boolean) {
  const store = new MemoryIdentityStore();
  const authority = new DelegationAuthority("pqc-test-secret");
  await store.registerPersistentIdentity({
    did: AGENT_DID,
    agentId: "AGT-PQC-01",
    agentName: "PQC test agent",
    organization: "SYNTRIASS_LABS",
    publicKey: "cd".repeat(32),
    modelDigest: RUNTIME.modelDigest,
    systemPromptHash: RUNTIME.systemPromptHash,
    enclaveType: "SOFTWARE_SANDBOX",
    createdAtUtc: new Date().toISOString(),
    version: "1.0.0",
  });
  const now = Date.now();
  await store.issueAuthorityGrant(
    await authority.signGrant({
      grantId: crypto.randomUUID(),
      agentDid: AGENT_DID,
      delegatorDid: toOfficerDid("OFFICER-IAF-882"),
      delegationChain: [toOfficerDid("OFFICER-IAF-882")],
      clearanceLevel: "SECRET",
      grantedTools: ["fly_to_location"],
      requiresMultiSigTools: [],
      rateLimitMaxPerHour: 100,
      validFromUtc: new Date(now - 1000).toISOString(),
      expiresAtUtc: new Date(now + 3600_000).toISOString(),
      status: "ACTIVE",
    }),
  );
  const funnel = new GovernedExecutionFunnel({
    store,
    manifest: {
      fly_to_location: { requiredPermission: "NAVIGATE_CAMERA", minimumClearance: "UNCLASSIFIED" },
    },
    verifyGrant: (g) => authority.verifyGrant(g),
    verifyCoSignature: () => false,
    ...(withContext
      ? {
          pqcContext: {
            cipherSuite: SYNTRIASS_CIPHER_SUITE,
            hndlProtectionStatus: HNDL_PROTECTION_STATUS,
            kernelLatencyNs: KERNEL_LATENCY_TARGET_NS,
            latencyProvenance: "SPEC_TARGET",
          },
        }
      : {}),
  });
  return { store, funnel };
}

const FRAME = {
  suite: "X25519-MLKEM1024 / MLDSA87",
  aead: "ChaCha20-Poly1305",
  plaintext_bytes: 480,
  envelope_bytes: 2214,
  plaintext_sha256: "9f".repeat(32),
  roundtrip_verified: true,
  hndl_note: "hybrid: HNDL requires breaking both X25519 and ML-KEM-1024",
  envelope: { nonce_hex: "00".repeat(12), ciphertext_hex: "3c".repeat(512) },
};

describe("pqc audit records", () => {
  it("seals a recomputable digest with SPEC_TARGET latency provenance", async () => {
    const payload = { objects: 21, firstNorad: 25544 };
    const record = await sealPqcAuditRecord("satcom-catalogue", payload);
    expect(record.evidenceDigest).toBe(await sha256Hex(canonicalJson(payload)));
    expect(record.cipherSuite).toBe("FIPS 204 X25519-MLKEM1024 / MLDSA87");
    expect(record.hndlProtectionStatus).toBe("IMMUNE_TO_SHORS_ALGORITHM");
    expect(record.kernelLatencyNs).toBe(343);
    expect(record.latencyProvenance).toBe("SPEC_TARGET");
    expect(pqcAudit.records().some((r) => r.id === record.id)).toBe(true);
  });
});

describe("pqc stamp in the evidence chain", () => {
  const request = {
    agentDid: AGENT_DID,
    runtimeParameters: RUNTIME,
    rawPrompt: "pull the catalogue",
    toolName: "fly_to_location",
    inputParams: { objects: 21 },
    preState: { camera: [0, 0, 1] },
    execute: () => {},
  };

  it("stamps configured funnels, leaves unconfigured ones untouched, and chains both", async () => {
    const withCtx = await pqcFunnelFixture(true);
    const stamped = await withCtx.funnel.execute(request);
    expect(stamped.packet.pqcAuditRecord?.cipherSuite).toBe(SYNTRIASS_CIPHER_SUITE);
    expect(stamped.packet.pqcAuditRecord?.evidenceDigest).toBe(
      await sha256Hex(canonicalJson({ objects: 21 })),
    );
    await expect(
      new EvidenceVerifier(withCtx.store).verifyEvidenceChain(AGENT_DID),
    ).resolves.toEqual({ valid: true, totalPackets: 1 });

    const without = await pqcFunnelFixture(false);
    const plain = await without.funnel.execute(request);
    expect(plain.packet.pqcAuditRecord).toBeUndefined();
    await expect(
      new EvidenceVerifier(without.store).verifyEvidenceChain(AGENT_DID),
    ).resolves.toEqual({ valid: true, totalPackets: 1 });
  });

  it("an edited stamp breaks the chain at its exact sequence", async () => {
    const { store, funnel } = await pqcFunnelFixture(true);
    await funnel.execute(request);
    const packets = await store.listEvidenceForAgent(AGENT_DID);
    // Hostile upgrade: relabel the spec target as a measurement.
    packets[0].pqcAuditRecord!.latencyProvenance = "MEASURED";
    const verdict = await new EvidenceVerifier(store).verifyEvidenceChain(AGENT_DID);
    expect(verdict.valid).toBe(false);
    expect(verdict.brokenSequence).toBe(1);
  });
});

describe("hndl exports", () => {
  it("certificate root digest verifies and breaks on edit", async () => {
    const record = await sealPqcAuditRecord("conjunction-query", { primary: 1, secondary: 2 });
    const certificate = await buildHndlCertificate({
      securityPosture: { signer_suite: "ML-DSA-87" },
      receiptChain: { merkle_root_hex: "ab".repeat(32), verified: true },
      telemetryFrame: { plaintext_sha256: FRAME.plaintext_sha256 },
      agentDid: AGENT_DID,
      auditRecords: [record],
    });
    expect(certificate.nistSecurityCategory).toContain("Category 5");
    expect(certificate.kernelLatency.provenance).toBe("SPEC_TARGET");
    await expect(verifyHndlCertificate(certificate)).resolves.toBe(true);
    const forged = { ...certificate, agentDid: toAgentDid("SOMEONE-ELSE") };
    await expect(verifyHndlCertificate(forged)).resolves.toBe(false);
  });

  it("forensic csv carries the columns and survives hostile text", async () => {
    const record = await sealPqcAuditRecord('quoted "source", test', { n: 1 });
    const csv = toPqcForensicCsv([record]);
    const [header, row] = csv.trim().split("\r\n");
    for (const col of ["Timestamp_UTC", "Source", "Cipher_Suite", "HNDL_Status", "Kernel_Latency_Ns", "Latency_Provenance", "Evidence_Digest", "Payload_Bytes"]) {
      expect(header).toContain(`"${col}"`);
    }
    expect(row).toContain('""source""');
    expect(row).toContain('"SPEC_TARGET"');
  });

  it("hex dump labels the adversary side SIM and leaks plaintext only as its hash", () => {
    const dump = buildHexComparisonDump(FRAME);
    expect(dump).toContain("[SIM]");
    expect(dump).toContain("SIMULATED demonstration");
    expect(dump).toContain("intercepts no traffic");
    expect(dump).toContain(FRAME.plaintext_sha256);
    expect(dump).toContain("3c 3c 3c"); // real ciphertext bytes present
    expect(dump).toContain("round-trip decrypt-and-verify: VERIFIED");
  });
});
