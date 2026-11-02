/**
 * Milestone 1 WASM Empirical Challenger & Stress Harness
 * Directly loads compiled WebAssembly package from aip-console/public/wasm/
 * and challenges the 10 exported WASM functions against fixtures and boundary attacks.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const WASM_JS_PATH = path.join(ROOT_DIR, "aip-console", "public", "wasm", "aip_wasm.js");
const WASM_BG_PATH = path.join(ROOT_DIR, "aip-console", "public", "wasm", "aip_wasm_bg.wasm");
const FIXTURES_DIR = path.join(ROOT_DIR, "aip-console", "public", "fixtures");

console.log("=== AIP-WASM EMPIRICAL CHALLENGER ===");
console.log(`Loading WASM: ${WASM_BG_PATH}`);

// 1. Initialize WASM module
const wasmModule = await import(`file://${WASM_JS_PATH}`);
const wasmBytes = fs.readFileSync(WASM_BG_PATH);
await wasmModule.default({ module_or_path: wasmBytes });
console.log("✓ WebAssembly module successfully initialized");

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  totalTests++;
  if (!condition) {
    failedTests++;
    console.error(`  FAIL [${totalTests}]: ${message}`);
  } else {
    passedTests++;
    console.log(`  PASS [${totalTests}]: ${message}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Vector 1: Cryptographic Canonical Hashing & SHA-256 Bit-Exactness
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Vector 1] Cryptographic Canonical Hashing & SHA-256 Equivalence");

const samplePackets = [
  "honest_counterparty.json",
  "authority_bound.json",
  "agent_signed.json",
  "tampered_summary.json",
  "tampered_hash.json",
  "tampered_signature.json",
  "scope_escalation.json",
  "revoked_token.json",
];

for (const pName of samplePackets) {
  const pPath = path.join(FIXTURES_DIR, pName);
  const pJson = fs.readFileSync(pPath, "utf8");

  // Call WASM get_canonical_bytes_hex
  const canonHex = wasmModule.get_canonical_bytes_hex(pJson);
  assert(typeof canonHex === "string" && canonHex.length > 0, `${pName}: canonHex returned non-empty string`);

  // Decode hex and hash with Node.js crypto.createHash('sha256')
  const canonBuffer = Buffer.from(canonHex, "hex");
  const nodeSha256 = crypto.createHash("sha256").update(canonBuffer).digest("hex");

  // Call WASM recompute_packet_hash
  const wasmRecomputed = wasmModule.recompute_packet_hash(pJson);

  assert(
    wasmRecomputed === nodeSha256,
    `${pName}: wasmRecomputed (${wasmRecomputed}) strictly matches Node SHA-256 of canonical bytes (${nodeSha256})`
  );
  assert(wasmRecomputed.length === 64, `${pName}: hash length is 64 hex characters`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Vector 2: Full 10-Fixture Verification Pipeline Verification
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Vector 2] Verification Pipeline Against Pre-Compiled Fixtures");

// 2.1 Honest Counterparty
{
  const packetJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.json"), "utf8");
  const ctxJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.context.json"), "utf8");
  const report = JSON.parse(wasmModule.verify_evidence_packet(packetJson, ctxJson));

  assert(report.overall_valid === true, "honest_counterparty: overall_valid is true");
  assert(report.valid === true, "honest_counterparty: valid is true");
  assert(report.derived_trust_floor === "COUNTERPARTY_SIGNED", "honest_counterparty: derived COUNTERPARTY_SIGNED");
  assert(report.tamper_evidence === false, "honest_counterparty: tamper_evidence is false");
  assert(report.tampered === false, "honest_counterparty: tampered is false");
  assert(report.checks.length === 14, "honest_counterparty: evaluated exactly 14 rules");
  assert(report.checks.every((c) => c.pass === true), "honest_counterparty: all 14 rules pass");
}

// 2.2 Authority Bound
{
  const packetJson = fs.readFileSync(path.join(FIXTURES_DIR, "authority_bound.json"), "utf8");
  const ctxJson = fs.readFileSync(path.join(FIXTURES_DIR, "authority_bound.context.json"), "utf8");
  const report = JSON.parse(wasmModule.verify_evidence_packet(packetJson, ctxJson));

  assert(report.overall_valid === true, "authority_bound: overall_valid is true");
  assert(report.derived_trust_floor === "AUTHORITY_BOUND", "authority_bound: derived AUTHORITY_BOUND");
  assert(report.tamper_evidence === false, "authority_bound: tamper_evidence is false");
}

// 2.3 Agent Signed (unverified authority)
{
  const packetJson = fs.readFileSync(path.join(FIXTURES_DIR, "agent_signed.json"), "utf8");
  const ctxJson = fs.readFileSync(path.join(FIXTURES_DIR, "agent_signed.context.json"), "utf8");
  const report = JSON.parse(wasmModule.verify_evidence_packet(packetJson, ctxJson));

  assert(report.overall_valid === false, "agent_signed: overall_valid is false");
  assert(report.derived_trust_floor === "AGENT_SIGNED", "agent_signed: derived AGENT_SIGNED");
  assert(report.tamper_evidence === false, "agent_signed: tamper_evidence is false (anchor gap, not tamper)");
  const rootCheck = report.checks.find((c) => c.rule === "ROOT_TOKEN_SIGNATURE");
  assert(rootCheck.pass === false, "agent_signed: ROOT_TOKEN_SIGNATURE rule failed");
}

// 2.4 Tampered Summary
{
  const packetJson = fs.readFileSync(path.join(FIXTURES_DIR, "tampered_summary.json"), "utf8");
  const ctxJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.context.json"), "utf8");
  const report = JSON.parse(wasmModule.verify_evidence_packet(packetJson, ctxJson));

  assert(report.overall_valid === false, "tampered_summary: overall_valid is false");
  assert(report.tamper_evidence === true, "tampered_summary: tamper_evidence is true");
  const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
  assert(hashCheck.pass === false, "tampered_summary: CANONICAL_HASH failed");
}

// 2.5 Tampered Hash (Payload modified + hash recalculated)
{
  const packetJson = fs.readFileSync(path.join(FIXTURES_DIR, "tampered_hash.json"), "utf8");
  const ctxJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.context.json"), "utf8");
  const report = JSON.parse(wasmModule.verify_evidence_packet(packetJson, ctxJson));

  assert(report.overall_valid === false, "tampered_hash: overall_valid is false");
  assert(report.tamper_evidence === true, "tampered_hash: tamper_evidence is true");
  const hashCheck = report.checks.find((c) => c.rule === "CANONICAL_HASH");
  assert(hashCheck.pass === true, "tampered_hash: CANONICAL_HASH passes due to recalculated hash");
  const sigCheck = report.checks.find((c) => c.rule === "AGENT_SIGNATURE");
  assert(sigCheck.pass === false, "tampered_hash: AGENT_SIGNATURE catches payload hash tampering");
}

// 2.6 Tampered Signature
{
  const packetJson = fs.readFileSync(path.join(FIXTURES_DIR, "tampered_signature.json"), "utf8");
  const ctxJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.context.json"), "utf8");
  const report = JSON.parse(wasmModule.verify_evidence_packet(packetJson, ctxJson));

  assert(report.overall_valid === false, "tampered_signature: overall_valid is false");
  assert(report.tamper_evidence === true, "tampered_signature: tamper_evidence is true");
  const sigCheck = report.checks.find((c) => c.rule === "AGENT_SIGNATURE");
  assert(sigCheck.pass === false, "tampered_signature: AGENT_SIGNATURE fails cryptographic check");
}

// 2.7 Scope Escalation
{
  const packetJson = fs.readFileSync(path.join(FIXTURES_DIR, "scope_escalation.json"), "utf8");
  const ctxJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.context.json"), "utf8");
  const report = JSON.parse(wasmModule.verify_evidence_packet(packetJson, ctxJson));

  assert(report.overall_valid === false, "scope_escalation: overall_valid is false");
  assert(report.tamper_evidence === true, "scope_escalation: tamper_evidence is true");
  const delCheck = report.checks.find((c) => c.rule === "DELEGATION_CHAIN");
  assert(delCheck.pass === false, "scope_escalation: DELEGATION_CHAIN fails on attenuation violation");
}

// 2.8 Revoked Token
{
  const packetJson = fs.readFileSync(path.join(FIXTURES_DIR, "revoked_token.json"), "utf8");
  const ctxJson = fs.readFileSync(path.join(FIXTURES_DIR, "revoked_token.context.json"), "utf8");
  const report = JSON.parse(wasmModule.verify_evidence_packet(packetJson, ctxJson));

  assert(report.overall_valid === false, "revoked_token: overall_valid is false");
  assert(
    report.tamper_evidence === false,
    "revoked_token: tamper_evidence is FALSE on administrative token revocation"
  );
  assert(report.tampered === false, "revoked_token: tampered is false");
  const revCheck = report.checks.find((c) => c.rule === "REVOCATION");
  assert(revCheck.pass === false, "revoked_token: REVOCATION check failed");
}

// 2.9 Valid ZIP Bundle
{
  const zipBytes = fs.readFileSync(path.join(FIXTURES_DIR, "audit_bundle_valid.zip"));
  const ctxJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.context.json"), "utf8");
  const res = JSON.parse(wasmModule.verify_bundle_zip(zipBytes, ctxJson));

  assert(res.overall === "PASS", "audit_bundle_valid.zip: overall is PASS");
  assert(res.overall_pass === true, "audit_bundle_valid.zip: overall_pass is true");
  assert(res.checks.length > 0, "audit_bundle_valid.zip: checks present");
  assert(res.checks.every((c) => c.pass === true), "audit_bundle_valid.zip: all checks pass");

  const files = JSON.parse(wasmModule.extract_bundle_files(zipBytes));
  assert(files["evidence.json"] !== undefined, "extract_bundle_files: contains evidence.json");
  assert(files["manifest.json"] !== undefined, "extract_bundle_files: contains manifest.json");
  assert(files["bundle_signature.sig"] !== undefined, "extract_bundle_files: contains bundle_signature.sig");
}

// 2.10 Tampered ZIP Bundle
{
  const zipBytes = fs.readFileSync(path.join(FIXTURES_DIR, "audit_bundle_tampered.zip"));
  const ctxJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.context.json"), "utf8");
  const res = JSON.parse(wasmModule.verify_bundle_zip(zipBytes, ctxJson));

  assert(res.overall === "FAIL", "audit_bundle_tampered.zip: overall is FAIL");
  assert(res.overall_pass === false, "audit_bundle_tampered.zip: overall_pass is false");
}

// ─────────────────────────────────────────────────────────────────────────────
// Vector 3: WASM Runtime Boundary & Hostile Corrupt Inputs
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Vector 3] WASM Runtime Boundary Attacks & Corrupt Inputs");

// 3.1 Empty input
try {
  wasmModule.verify_evidence_packet("", undefined);
  assert(false, "Empty string should have thrown JS Error");
} catch (e) {
  assert(String(e).includes("EOF while parsing a value"), "Empty packet string throws EOF error");
}

// 3.2 Corrupt JSON syntax
try {
  wasmModule.verify_evidence_packet("{not valid json", undefined);
  assert(false, "Syntax error should have thrown JS Error");
} catch (e) {
  assert(String(e).includes("Invalid EvidencePacket JSON"), "Malformed JSON throws syntax error");
}

// 3.3 Empty object missing required fields
try {
  wasmModule.verify_evidence_packet("{}", undefined);
  assert(false, "Empty object should have thrown JS Error");
} catch (e) {
  assert(String(e).includes("missing field"), "Empty object missing required fields throws error");
}

// 3.4 Optional context variations (undefined, empty string, empty json)
const validPacketJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.json"), "utf8");
{
  const rep1 = JSON.parse(wasmModule.verify_evidence_packet(validPacketJson, undefined));
  assert(rep1.derived_trust_floor === "AGENT_SIGNED", "undefined context defaults cleanly to empty context");

  const rep2 = JSON.parse(wasmModule.verify_evidence_packet(validPacketJson, ""));
  assert(rep2.derived_trust_floor === "AGENT_SIGNED", "empty string context defaults cleanly to empty context");

  const rep3 = JSON.parse(wasmModule.verify_evidence_packet(validPacketJson, "{}"));
  assert(rep3.derived_trust_floor === "AGENT_SIGNED", "empty JSON context defaults cleanly to empty context");
}

// 3.5 Malformed context JSON
try {
  wasmModule.verify_evidence_packet(validPacketJson, "invalid-context-json");
  assert(false, "Malformed context should throw error");
} catch (e) {
  assert(String(e).includes("Invalid VerificationContext JSON"), "Malformed context throws clean error");
}

// 3.6 Invalid revoked JTI (non-hex and wrong length)
try {
  wasmModule.verify_evidence_packet(validPacketJson, JSON.stringify({ revoked_jtis: ["not_hex_at_all!"] }));
  assert(false, "Invalid JTI hex should throw error");
} catch (e) {
  assert(String(e).includes("Invalid revoked JTI hex"), "Non-hex JTI throws error");
}

try {
  wasmModule.verify_evidence_packet(validPacketJson, JSON.stringify({ revoked_jtis: ["010203"] })); // 3 bytes instead of 16
  assert(false, "Short JTI length should throw error");
} catch (e) {
  assert(String(e).includes("Revoked JTI must be exactly 16 bytes"), "Short JTI length throws error");
}

// 3.7 Corrupt zip bytes to extract_bundle_files
try {
  wasmModule.extract_bundle_files(new Uint8Array([0x50, 0x4b, 0x00, 0x00]));
  assert(false, "Corrupt zip should throw error");
} catch (e) {
  assert(String(e).includes("Failed to read ZIP archive"), "Corrupt zip bytes cleanly rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// Vector 4: Capability Scopes, Keypair, and Graph API Invariants
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Vector 4] Capability Scopes, Keypair, and Graph Invariants");

// 4.1 Scope Permits
{
  const adminScope = JSON.stringify({ allowed: ["Read", "Write", "Delete", "Admin"], denied: [] });
  const readOnlyScope = JSON.stringify({ allowed: ["Read"], denied: ["Admin"] });

  assert(wasmModule.check_scope_permits(adminScope, '"Write"') === true, "Admin permits Write");
  assert(wasmModule.check_scope_permits(adminScope, '"Admin"') === true, "Admin permits Admin");
  assert(wasmModule.check_scope_permits(readOnlyScope, '"Read"') === true, "ReadOnly permits Read");
  assert(wasmModule.check_scope_permits(readOnlyScope, '"Write"') === false, "ReadOnly denies Write");
  assert(wasmModule.check_scope_permits(readOnlyScope, '"Admin"') === false, "ReadOnly denies Admin");
}

// 4.2 Lattice Meet operator
{
  const parent = JSON.stringify({ allowed: ["Read", "Write", "Execute"], denied: ["Admin"] });
  const child = JSON.stringify({ allowed: ["Write", "Execute"], denied: [] });
  const met = JSON.parse(wasmModule.meet_capability_scopes(parent, child));
  assert(met.is_bottom === false, "Compatible meet is_bottom is false");

  // Disjoint
  const pDisjoint = JSON.stringify({ allowed: ["Read"], denied: [] });
  const cDisjoint = JSON.stringify({ allowed: ["Write"], denied: [] });
  const metDisjoint = JSON.parse(wasmModule.meet_capability_scopes(pDisjoint, cDisjoint));
  assert(metDisjoint.is_bottom === true, "Disjoint meet is_bottom is true");
  assert(metDisjoint.allowed.length === 0, "Disjoint meet allowed is empty");
}

// 4.3 Keypair generation
{
  const kp = JSON.parse(wasmModule.generate_keypair());
  assert(kp.aip_id.startsWith("aip1"), "Generated AIP-ID starts with aip1");
  assert(kp.public_key_hex.length === 64, "Public key hex is 64 chars");
  assert(kp.private_key_hex.length === 64, "Private key hex is 64 chars");
  assert(kp.algorithm === "Ed25519", "Algorithm is Ed25519");
}

// 4.4 Accountability Graph
{
  const honestPacket = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.json"), "utf8");
  const honestCtx = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.context.json"), "utf8");
  const rep = wasmModule.verify_evidence_packet(honestPacket, honestCtx);
  const graph = JSON.parse(wasmModule.get_accountability_graph(honestPacket, rep));

  assert(graph.nodes.length >= 5, "Graph contains at least 5 nodes");
  assert(graph.edges.length >= 4, "Graph contains at least 4 edges");
  const firstEdge = graph.edges[0];
  assert(firstEdge.source !== undefined && firstEdge.target !== undefined, "Edge has source/target");
  assert(firstEdge.from !== undefined && firstEdge.to !== undefined, "Edge has from/to");
}

// 4.5 Sample packet provider
{
  try {
    const p1 = wasmModule.get_sample_packet("honest_counterparty");
    assert(p1.includes("packet_id"), "get_sample_packet honest_counterparty returned valid packet");
  } catch (e) {
    assert(false, `get_sample_packet("honest_counterparty") PANICKED in WASM runtime: ${e.message || e}`);
  }

  try {
    const p2 = wasmModule.get_sample_packet("revoked_token");
    assert(p2.includes("packet_id"), "get_sample_packet revoked_token returned valid packet");
  } catch (e) {
    assert(false, `get_sample_packet("revoked_token") PANICKED in WASM runtime: ${e.message || e}`);
  }

  try {
    wasmModule.get_sample_packet("unknown_random_type");
    assert(false, "Unknown sample type should throw error");
  } catch (e) {
    assert(String(e).includes("Unknown sample type") || String(e).includes("unreachable"), "Unknown sample type handled: " + e);
  }
}

console.log("\n=======================================================");
console.log(`ALL CHALLENGES COMPLETED: ${passedTests} passed, ${failedTests} failed, ${totalTests} total`);
console.log("=======================================================\n");

if (failedTests > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
