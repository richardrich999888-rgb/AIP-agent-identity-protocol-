/**
 * Milestone 1 Iteration 2 Challenger 1 - Comprehensive Adversarial Stress Test
 * Rigorously stress-tests all 10 exported WASM functions against hostile inputs,
 * fuzzing, boundary cases, memory stability, and verifies 100% resolution of the
 * get_sample_packet runtime panic.
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

console.log("================================================================================");
console.log("  M1 ITERATION 2 CHALLENGER 1: DEEP ADVERSARIAL & STRESS HARNESS");
console.log("================================================================================");
console.log(`Target WASM module: ${WASM_BG_PATH}`);

// Initialize WASM
const wasmModule = await import(`file://${WASM_JS_PATH}`);
const wasmBytes = fs.readFileSync(WASM_BG_PATH);
await wasmModule.default({ module_or_path: wasmBytes });
console.log("✓ WebAssembly instance initialized successfully.\n");

let total = 0;
let passed = 0;
let failed = 0;

function check(desc, fn) {
  total++;
  try {
    const res = fn();
    if (res === false) {
      failed++;
      console.error(`  [FAIL ${total}] ${desc}`);
    } else {
      passed++;
      console.log(`  [PASS ${total}] ${desc}`);
    }
  } catch (err) {
    failed++;
    console.error(`  [FAIL ${total}] ${desc} — Unexpected error: ${err.message || err}`);
  }
}

function expectThrow(desc, fn, expectedSnippet) {
  total++;
  try {
    fn();
    failed++;
    console.error(`  [FAIL ${total}] ${desc} — Expected error was NOT thrown!`);
  } catch (err) {
    const msg = String(err.message || err);
    if (expectedSnippet && !msg.toLowerCase().includes(expectedSnippet.toLowerCase())) {
      failed++;
      console.error(`  [FAIL ${total}] ${desc} — Threw error, but snippet "${expectedSnippet}" not found in: "${msg}"`);
    } else {
      passed++;
      console.log(`  [PASS ${total}] ${desc} (caught expected error: ${msg.slice(0, 70)}...)`);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 1: get_sample_packet Exhaustive Coverage & Panic Verification
// ─────────────────────────────────────────────────────────────────────────────
console.log(">>> VECTOR 1: get_sample_packet Robustness & Zero-Trap Invariant");

const sampleAliases = [
  // Honest counterparty aliases
  "honest_counterparty",
  "honest_counterparty.json",
  "valid_loan",
  "valid_countersigned",
  "valid",
  "",
  // Authority bound
  "authority_bound",
  "authority_bound.json",
  // Agent signed
  "agent_signed",
  "agent_signed.json",
  // Tampered summary
  "tampered_summary",
  "tampered_summary.json",
  "tampered_decision",
  "tampered",
  // Tampered hash
  "tampered_hash",
  "tampered_hash.json",
  "tampered_hash_recomputed",
  // Tampered signature
  "tampered_signature",
  "tampered_signature.json",
  // Scope escalation
  "scope_escalation",
  "scope_escalation.json",
  "attenuation_violation",
  // Revoked token
  "revoked_token",
  "revoked_token.json",
  "revoked_delegation",
  "revoked",
  // Contexts
  "sample_context",
  "valid_context",
  "context",
  "honest_counterparty.context",
  "honest_counterparty.context.json",
  "authority_bound.context",
  "authority_bound.context.json",
  "authority_context",
  "agent_signed.context",
  "agent_signed.context.json",
  "agent_context",
  "revoked_token.context",
  "revoked_token.context.json",
  "revoked_context",
  // Catalog
  "index",
  "index.json",
];

for (const alias of sampleAliases) {
  check(`get_sample_packet("${alias}") returns valid parseable JSON without WASM panic`, () => {
    const raw = wasmModule.get_sample_packet(alias);
    if (!raw || typeof raw !== "string" || raw.length === 0) return false;
    const parsed = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null;
  });
}

// Case insensitivity & trimming
check("get_sample_packet handles leading/trailing whitespace and mixed case", () => {
  const p1 = wasmModule.get_sample_packet("   HONEST_counterparty   ");
  const p2 = wasmModule.get_sample_packet("honest_counterparty");
  return p1 === p2;
});

// Hostile / invalid inputs to get_sample_packet
const hostileSamples = [
  "non_existent_packet",
  "../../../etc/passwd",
  "null",
  "undefined",
  "12345",
  "🦀 WebAssembly Panic Check 🦀",
  "x".repeat(5000),
  "__proto__",
  "constructor",
];

for (const hostile of hostileSamples) {
  const label = hostile.length > 20 ? hostile.slice(0, 20) + "..." : hostile;
  expectThrow(
    `get_sample_packet("${label}") cleanly rejects with JS Error instead of WASM panic`,
    () => wasmModule.get_sample_packet(hostile),
    "Unknown sample type"
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 2: verify_evidence_packet Hostile & Boundary Inputs
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n>>> VECTOR 2: verify_evidence_packet Adversarial Stress");

const honestPacket = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.json"), "utf8");
const honestCtx = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.context.json"), "utf8");

expectThrow("verify_evidence_packet rejects empty string", () => wasmModule.verify_evidence_packet("", null), "EOF");
expectThrow("verify_evidence_packet rejects whitespace string", () => wasmModule.verify_evidence_packet("   ", null), "EOF");
expectThrow("verify_evidence_packet rejects non-JSON garbage", () => wasmModule.verify_evidence_packet("INVALID_DATA", null), "Invalid EvidencePacket JSON");
expectThrow("verify_evidence_packet rejects JSON array", () => wasmModule.verify_evidence_packet("[]", null), "Invalid EvidencePacket JSON");
expectThrow("verify_evidence_packet rejects empty JSON object", () => wasmModule.verify_evidence_packet("{}", null), "missing field");

// Huge payload stress test (1MB payload injected into decision summary)
{
  const packetObj = JSON.parse(honestPacket);
  packetObj.decision.summary = "A".repeat(1024 * 1024); // 1 MiB string
  const hugeJson = JSON.stringify(packetObj);

  check("verify_evidence_packet survives 1MB payload without memory abort", () => {
    const reportJson = wasmModule.verify_evidence_packet(hugeJson, honestCtx);
    const report = JSON.parse(reportJson);
    return report.overall_valid === false && report.tamper_evidence === true;
  });
}

// Unicode and emoji injection
{
  const packetObj = JSON.parse(honestPacket);
  packetObj.decision.summary = "Syntriass 🛡️ 🔐 \u0000\u0007 \u4e16\u754c \u0627\u0644\u0639\u0631\u0628\u064a\u0629";
  const unicodeJson = JSON.stringify(packetObj);

  check("verify_evidence_packet correctly detects hash mismatch on UTF-8 multibyte characters", () => {
    const reportJson = wasmModule.verify_evidence_packet(unicodeJson, honestCtx);
    const report = JSON.parse(reportJson);
    return report.overall_valid === false && report.tamper_evidence === true;
  });
}

// Context boundary fuzzing
expectThrow("verify_evidence_packet rejects invalid context JSON", () => {
  wasmModule.verify_evidence_packet(honestPacket, "{not: valid, json}");
}, "Invalid VerificationContext JSON");

expectThrow("verify_evidence_packet rejects odd-length hex JTI in context", () => {
  wasmModule.verify_evidence_packet(honestPacket, JSON.stringify({ revoked_jtis: ["abc"] }));
}, "Invalid revoked JTI hex");

expectThrow("verify_evidence_packet rejects 30-char hex JTI (must be 32 hex chars / 16 bytes)", () => {
  wasmModule.verify_evidence_packet(honestPacket, JSON.stringify({ revoked_jtis: ["00".repeat(15)] }));
}, "Revoked JTI must be exactly 16 bytes");

check("verify_evidence_packet accepts valid 32-char hex JTI in valid context", () => {
  const ctxObj = JSON.parse(honestCtx);
  ctxObj.revoked_jtis = ["aa".repeat(16)];
  const rep = JSON.parse(wasmModule.verify_evidence_packet(honestPacket, JSON.stringify(ctxObj)));
  return rep.overall_valid === true && rep.derived_trust_floor === "COUNTERPARTY_SIGNED";
});

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 3: verify_bundle_zip & extract_bundle_files Security
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n>>> VECTOR 3: verify_bundle_zip & extract_bundle_files Security");

const validZip = fs.readFileSync(path.join(FIXTURES_DIR, "audit_bundle_valid.zip"));
const tamperedZip = fs.readFileSync(path.join(FIXTURES_DIR, "audit_bundle_tampered.zip"));

expectThrow("extract_bundle_files throws on 0 bytes", () => wasmModule.extract_bundle_files(new Uint8Array(0)), "Failed to read ZIP archive");
expectThrow("extract_bundle_files throws on 4-byte PK header with no directory", () => wasmModule.extract_bundle_files(new Uint8Array([0x50, 0x4b, 0x03, 0x04])), "Could not find EOCD");

check("verify_bundle_zip handles corrupt bytes gracefully with overall FAIL report", () => {
  const rep = JSON.parse(wasmModule.verify_bundle_zip(new Uint8Array([1, 2, 3, 4, 5]), null));
  return rep.overall === "FAIL" && rep.overall_pass === false && rep.checks.length > 0;
});

// Fuzzing extract_bundle_files with random bytes
check("extract_bundle_files safely rejects 50 random byte arrays without WASM memory trap", () => {
  for (let i = 0; i < 50; i++) {
    const randomBytes = crypto.randomBytes(Math.floor(Math.random() * 256) + 1);
    try {
      wasmModule.extract_bundle_files(randomBytes);
      return false; // Should not succeed as valid ZIP
    } catch (e) {
      // Must throw clean error, not uncatchable trap
      if (!String(e).includes("Failed to read ZIP archive")) return false;
    }
  }
  return true;
});

check("extract_bundle_files successfully parses valid ZIP and returns exactly 7 bundle files", () => {
  const map = JSON.parse(wasmModule.extract_bundle_files(validZip));
  const expectedFiles = [
    "evidence.json",
    "manifest.json",
    "verification_report.json",
    "verification_report.md",
    "authority_graph.json",
    "authority_graph.dot",
    "bundle_signature.sig",
  ];
  for (const f of expectedFiles) {
    if (!map[f] || typeof map[f] !== "string" || map[f].length === 0) return false;
  }
  return Object.keys(map).length === 7;
});

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 4: get_accountability_graph Edge Cases
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n>>> VECTOR 4: get_accountability_graph Verification & DAG Schema");

check("get_accountability_graph works with undefined report_json", () => {
  const g = JSON.parse(wasmModule.get_accountability_graph(honestPacket, undefined));
  return g.nodes.length === 7 && g.edges.length === 6 && g.claimed_trust_floor === "COUNTERPARTY_SIGNED" && g.derived_trust_floor === null;
});

check("get_accountability_graph works with null report_json", () => {
  const g = JSON.parse(wasmModule.get_accountability_graph(honestPacket, null));
  return g.nodes.length === 7 && g.edges.length === 6;
});

check("get_accountability_graph works with invalid report_json without crashing", () => {
  const g = JSON.parse(wasmModule.get_accountability_graph(honestPacket, "not-valid-json"));
  return g.nodes.length === 7 && g.edges.length === 6;
});

check("get_accountability_graph provides complete React Flow dual-edge compatibility", () => {
  const g = JSON.parse(wasmModule.get_accountability_graph(honestPacket, null));
  for (const edge of g.edges) {
    if (!edge.source || !edge.target || !edge.from || !edge.to || !edge.relation) return false;
    if (edge.source !== edge.from || edge.target !== edge.to) return false;
  }
  return true;
});

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 5: recompute_packet_hash & get_canonical_bytes_hex Invariants
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n>>> VECTOR 5: recompute_packet_hash & get_canonical_bytes_hex Bit-Exactness");

check("recompute_packet_hash is idempotent and deterministic across 500 iterations", () => {
  const firstHash = wasmModule.recompute_packet_hash(honestPacket);
  for (let i = 0; i < 500; i++) {
    if (wasmModule.recompute_packet_hash(honestPacket) !== firstHash) return false;
  }
  return true;
});

check("get_canonical_bytes_hex produces valid even-length hex string", () => {
  const hex = wasmModule.get_canonical_bytes_hex(honestPacket);
  if (hex.length % 2 !== 0) return false;
  return /^[0-9a-f]+$/.test(hex);
});

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 6: check_scope_permits & meet_capability_scopes Lattice Algebra
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n>>> VECTOR 6: Capability Lattice Algebraic Law Invariants");

// Idempotence: A ⊓ A == A
{
  const scopeA = JSON.stringify({ allowed: ["Read", "Write"], denied: ["Admin"] });
  check("Lattice Idempotence: scope A ⊓ scope A preserves allowed actions and !is_bottom", () => {
    const met = JSON.parse(wasmModule.meet_capability_scopes(scopeA, scopeA));
    const allowedNames = met.allowed.map((a) => (typeof a === "string" ? a : a.Standard || a.Custom));
    return allowedNames.includes("Read") && allowedNames.includes("Write") && !met.is_bottom;
  });
}

// Bottom generation: Disjoint sets
{
  const scopeRead = JSON.stringify({ allowed: ["Read"], denied: [] });
  const scopeWrite = JSON.stringify({ allowed: ["Write"], denied: [] });
  check("Lattice Disjoint Meet generates bottom ⊥ with is_bottom: true", () => {
    const met = JSON.parse(wasmModule.meet_capability_scopes(scopeRead, scopeWrite));
    return met.is_bottom === true && met.allowed.length === 0;
  });
}

// Scope permits loose format handling
check("check_scope_permits handles quoted string action JSON", () => {
  const scope = JSON.stringify({ allowed: ["Admin"], denied: [] });
  return wasmModule.check_scope_permits(scope, '"Admin"') === true;
});

check("check_scope_permits handles unquoted action JSON", () => {
  const scope = JSON.stringify({ allowed: ["Admin"], denied: [] });
  return wasmModule.check_scope_permits(scope, "Admin") === true;
});

check("check_scope_permits prioritizes explicit denial over allowance", () => {
  const scope = JSON.stringify({ allowed: ["Admin", "Write"], denied: ["Admin"] });
  return wasmModule.check_scope_permits(scope, '"Admin"') === false;
});

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 7: generate_keypair Determinism & Entropy
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n>>> VECTOR 7: generate_keypair Cryptographic Generation");

check("generate_keypair generates 25 distinct keypairs with valid AIP-IDs", () => {
  const seenIds = new Set();
  const seenPubkeys = new Set();

  for (let i = 0; i < 25; i++) {
    const kp = JSON.parse(wasmModule.generate_keypair());
    if (!kp.aip_id.startsWith("aip1")) return false;
    if (kp.public_key_hex.length !== 64) return false;
    if (kp.private_key_hex.length !== 64) return false;
    if (kp.algorithm !== "Ed25519") return false;
    if (seenIds.has(kp.aip_id)) return false;
    if (seenPubkeys.has(kp.public_key_hex)) return false;
    seenIds.add(kp.aip_id);
    seenPubkeys.add(kp.public_key_hex);
  }
  return true;
});

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n================================================================================");
console.log(`STRESS TEST COMPLETE: ${passed} PASSED, ${failed} FAILED, ${total} TOTAL`);
console.log("================================================================================");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
