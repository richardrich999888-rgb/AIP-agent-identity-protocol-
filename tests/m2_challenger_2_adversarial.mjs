/**
 * Milestone 2 Challenger 2 Adversarial Stress Harness
 *
 * Focus areas:
 * 1. Zero JS crypto check (scanning all ts/tsx files in aip-console/src)
 * 2. Adversarial input testing:
 *    - Corrupted JSON (syntax errors, non-JSON text, empty files, missing fields)
 *    - Corrupted ZIP (0-byte, truncated, garbage, missing files, corrupted manifest)
 *    - Extension filtering and exception isolation
 * 3. Trust anchor re-verification reactivity:
 *    - Root key removal / substitution -> Rule 5 failure
 *    - Counterparty key removal / substitution -> Rule 13 failure
 *    - JTI revocation -> Rule 9 failure
 *    - Empty context -> non-crashing graceful degradation
 *    - Malformed context handling
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const CONSOLE_SRC = path.join(ROOT_DIR, "aip-console", "src");
const FIXTURES_DIR = path.join(ROOT_DIR, "aip-console", "public", "fixtures");
const WASM_JS_PATH = path.join(ROOT_DIR, "aip-console", "public", "wasm", "aip_wasm.js");
const WASM_BG_PATH = path.join(ROOT_DIR, "aip-console", "public", "wasm", "aip_wasm_bg.wasm");

console.log("================================================================================");
console.log("       AIP MILESTONE 2 CHALLENGER 2: ADVERSARIAL STRESS TEST HARNESS            ");
console.log("================================================================================\n");

let total = 0;
let passed = 0;
let failed = 0;

function assert(condition, testName, details = "") {
  total++;
  if (condition) {
    passed++;
    console.log(`[PASS] #${total}: ${testName}`);
  } else {
    failed++;
    console.error(`[FAIL] #${total}: ${testName} ${details ? `-> ${details}` : ""}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 1: Zero-JS Cryptographic Logic Audit
// ─────────────────────────────────────────────────────────────────────────────
console.log("─── VECTOR 1: Zero-JS Cryptographic Logic Audit ───");

function getAllTsFiles(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  for (const file of list) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      results = results.concat(getAllTsFiles(fullPath));
    } else if (file.endsWith(".ts") || file.endsWith(".tsx")) {
      results.push(fullPath);
    }
  }
  return results;
}

const allTsFiles = getAllTsFiles(CONSOLE_SRC);
assert(allTsFiles.length >= 15, `Found ${allTsFiles.length} TypeScript source files in aip-console/src`);

// Forbidden patterns indicating JS-side cryptographic verification or hashing
const forbiddenCryptoPatterns = [
  /\bcrypto\.subtle\b/,
  /\bwindow\.crypto\.subtle\b/,
  /\bcreateHash\s*\(/,
  /\bsha256\s*\(/,
  /\bed25519\.verify\b/,
  /\bnacl\.sign\b/,
  /\btweetnacl\b/,
  /\b@noble\/ed25519\b/,
  /\bjs-sha256\b/,
];

for (const file of allTsFiles) {
  const relPath = path.relative(CONSOLE_SRC, file);
  const content = fs.readFileSync(file, "utf8");
  for (const pattern of forbiddenCryptoPatterns) {
    const matches = pattern.test(content);
    assert(!matches, `Zero-JS crypto check in ${relPath}: no matches for pattern ${pattern}`);
  }
}

// Check VerificationLedger.tsx specifically: confirm it maps report.checks directly
const ledgerPath = path.join(CONSOLE_SRC, "components", "ingestion", "VerificationLedger.tsx");
const ledgerContent = fs.readFileSync(ledgerPath, "utf8");
assert(
  ledgerContent.includes("report.checks.map") || ledgerContent.includes("filteredChecks.map"),
  "VerificationLedger.tsx iterates directly over report checks"
);
assert(
  !ledgerContent.includes("verify_evidence_packet") && !ledgerContent.includes("verify_bundle_zip"),
  "VerificationLedger.tsx does not call verification functions directly (pure presenter)"
);

// Check TrustFloorBadge.tsx specifically: confirm it uses TRUST_FLOOR_ORDER numeric lookup
const badgePath = path.join(CONSOLE_SRC, "components", "ingestion", "TrustFloorBadge.tsx");
const badgeContent = fs.readFileSync(badgePath, "utf8");
assert(
  badgeContent.includes("TRUST_FLOOR_ORDER[derivedFloor]"),
  "TrustFloorBadge.tsx looks up derivedFloor level via TRUST_FLOOR_ORDER"
);

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 2: Adversarial Input & Corrupted File Edge Cases
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── VECTOR 2: Adversarial Input & Corrupted File Edge Cases ───");

// Load WASM module in Node
const wasmModule = await import(`file://${WASM_JS_PATH}`);
const wasmBytes = fs.readFileSync(WASM_BG_PATH);
await wasmModule.default({ module_or_path: wasmBytes });

const honestJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.json"), "utf8");
const honestCtx = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.context.json"), "utf8");
const validZip = fs.readFileSync(path.join(FIXTURES_DIR, "audit_bundle_valid.zip"));

// Baseline check: honest packet must verify
const baselineReport = JSON.parse(wasmModule.verify_evidence_packet(honestJson, honestCtx));
assert(baselineReport.overall_valid === true, "Baseline: honest_counterparty verifies valid (14 rules pass)");
assert(baselineReport.checks.length === 14, "Baseline: honest_counterparty produces exactly 14 checks");

// 2.1: Corrupted JSON Syntax
const corruptedJsonCases = [
  { name: "Unclosed curly brace", payload: '{"magic":[65,69,80,49],' },
  { name: "Truncated JSON", payload: honestJson.slice(0, 100) },
  { name: "Non-JSON plain text", payload: "This is definitely not JSON content." },
  { name: "HTML error page", payload: "<!DOCTYPE html><html><body>502 Bad Gateway</body></html>" },
  { name: "Empty string", payload: "" },
  { name: "Whitespace only", payload: "    \n\t  " },
  { name: "Null literal string", payload: "null" },
  { name: "Empty object {}", payload: "{}" },
  { name: "Number primitive", payload: "12345" },
  { name: "Boolean primitive", payload: "true" },
  { name: "JSON array instead of object", payload: "[]" },
];

for (const tc of corruptedJsonCases) {
  let threw = false;
  let errorMsg = "";
  try {
    wasmModule.verify_evidence_packet(tc.payload, null);
  } catch (err) {
    threw = true;
    errorMsg = err instanceof Error ? err.message : String(err);
  }
  assert(
    threw,
    `Corrupted JSON rejection (${tc.name}): throws error gracefully`,
    errorMsg
  );
  assert(
    errorMsg.includes("Invalid EvidencePacket JSON") || errorMsg.includes("missing field"),
    `Corrupted JSON rejection (${tc.name}): descriptive error message (${errorMsg.slice(0, 60)}...)`
  );
}

// 2.2: Partial / Missing Required Fields in JSON
const parsedHonest = JSON.parse(honestJson);

const missingFieldCases = [
  { name: "Missing magic header", mutate: (p) => { delete p.magic; } },
  { name: "Missing version", mutate: (p) => { delete p.version; } },
  { name: "Missing packet_hash", mutate: (p) => { delete p.packet_hash; } },
  { name: "Missing root_authority", mutate: (p) => { delete p.root_authority; } },
  { name: "Missing agent", mutate: (p) => { delete p.agent; } },
  { name: "Missing agent_sig", mutate: (p) => { delete p.agent_sig; } },
  { name: "Missing decision", mutate: (p) => { delete p.decision; } },
  { name: "Missing actions", mutate: (p) => { delete p.actions; } },
  { name: "Wrong magic bytes [0, 0, 0, 0]", mutate: (p) => { p.magic = [0, 0, 0, 0]; } },
];

for (const tc of missingFieldCases) {
  const cloned = JSON.parse(honestJson);
  tc.mutate(cloned);
  const mutatedJson = JSON.stringify(cloned);

  let threw = false;
  let caughtReport = null;
  let errorMsg = "";
  try {
    const raw = wasmModule.verify_evidence_packet(mutatedJson, honestCtx);
    caughtReport = JSON.parse(raw);
  } catch (err) {
    threw = true;
    errorMsg = err instanceof Error ? err.message : String(err);
  }

  // Either it throws an Invalid EvidencePacket JSON error, OR Rule 1 (STRUCTURE) fails
  if (threw) {
    assert(true, `Missing field (${tc.name}): throws parsing error gracefully`);
  } else if (caughtReport) {
    const r1 = caughtReport.checks.find((c) => c.rule === "STRUCTURE");
    assert(
      r1 && r1.pass === false,
      `Missing field (${tc.name}): Rule 1 (STRUCTURE) fails when schema parsed loosely`
    );
  }
}

// 2.3: Corrupted ZIP Bundles
const corruptedZipCases = [
  { name: "0-byte empty buffer", bytes: new Uint8Array(0) },
  { name: "Truncated 10-byte ZIP header", bytes: validZip.subarray(0, 10) },
  { name: "Random garbage bytes (256B)", bytes: new Uint8Array(256).map((_, i) => (i * 37) % 256) },
  { name: "Reversed valid ZIP bytes", bytes: new Uint8Array(validZip).reverse() },
  { name: "Corrupted central directory", bytes: (() => {
      const b = new Uint8Array(validZip);
      b[b.length - 20] ^= 0xff;
      b[b.length - 21] ^= 0xff;
      return b;
    })()
  },
];

for (const tc of corruptedZipCases) {
  let threw = false;
  let result = null;
  try {
    const raw = wasmModule.verify_bundle_zip(tc.bytes, null);
    result = JSON.parse(raw);
  } catch (err) {
    threw = true;
  }

  // verify_bundle_zip should NOT panic or crash: it either returns overall_pass: false with BUNDLE_READABLE fail, or throws
  if (!threw && result) {
    assert(
      result.overall_pass === false,
      `Corrupted ZIP (${tc.name}): handled cleanly with overall_pass = false`
    );
    assert(
      result.checks.some((c) => c.status === "fail" || !c.pass),
      `Corrupted ZIP (${tc.name}): contains failing check`
    );
  } else {
    assert(threw, `Corrupted ZIP (${tc.name}): threw handled exception without WASM panic`);
  }

  // extract_bundle_files on corrupted ZIP should throw a handled JS error without panic
  let extractThrew = false;
  try {
    wasmModule.extract_bundle_files(tc.bytes);
  } catch (err) {
    extractThrew = true;
  }
  assert(
    extractThrew,
    `extract_bundle_files on Corrupted ZIP (${tc.name}): rejects gracefully`
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 3: Verifier Trust Anchor Re-Verification Reactivity
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── VECTOR 3: Trust Anchor Re-Verification Reactivity ───");

// Parse baseline context
const baseCtxObj = JSON.parse(honestCtx);

// 3.1: Untrusted Root Key: Replace Alice CFO's key with an unknown key
const untrustedRootCtx = JSON.parse(JSON.stringify(baseCtxObj));
const aliceId = "aip12hrTEHHmno9YyKKK7TfzWJWqTHGifXEcrn2p29W9CY";
// Invert key bytes
untrustedRootCtx.trusted_issuers[aliceId] = "0000000000000000000000000000000000000000000000000000000000000000";
if (untrustedRootCtx.issuer_public_keys) {
  untrustedRootCtx.issuer_public_keys[aliceId] = "0000000000000000000000000000000000000000000000000000000000000000";
}

const untrustedRootReport = JSON.parse(
  wasmModule.verify_evidence_packet(honestJson, JSON.stringify(untrustedRootCtx))
);

assert(
  untrustedRootReport.overall_valid === false,
  "Untrusted Root: overall_valid is false"
);
const rule5 = untrustedRootReport.checks.find((c) => c.rule === "ROOT_TOKEN_SIGNATURE");
assert(
  rule5 && rule5.pass === false,
  `Untrusted Root: Rule 5 (ROOT_TOKEN_SIGNATURE) fails (detail: "${rule5?.detail}")`
);
assert(
  untrustedRootReport.derived_trust_floor === "AGENT_SIGNED",
  `Untrusted Root: derived trust floor downgraded to AGENT_SIGNED (found: ${untrustedRootReport.derived_trust_floor})`
);

// 3.2: Untrusted Counterparty: Replace bank counterparty key with an unknown key
const untrustedCounterpartyCtx = JSON.parse(JSON.stringify(baseCtxObj));
const cpId = "ledger.example-bank.com";
untrustedCounterpartyCtx.trusted_counterparties[cpId] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
if (untrustedCounterpartyCtx.counterparty_public_keys) {
  untrustedCounterpartyCtx.counterparty_public_keys[cpId] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
}

const untrustedCpReport = JSON.parse(
  wasmModule.verify_evidence_packet(honestJson, JSON.stringify(untrustedCounterpartyCtx))
);

assert(
  untrustedCpReport.overall_valid === false,
  "Untrusted Counterparty: overall_valid is false"
);
const rule13 = untrustedCpReport.checks.find((c) => c.rule === "RECEIPT_BINDING");
assert(
  rule13 && rule13.pass === false,
  `Untrusted Counterparty: Rule 13 (RECEIPT_BINDING) fails (detail: "${rule13?.detail}")`
);
assert(
  untrustedCpReport.derived_trust_floor === "AUTHORITY_BOUND",
  `Untrusted Counterparty: derived trust floor downgraded to AUTHORITY_BOUND (found: ${untrustedCpReport.derived_trust_floor})`
);

// 3.3: Injected Revoked JTI: Revoke the root token or delegation token
const revokedCtx = JSON.parse(JSON.stringify(baseCtxObj));
// Extract root token JTI from packet and convert byte array to hex
const rootJtiBytes = parsedHonest.root_authority.root_token.jti;
const rootJtiHex = Buffer.from(rootJtiBytes).toString("hex");
revokedCtx.revoked_jtis = [rootJtiHex];

const revokedReport = JSON.parse(
  wasmModule.verify_evidence_packet(honestJson, JSON.stringify(revokedCtx))
);

assert(
  revokedReport.overall_valid === false,
  "Revoked Token JTI: overall_valid is false"
);
const rule9 = revokedReport.checks.find((c) => c.rule === "REVOCATION");
assert(
  rule9 && rule9.pass === false,
  `Revoked Token JTI: Rule 9 (REVOCATION) fails (detail: "${rule9?.detail}")`
);

// 3.4: Re-verification Cycle: Toggle back to honest banking context
const restoredReport = JSON.parse(
  wasmModule.verify_evidence_packet(honestJson, honestCtx)
);
assert(
  restoredReport.overall_valid === true,
  "Re-verification cycle: restoring honest context restores 100% valid state"
);
assert(
  restoredReport.derived_trust_floor === "COUNTERPARTY_SIGNED",
  "Re-verification cycle: restored trust floor returns to COUNTERPARTY_SIGNED"
);

// 3.5: Empty Context Handling: Verify without any anchors
const emptyContextReport = JSON.parse(
  wasmModule.verify_evidence_packet(honestJson, "{}")
);
assert(
  emptyContextReport.overall_valid === false,
  "Empty context: overall_valid is false (untrusted anchors)"
);
assert(
  emptyContextReport.tamper_evidence === false,
  "Empty context: tamper_evidence is false (untampered packet, merely unanchored)"
);

// 3.6: Malformed Context JSON: Verify engine error handling
let malformedCtxThrew = false;
let malformedCtxError = "";
try {
  wasmModule.verify_evidence_packet(honestJson, "{ not a valid json context");
} catch (err) {
  malformedCtxThrew = true;
  malformedCtxError = err instanceof Error ? err.message : String(err);
}
assert(
  malformedCtxThrew,
  "Malformed context JSON throws handled error",
  malformedCtxError
);
assert(
  malformedCtxError.includes("Invalid VerificationContext JSON"),
  `Malformed context error mentions VerificationContext (${malformedCtxError})`
);

// ─────────────────────────────────────────────────────────────────────────────
// SUMMARY
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n================================================================================");
console.log(`TOTAL TESTS: ${total} | PASSED: ${passed} | FAILED: ${failed}`);
if (failed === 0) {
  console.log("CHALLENGER 2 VERDICT: APPROVE (Adversarial Stress Testing Passed 100%)");
} else {
  console.log("CHALLENGER 2 VERDICT: REJECT (Failures Detected)");
}
console.log("================================================================================\n");

if (failed > 0) {
  process.exit(1);
}
