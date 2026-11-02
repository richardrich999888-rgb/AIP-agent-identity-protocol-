/**
 * Milestone 4 Empirical Challenger & Adversarial Stress Harness
 * 
 * Verifies Requirements R3 & R4 (Features F11 - F16):
 * 1. Attack vector presets in attackPresets.ts vs live WASM engine.
 * 2. Smart Hash Recalculation Toggle proving cryptographic non-repudiation (CANONICAL_HASH: PASS, AGENT_SIGNATURE: FAIL, tamper_evidence: true).
 * 3. Scope Matrix boundary cases (explicit deny priority, empty allowed array, complex custom verbs, case sensitivity, Admin inheritance).
 * 4. Capability Lattice boundary cases (idempotence, identity element, disjoint bottom ⊥, associativity, commutativity).
 * 5. Cascade Revocation Tree boundary cases (leaf revocation, depth-4 chain, wide tree 10 children, WASM context sync triggering Rule 9 failure).
 * 6. Zero-JS verification static code analysis in tamper and authority components.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const CONSOLE_DIR = path.join(ROOT_DIR, "aip-console");
const FIXTURES_DIR = path.join(CONSOLE_DIR, "public", "fixtures");
const WASM_JS_PATH = path.join(CONSOLE_DIR, "public", "wasm", "aip_wasm.js");
const WASM_BG_PATH = path.join(CONSOLE_DIR, "public", "wasm", "aip_wasm_bg.wasm");

const TAMPER_DIR = path.join(CONSOLE_DIR, "src", "components", "tamper");
const AUTHORITY_DIR = path.join(CONSOLE_DIR, "src", "components", "authority");

console.log("================================================================================");
console.log("       AIP MILESTONE 4 EMPIRICAL CHALLENGER & ADVERSARIAL STRESS HARNESS        ");
console.log("================================================================================\n");

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
const findings = [];

function assert(condition, testName, details = "") {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`[PASS] #${totalTests}: ${testName}`);
  } else {
    failedTests++;
    console.error(`[FAIL] #${totalTests}: ${testName} ${details ? `-> ${details}` : ""}`);
    findings.push({ testName, details });
  }
}

// ─── INITIALIZATION ─────────────────────────────────────────────────────────
console.log("─── INITIALIZATION: WebAssembly Engine Loader ───");
assert(fs.existsSync(WASM_JS_PATH), "WASM JS wrapper exists: public/wasm/aip_wasm.js");
assert(fs.existsSync(WASM_BG_PATH), "WASM binary exists: public/wasm/aip_wasm_bg.wasm");

let wasm;
try {
  const wasmModule = await import(`file://${WASM_JS_PATH}`);
  const wasmBytes = fs.readFileSync(WASM_BG_PATH);
  await wasmModule.default({ module_or_path: wasmBytes });
  wasm = wasmModule;
  assert(true, "WebAssembly module instantiated successfully in Node.js");
} catch (err) {
  assert(false, `WebAssembly initialization failed: ${err.message}`);
  process.exit(1);
}

// Load baseline valid packet and context
const baselinePacketPath = path.join(FIXTURES_DIR, "honest_counterparty.json");
const baselineContextPath = path.join(FIXTURES_DIR, "honest_counterparty.context.json");
assert(fs.existsSync(baselinePacketPath), "honest_counterparty.json fixture exists");
assert(fs.existsSync(baselineContextPath), "honest_counterparty.context.json fixture exists");

const baselinePacketJson = fs.readFileSync(baselinePacketPath, "utf8");
const baselineContextJson = fs.readFileSync(baselineContextPath, "utf8");
const baselinePacket = JSON.parse(baselinePacketJson);

// Verify baseline is 100% valid in WASM
const baselineReportStr = wasm.verify_evidence_packet(baselinePacketJson, baselineContextJson);
const baselineReport = JSON.parse(baselineReportStr);
assert(baselineReport.valid === true, "Baseline packet verifies as overall valid (valid === true)");
assert(baselineReport.tampered === false, "Baseline packet has tamper_evidence === false");
assert(baselineReport.trust_floor === "COUNTERPARTY_SIGNED", "Baseline packet derived trust_floor is COUNTERPARTY_SIGNED");
assert(baselineReport.checks.length === 14, "Baseline packet evaluates all 14 checks");
assert(baselineReport.checks.every(c => c.pass), "All 14 baseline checks pass");


// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 1A: Evaluation of attackPresets.ts Direct Mutations
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── VECTOR 1A: Testing attackPresets.ts Mutations Directly in Live WASM ───");

const presetsFilePath = path.join(TAMPER_DIR, "attackPresets.ts");
assert(fs.existsSync(presetsFilePath), "attackPresets.ts source file exists");
const presetsSource = fs.readFileSync(presetsFilePath, "utf8");

// The 14 presets as written in attackPresets.ts
const attackPresetsAsWritten = [
  {
    id: "p01_structure",
    targetRule: "STRUCTURE",
    name: "Malformed Wire Format Header",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      p.magic = [0x42, 0x41, 0x44, 0x31];
      p.version = 99;
      return { packet: p, context };
    },
  },
  {
    id: "p02_agent_id",
    targetRule: "AGENT_ID_BINDING",
    name: "Agent Identity Hijacking",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      p.agent = { ...p.agent, aip_id: "aip1mismatchidentity99887766554433221122" };
      return { packet: p, context };
    },
  },
  {
    id: "p03_canonical_hash",
    targetRule: "CANONICAL_HASH",
    name: "Decision Summary Tampering",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      p.decision = { ...p.decision, summary: "TAMPERED: Divert $5,000,000" };
      return { packet: p, context };
    },
  },
  {
    id: "p04_agent_sig",
    targetRule: "AGENT_SIGNATURE",
    name: "Agent Signature Corruption",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const corrupted = "9f8e7d6c5b4a392817061524334251607f8e9d0c1b2a3948576675849302dead";
      if (p.agent_sig) {
        if (Array.isArray(p.agent_sig.signature_bytes) && p.agent_sig.signature_bytes.length > 0) {
          p.agent_sig.signature_bytes[0] ^= 0xff;
        } else if (typeof p.agent_sig.signature_bytes === "string") {
          p.agent_sig.signature_bytes = corrupted;
        } else {
          p.agent_sig.signature_bytes = new Array(64).fill(0xfe);
        }
        if ("sig_hex" in p.agent_sig) p.agent_sig.sig_hex = corrupted;
      }
      return { packet: p, context };
    },
  },
  {
    id: "p05_root_sig",
    targetRule: "ROOT_TOKEN_SIGNATURE",
    name: "Root Authority Token Forgery",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const badSig = "bad_root_signature_hex_000000000000000000000000000000000000000000000000";
      const rtSig = p.root_authority?.root_token?.issuer_sig;
      if (rtSig) {
        if (Array.isArray(rtSig.signature_bytes) && rtSig.signature_bytes.length > 0) {
          rtSig.signature_bytes[0] ^= 0xff;
        } else if (typeof rtSig.signature_bytes === "string") {
          rtSig.signature_bytes = badSig;
        } else {
          rtSig.signature_bytes = new Array(64).fill(0xfe);
        }
        if ("sig_hex" in rtSig) rtSig.sig_hex = badSig;
      }
      return { packet: p, context };
    },
  },
  {
    id: "p06_delegation",
    targetRule: "DELEGATION_CHAIN",
    name: "Scope Escalation Attack",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      if (Array.isArray(p.delegation_chain) && p.delegation_chain.length > 0) {
        const firstHop = p.delegation_chain[0];
        if (firstHop.scope && Array.isArray(firstHop.scope.allowed)) {
          const first = firstHop.scope.allowed[0];
          if (first && typeof first === "object" && "Standard" in first) {
            firstHop.scope.allowed.push({ Standard: "Admin" });
          } else if (first && typeof first === "object" && "kind" in first) {
            firstHop.scope.allowed.push({ kind: "Standard", action: "Admin" });
          } else if (typeof first === "string") {
            firstHop.scope.allowed.push("Admin");
          } else {
            firstHop.scope.allowed.push({ Standard: "Admin" });
          }
        }
      }
      return { packet: p, context };
    },
  },
  {
    id: "p07_authority",
    targetRule: "AUTHORITY_CHAIN",
    name: "Broken Authority Chain Handoff",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      if (Array.isArray(p.delegation_chain) && p.delegation_chain.length > 0) {
        p.delegation_chain[p.delegation_chain.length - 1].grantee_id = "unexpected-middleman-agent";
      } else if (p.root_authority?.root_token) {
        p.root_authority.root_token.agent_id = "unexpected-middleman-agent";
      }
      return { packet: p, context };
    },
  },
  {
    id: "p08_scope",
    targetRule: "SCOPE_AUTHORITY",
    name: "Unpermitted Action Execution",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      if (Array.isArray(p.actions)) {
        const hasExisting = p.actions.length > 0;
        const template = hasExisting ? JSON.parse(JSON.stringify(p.actions[0])) : null;
        const isWireFormat = !template || Array.isArray(template.action_id);

        const unpermittedActionId = isWireFormat
          ? [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
          : "0102030405060708090a0b0c0d0e0f10";

        const unpermittedActionKind =
          template && template.action_kind && "kind" in template.action_kind
            ? { kind: "Custom", name: "unpermitted:action_divert" }
            : { Custom: "unpermitted:action_divert" };

        const unpermittedPayloadHash = isWireFormat
          ? new Array(32).fill(0)
          : "0000000000000000000000000000000000000000000000000000000000000000";

        const unpermittedAgentSig = template?.agent_sig
          ? JSON.parse(JSON.stringify(template.agent_sig))
          : p.agent_sig
          ? JSON.parse(JSON.stringify(p.agent_sig))
          : {
              algorithm: "Ed25519",
              signer_id: p.agent?.aip_id || "aip12x9K8yM4QvB7eR6tP3sW1uZbAcD5fGhJ7",
              timestamp: Date.now(),
              nonce: isWireFormat ? new Array(16).fill(0) : "00".repeat(16),
              payload_hash: unpermittedPayloadHash,
              signature_bytes: isWireFormat ? new Array(64).fill(0) : "00".repeat(64),
            };

        p.actions.push({
          action_id: unpermittedActionId,
          action_kind: unpermittedActionKind,
          description: "Unauthorized funds transfer outside authority scope",
          payload_hash: unpermittedPayloadHash,
          performed_at: Date.now(),
          agent_sig: unpermittedAgentSig,
        });
      }
      return { packet: p, context };
    },
  },
  {
    id: "p09_revocation",
    targetRule: "REVOCATION",
    name: "Revoked Credential Injection",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const ctx = context ? JSON.parse(JSON.stringify(context)) : {};
      const targetJti = p.delegation_chain?.[0]?.jti || p.root_authority?.root_token?.jti || "a1b2c3d4e5f60718293a4b5c6d7e8f90";
      const currentJtis = Array.isArray(ctx.revoked_jtis) ? ctx.revoked_jtis : [];
      if (!currentJtis.includes(targetJti)) {
        ctx.revoked_jtis = [...currentJtis, targetJti];
        ctx.revoked_token_ids = ctx.revoked_jtis;
      }
      return { packet: p, context: ctx };
    },
  },
  {
    id: "p10_temporal",
    targetRule: "TEMPORAL_VALIDITY",
    name: "Inverted Timestamp Fraud",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      if (Array.isArray(p.actions) && p.actions.length > 0 && p.decision?.decided_at) {
        p.actions[0].performed_at = p.decision.decided_at - 1000000;
      }
      return { packet: p, context };
    },
  },
  {
    id: "p11_actions",
    targetRule: "ACTION_ATTESTATIONS",
    name: "Action Payload Mutation",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const tamperedHex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffftampered";
      if (Array.isArray(p.actions) && p.actions.length > 0) {
        if (Array.isArray(p.actions[0].payload_hash) && p.actions[0].payload_hash.length > 0) {
          p.actions[0].payload_hash[0] ^= 0xff;
        } else if (typeof p.actions[0].payload_hash === "string") {
          p.actions[0].payload_hash = tamperedHex;
        } else {
          p.actions[0].payload_hash = new Array(32).fill(0xff);
        }
      }
      return { packet: p, context };
    },
  },
  {
    id: "p12_trace",
    targetRule: "TRACE_BINDING",
    name: "Distributed Trace Spoofing",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const zeroHex = "0000000000000000000000000000000000000000000000000000000000000000";
      if (p.trace_binding) {
        if (Array.isArray(p.trace_binding.trace_hash) && p.trace_binding.trace_hash.length > 0) {
          p.trace_binding.trace_hash[0] ^= 0xff;
        } else if (typeof p.trace_binding.trace_hash === "string") {
          p.trace_binding.trace_hash = zeroHex;
        } else {
          p.trace_binding.trace_hash = new Array(32).fill(0);
        }
      } else {
        p.trace_binding = {
          trace_id: "trace-tampered-001",
          trace_hash: new Array(32).fill(0),
        };
      }
      return { packet: p, context };
    },
  },
  {
    id: "p13_receipt",
    targetRule: "RECEIPT_BINDING",
    name: "Counterparty Signature Corruption",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const corrupt = "corrupted_sig_hex_bytes_000000000000000000000000000000000000000000";
      const cpSig = p.receipt_binding?.counterparty_sig;
      if (cpSig) {
        if (Array.isArray(cpSig.signature_bytes) && cpSig.signature_bytes.length > 0) {
          cpSig.signature_bytes[0] ^= 0xff;
        } else if (typeof cpSig.signature_bytes === "string") {
          cpSig.signature_bytes = corrupt;
        } else {
          cpSig.signature_bytes = new Array(64).fill(0xfe);
        }
        if ("sig_hex" in cpSig) cpSig.sig_hex = corrupt;
      }
      return { packet: p, context };
    },
  },
  {
    id: "p14_trust_floor",
    targetRule: "TRUST_FLOOR",
    name: "Trust Floor Claim Inflation",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      p.claimed_trust_floor = "COUNTERPARTY_SIGNED";
      p.decision = {
        ...p.decision,
        summary: "FORCED_UNVERIFIED: Manipulated summary forcing derived trust floor drop",
      };
      return { packet: p, context };
    },
  },
];

const presetsFailingDeserialization = [];
const presetsPassingDeserialization = [];

for (const pr of attackPresetsAsWritten) {
  const { packet: mutPkt, context: mutCtx } = pr.mutate(baselinePacket, JSON.parse(baselineContextJson));
  try {
    const raw = wasm.verify_evidence_packet(JSON.stringify(mutPkt), JSON.stringify(mutCtx));
    const rep = JSON.parse(raw);
    const check = rep.checks.find(c => c.rule === pr.targetRule);
    presetsPassingDeserialization.push({ id: pr.id, target: pr.targetRule, pass: check?.pass });
    console.log(`Preset ${pr.id} (${pr.targetRule}): DESERIALIZED OK -> rule pass: ${check?.pass}`);
  } catch (err) {
    presetsFailingDeserialization.push({ id: pr.id, target: pr.targetRule, error: err.message || String(err) });
    console.warn(`Preset ${pr.id} (${pr.targetRule}): DESERIALIZATION REJECTED -> ${err.message || err}`);
  }
}

console.log(`\nPreset Deserialization Summary: ${presetsPassingDeserialization.length} OK, ${presetsFailingDeserialization.length} Failed`);
assert(
  presetsPassingDeserialization.length === 14,
  `All 14 presets pass WASM EvidencePacket deserialization (actually passed: ${presetsPassingDeserialization.length}/14)`,
  `${presetsFailingDeserialization.length} presets failed deserialization: ${presetsFailingDeserialization.map(f => f.id).join(", ")}`
);


// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 1B: Testing Wire-Compatible Attack Presets
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── VECTOR 1B: Testing Wire-Compatible Presets Against Exact Rules ───");

const wireCompatiblePresets = [
  { id: "p01", target: "STRUCTURE", name: "Malformed Wire Format", fn: p => { p.magic = [0x42, 0x41, 0x44, 0x31]; p.version = 99; } },
  { id: "p02", target: "AGENT_ID_BINDING", name: "Agent Identity Hijack", fn: p => { p.agent.aip_id = "aip1mismatchidentity99887766554433221122"; } },
  { id: "p03", target: "CANONICAL_HASH", name: "Decision Summary Tamper", fn: p => { p.decision.summary = "TAMPERED: Unauthorized diversion"; } },
  { id: "p04", target: "AGENT_SIGNATURE", name: "Agent Sig Bit Flip", fn: p => { p.agent_sig.signature_bytes[0] ^= 0xff; } },
  { id: "p05", target: "ROOT_TOKEN_SIGNATURE", name: "Root Sig Bit Flip", fn: p => { p.root_authority.root_token.issuer_sig.signature_bytes[0] ^= 0xff; } },
  { id: "p06", target: "DELEGATION_CHAIN", name: "Escalation in Wire Format", fn: p => { p.delegation_chain[0].scope.allowed.push({ Standard: "Admin" }); } },
  { id: "p07", target: "AUTHORITY_CHAIN", name: "Grantee Disconnect", fn: p => { p.delegation_chain[p.delegation_chain.length - 1].grantee_id = "unexpected-agent"; } },
  { id: "p08", target: "SCOPE_AUTHORITY", name: "Unpermitted Custom Action", fn: p => {
    p.actions.push({
      action_id: [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],
      action_kind: { Custom: "unpermitted:action_divert" },
      description: "Unauthorized action outside scope",
      payload_hash: new Array(32).fill(0),
      performed_at: Date.now(),
      agent_sig: p.agent_sig
    });
  }},
  { id: "p09", target: "REVOCATION", name: "Revoked JTI in Context", fn: (p, ctx) => { ctx.revoked_jtis = [p.delegation_chain[0].jti]; ctx.revoked_token_ids = ctx.revoked_jtis; } },
  { id: "p10", target: "TEMPORAL_VALIDITY", name: "Inverted Timestamp", fn: p => { p.actions[0].performed_at = p.decision.decided_at - 1000000; } },
  { id: "p11", target: "ACTION_ATTESTATIONS", name: "Action Payload Bit Flip", fn: p => { p.actions[0].payload_hash[0] ^= 0xff; } },
  { id: "p12", target: "TRACE_BINDING", name: "Trace Hash Bit Flip", fn: p => { p.trace_binding.trace_hash[0] ^= 0xff; } },
  { id: "p13", target: "RECEIPT_BINDING", name: "Counterparty Sig Bit Flip", fn: p => { p.receipt_binding.counterparty_sig.signature_bytes[0] ^= 0xff; } },
  { id: "p14", target: "TRUST_FLOOR", name: "Trust Floor Inflation", fn: p => { p.claimed_trust_floor = "COUNTERPARTY_SIGNED"; p.decision.summary = "FORCED_UNVERIFIED"; } },
];

for (const m of wireCompatiblePresets) {
  const p = JSON.parse(baselinePacketJson);
  const ctx = JSON.parse(baselineContextJson);
  m.fn(p, ctx);

  const raw = wasm.verify_evidence_packet(JSON.stringify(p), JSON.stringify(ctx));
  const rep = JSON.parse(raw);
  const targetCheck = rep.checks.find(c => c.rule === m.target);

  assert(rep.valid === false, `Wire-compatible ${m.id} (${m.name}): overall valid is false`);
  assert(targetCheck !== undefined, `Wire-compatible ${m.id}: target check '${m.target}' exists in report`);
  assert(targetCheck?.pass === false, `Wire-compatible ${m.id}: target check '${m.target}' FAILS (pass === false)`);
}


// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 2: Smart Hash Recalculation Toggle & Cryptographic Non-Repudiation (F12)
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── VECTOR 2: Smart Hash Recalculation Toggle & Non-Repudiation ───");

// Helper for wire-format [u8; 32]
function hexToBytes(hex) {
  const bytes = [];
  for (let c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16));
  return bytes;
}

const testMutations = [
  { name: "Decision Summary Tampering", mutate: (p) => { p.decision.summary = "ADVERSARIAL_MUTATION: Wire $9,999,999 to offshore IBAN"; } },
  { name: "Decision Rationale Hash Tampering", mutate: (p) => { p.decision.rationale_hash[0] ^= 0xff; } },
  { name: "Action Description Tampering", mutate: (p) => { p.actions[0].description = "Exfiltrate proprietary cryptographic keys"; } },
];

for (const mut of testMutations) {
  const pkt = JSON.parse(baselinePacketJson);
  mut.mutate(pkt);
  const originalStoredHash = pkt.packet_hash;

  // NAIVE MODE
  const naiveJson = JSON.stringify(pkt);
  const naiveRep = JSON.parse(wasm.verify_evidence_packet(naiveJson, baselineContextJson));
  const naiveHashCheck = naiveRep.checks.find(c => c.rule === "CANONICAL_HASH");

  assert(naiveHashCheck?.pass === false, `[Naive Mode] ${mut.name}: CANONICAL_HASH FAILS`);
  assert(naiveRep.tampered === true, `[Naive Mode] ${mut.name}: tamper_evidence is TRUE`);
  assert(naiveRep.valid === false, `[Naive Mode] ${mut.name}: overall valid is FALSE`);

  // 3A. TEST AS WRITTEN IN TamperSimulator.tsx (Wire-Format Byte-Packing)
  const freshHashHex = wasm.recompute_packet_hash(naiveJson);
  assert(freshHashHex !== originalStoredHash, `[Smart Mode] Fresh hash (${freshHashHex.slice(0, 16)}...) != Stored hash`);

  const pktAsSimulated = JSON.parse(JSON.stringify(pkt));
  const targetHash = Array.isArray(pkt.packet_hash) ? hexToBytes(freshHashHex) : freshHashHex;
  pktAsSimulated.packet_hash = targetHash; // Wire format assignment as written in TamperSimulator.tsx line 98
  let wireModeCrashed = false;
  try {
    wasm.verify_evidence_packet(JSON.stringify(pktAsSimulated), baselineContextJson);
  } catch (err) {
    wireModeCrashed = true;
    console.warn(`[TamperSimulator] Serialization error: ${err.message || err}`);
  }
  assert(
    !wireModeCrashed,
    `TamperSimulator.tsx wire-format assignment to packet_hash passes WASM deserialization for ${mut.name}`,
    `Assigning hex string to packet_hash ([u8; 32]) causes WASM serde deserialization failure`
  );

  // 3B. WIRE-FORMAT CONVERTED (hexToBytes for [u8; 32])
  const pktWire = JSON.parse(JSON.stringify(pkt));
  pktWire.packet_hash = hexToBytes(freshHashHex);
  const smartWireJson = JSON.stringify(pktWire);
  const smartRep = JSON.parse(wasm.verify_evidence_packet(smartWireJson, baselineContextJson));

  const smartHashCheck = smartRep.checks.find(c => c.rule === "CANONICAL_HASH");
  const smartSigCheck = smartRep.checks.find(c => c.rule === "AGENT_SIGNATURE");

  assert(smartHashCheck?.pass === true, `[Smart Wire Mode] ${mut.name}: CANONICAL_HASH PASSES (recalculated hash matches canonical bytes)`);
  assert(smartSigCheck?.pass === false, `[Smart Wire Mode] ${mut.name}: AGENT_SIGNATURE FAILS (non-repudiation: signature cannot be forged)`);
  assert(smartRep.tampered === true, `[Smart Wire Mode] ${mut.name}: tamper_evidence REMAINS TRUE`);
  assert(smartRep.valid === false, `[Smart Wire Mode] ${mut.name}: overall valid REMAINS FALSE`);
  assert(smartRep.trust_floor === "UNVERIFIED", `[Smart Wire Mode] ${mut.name}: trust_floor downgraded to UNVERIFIED`);
}


// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 3: Scope Matrix Boundary Conditions (F14.B1 - F14.B5)
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── VECTOR 3: Visual Scope Matrix Boundary Conditions ───");

function checkScopePermission(scope, actionStr) {
  const norm = actionStr.trim();
  const isDenied = scope.denied?.some(d => (typeof d === "string" ? d : d.name || d.action).toLowerCase() === norm.toLowerCase());
  if (isDenied) return false;

  const isExplicitAllowed = scope.allowed?.some(a => {
    const val = typeof a === "string" ? a : a.name || a.action;
    const standardVerbs = ["read", "write", "delete", "admin", "execute", "delegate"];
    if (standardVerbs.includes(norm.toLowerCase()) && standardVerbs.includes(val.toLowerCase())) {
      return val.toLowerCase() === norm.toLowerCase();
    }
    return val === norm;
  });
  if (isExplicitAllowed) return true;

  const hasAdmin = scope.allowed?.some(a => (typeof a === "string" ? a : a.action) === "Admin");
  const standardVerbs = ["read", "write", "delete", "admin", "execute", "delegate"];
  if (hasAdmin && standardVerbs.includes(norm.toLowerCase())) {
    return true;
  }
  return false;
}

// F14.B1
console.log("\nF14.B1: Explicit Deny Priority");
const scopeDenyConflict = {
  allowed: ["Read", "Write", { kind: "Custom", name: "wire:transfer" }],
  denied: ["Write", { kind: "Custom", name: "wire:transfer" }],
};
assert(checkScopePermission(scopeDenyConflict, "Write") === false, "F14.B1: Action in both allowed and denied is DENIED (Write -> false)");
assert(checkScopePermission(scopeDenyConflict, "wire:transfer") === false, "F14.B1: Custom verb in both allowed and denied is DENIED");
assert(checkScopePermission(scopeDenyConflict, "Read") === true, "F14.B1: Non-denied allowed action remains PERMITTED (Read -> true)");

const wasmScopeJson = JSON.stringify({ allowed: ["Read", "Write"], denied: ["Write"] });
assert(wasm.check_scope_permits(wasmScopeJson, JSON.stringify("Write")) === false, "F14.B1 (WASM): check_scope_permits evaluates explicit deny as false");
assert(wasm.check_scope_permits(wasmScopeJson, JSON.stringify("Read")) === true, "F14.B1 (WASM): check_scope_permits evaluates non-denied allowed as true");

// F14.B2
console.log("\nF14.B2: Empty Allowed Array Closed World");
const emptyScope = { allowed: [], denied: [] };
const candidateActions = ["Read", "Write", "Delete", "Admin", "Execute", "Delegate", "loan:approve", "wire:send", "ledger:audit"];
let permittedCount = 0;
for (const act of candidateActions) {
  if (checkScopePermission(emptyScope, act)) permittedCount++;
}
assert(permittedCount === 0, `F14.B2: Empty allowed array permits exactly 0 actions (got ${permittedCount})`);

// F14.B3
console.log("\nF14.B3: Complex Custom Action Verbs");
const customActionRegex = /^[a-zA-Z0-9_\-\:\.\/]+$/;
const validVerbs = ["ledger/treasury:transfer-wire_v2", "cloud.infra/vpc:route_table-update.v1", "auth:user_profile.read"];
const invalidVerbs = ["malicious;drop_table", "spaces not allowed", "dollar$sign", "<script>alert(1)</script>"];
for (const v of validVerbs) assert(customActionRegex.test(v), `F14.B3: Valid custom verb matches regex: '${v}'`);
for (const inv of invalidVerbs) assert(!customActionRegex.test(inv), `F14.B3: Invalid custom verb fails regex: '${inv}'`);

const complexScope = { allowed: [{ kind: "Custom", name: "ledger/treasury:transfer-wire_v2" }], denied: [] };
assert(checkScopePermission(complexScope, "ledger/treasury:transfer-wire_v2") === true, "F14.B3: Complex verb 'ledger/treasury:transfer-wire_v2' is PERMITTED");

// F14.B4
console.log("\nF14.B4: Strict Case Sensitivity");
const caseScope = { allowed: [{ kind: "Custom", name: "loan:approve" }], denied: [] };
assert(checkScopePermission(caseScope, "loan:approve") === true, "F14.B4: Exact match 'loan:approve' is PERMITTED");
assert(checkScopePermission(caseScope, "LOAN:APPROVE") === false, "F14.B4: Uppercase 'LOAN:APPROVE' is DENIED");
assert(checkScopePermission(caseScope, "Loan:Approve") === false, "F14.B4: TitleCase 'Loan:Approve' is DENIED");

// F14.B5
console.log("\nF14.B5: Admin Inheritance");
const adminScope = { allowed: ["Admin"], denied: ["Delete"] };
assert(checkScopePermission(adminScope, "Read") === true, "F14.B5: Admin grants standard verb 'Read'");
assert(checkScopePermission(adminScope, "Write") === true, "F14.B5: Admin grants standard verb 'Write'");
assert(checkScopePermission(adminScope, "Execute") === true, "F14.B5: Admin grants standard verb 'Execute'");
assert(checkScopePermission(adminScope, "Delete") === false, "F14.B5: Explicit deny on 'Delete' OVERRIDES Admin grant");
assert(checkScopePermission(adminScope, "wire:transfer") === false, "F14.B5: Admin DOES NOT grant unpermitted custom verb");


// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 4: Capability Lattice Boundary Conditions (F15.B1 - F15.B5)
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── VECTOR 4: Capability Lattice Meet (⊓) Boundary Conditions ───");

function meetScopesPure(parent, child) {
  const pAllowed = parent.allowed || [];
  const pDenied = parent.denied || [];
  const cAllowed = child.allowed || [];
  const cDenied = child.denied || [];

  const hasAdmin = pAllowed.some(a => (typeof a === "string" ? a : a.action) === "Admin");
  let effParentAllowed = [...pAllowed];
  if (hasAdmin) {
    const stds = ["Read", "Write", "Delete", "Admin", "Execute", "Delegate"];
    for (const s of stds) {
      if (!effParentAllowed.some(a => (typeof a === "string" ? a : a.action) === s) &&
          !pDenied.some(d => (typeof d === "string" ? d : d.action) === s)) {
        effParentAllowed.push(s);
      }
    }
  }

  const pAllowedMinusDenied = effParentAllowed.filter(p => {
    const pStr = typeof p === "string" ? p : p.name || p.action;
    return !pDenied.some(d => (typeof d === "string" ? d : d.name || d.action) === pStr);
  });

  const metAllowed = cAllowed.filter(c => {
    const cStr = typeof c === "string" ? c : c.name || c.action;
    return pAllowedMinusDenied.some(p => (typeof p === "string" ? p : p.name || p.action) === cStr);
  });

  const metDenied = [...pDenied];
  for (const cd of cDenied) {
    const cdStr = typeof cd === "string" ? cd : cd.name || cd.action;
    if (!metDenied.some(d => (typeof d === "string" ? d : d.name || d.action) === cdStr)) {
      metDenied.push(cd);
    }
  }

  return { allowed: metAllowed, denied: metDenied, isBottom: metAllowed.length === 0 };
}

// F15.B1
console.log("\nF15.B1: Lattice Idempotence (S ⊓ S = S)");
const testScopes = [
  { allowed: ["Read", "Write"], denied: [] },
  { allowed: ["Read", "Write", "Execute"], denied: ["Delete"] },
  { allowed: ["loan:approve", "credit:underwrite"], denied: [] },
];
for (const s of testScopes) {
  const met = meetScopesPure(s, s);
  assert(!met.isBottom, `F15.B1: Meet with self is not bottom`);
  assert(JSON.stringify(met.allowed) === JSON.stringify(s.allowed), `F15.B1: S ⊓ S === S holds`);
}

// F15.B2
console.log("\nF15.B2: Lattice Identity Element (ADMIN ⊓ S = S)");
const fullAdmin = { allowed: ["Admin"], denied: [] };
const subScope = { allowed: ["Read", "Write", "Execute"], denied: ["Delete"] };
const metAdmin = meetScopesPure(fullAdmin, subScope);
assert(JSON.stringify(metAdmin.allowed.sort()) === JSON.stringify(subScope.allowed.sort()), "F15.B2: ADMIN ⊓ S === S");

// F15.B3
console.log("\nF15.B3: Disjoint Bottom ⊥ Testing");
const scopeA = { allowed: ["Read", "Write"], denied: [] };
const scopeB = { allowed: ["Execute", "loan:approve"], denied: [] };
const metDisjoint = meetScopesPure(scopeA, scopeB);
assert(metDisjoint.isBottom === true, "F15.B3: Pure meet of disjoint scopes yields isBottom: true");

const wasmDisjointResult = JSON.parse(wasm.meet_capability_scopes(JSON.stringify(scopeA), JSON.stringify(scopeB)));
assert(wasmDisjointResult.is_bottom === true, "F15.B3 (WASM): meet_capability_scopes returns is_bottom: true");
assert(wasmDisjointResult.allowed.length === 0, "F15.B3 (WASM): meet_capability_scopes returns allowed: []");

// F15.B4
console.log("\nF15.B4: Lattice Associativity ((A ⊓ B) ⊓ C = A ⊓ (B ⊓ C))");
const scopeChainA = { allowed: ["Read", "Write", "Execute", "Delete"], denied: [] };
const scopeChainB = { allowed: ["Read", "Write", "Execute"], denied: [] };
const scopeChainC = { allowed: ["Read", "Write"], denied: [] };
const leftAssoc = meetScopesPure(meetScopesPure(scopeChainA, scopeChainB), scopeChainC);
const rightAssoc = meetScopesPure(scopeChainA, meetScopesPure(scopeChainB, scopeChainC));
assert(JSON.stringify(leftAssoc.allowed) === JSON.stringify(rightAssoc.allowed), "F15.B4: Associativity holds");

// F15.B5
console.log("\nF15.B5: Lattice Commutativity (Allowed(A ⊓ B) = Allowed(B ⊓ A))");
const commScope1 = { allowed: ["Read", "Write", "Execute"], denied: [] };
const commScope2 = { allowed: ["Write", "Execute", "Delete"], denied: [] };
const commMeet1 = meetScopesPure(commScope1, commScope2);
const commMeet2 = meetScopesPure(commScope2, commScope1);
assert(JSON.stringify(commMeet1.allowed.sort()) === JSON.stringify(commMeet2.allowed.sort()), "F15.B5: Commutativity holds on allowed");


// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 5: Cascade Revocation Tree Boundary Conditions (F16.B1 - F16.B4)
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── VECTOR 5: Cascade Revocation Tree Boundaries ───");

function cascadeRevoke(targetJti, treeNodes, primaryReason = "Compromise") {
  const result = [];
  const queue = [targetJti];
  result.push({ jti: targetJti, reason: primaryReason, cascade: true });
  while (queue.length > 0) {
    const current = queue.shift();
    const children = treeNodes.filter(n => n.parent_jti === current);
    for (const child of children) {
      result.push({ jti: child.jti, reason: "AdminRevocation", cascade: true });
      queue.push(child.jti);
    }
  }
  return result;
}

// F16.B1
console.log("\nF16.B1: Leaf Revocation");
const simpleTree = [
  { jti: "root-jti-00", parent_jti: undefined },
  { jti: "hop1-jti-01", parent_jti: "root-jti-00" },
  { jti: "hop2-jti-02", parent_jti: "hop1-jti-01" },
];
const leafRevocations = cascadeRevoke("hop2-jti-02", simpleTree);
assert(leafRevocations.length === 1, `F16.B1: Leaf revocation produces exactly 1 entry`);
assert(leafRevocations[0].jti === "hop2-jti-02", "F16.B1: Revoked JTI is leaf token");

// F16.B2
console.log("\nF16.B2: Depth-4 Chain BFS Traversal");
const depth4Chain = [
  { jti: "chain-root-00", parent_jti: undefined },
  { jti: "chain-hop1-01", parent_jti: "chain-root-00" },
  { jti: "chain-hop2-02", parent_jti: "chain-hop1-01" },
  { jti: "chain-hop3-03", parent_jti: "chain-hop2-02" },
  { jti: "chain-hop4-04", parent_jti: "chain-hop3-03" },
];
const fullChainRevocations = cascadeRevoke("chain-root-00", depth4Chain);
assert(fullChainRevocations.length === 5, `F16.B2: Full chain revocation invalidates all 5 nodes`);
assert(fullChainRevocations[0].jti === "chain-root-00" && fullChainRevocations[0].reason === "Compromise", "F16.B2: Root is primary");
assert(fullChainRevocations[4].jti === "chain-hop4-04", "F16.B2: Hop 4 is last in BFS");

const midChainRevocations = cascadeRevoke("chain-hop2-02", depth4Chain);
assert(midChainRevocations.length === 3, `F16.B2: Mid-chain revocation invalidates exactly 3 nodes`);
const midJtis = midChainRevocations.map(r => r.jti);
assert(!midJtis.includes("chain-root-00") && !midJtis.includes("chain-hop1-01"), "F16.B2: Ancestors untouched");

// F16.B4
console.log("\nF16.B4: Wide Tree (10 Children)");
const wideTree = [{ jti: "wide-parent-00", parent_jti: undefined }];
for (let i = 1; i <= 10; i++) wideTree.push({ jti: `wide-child-${i}`, parent_jti: "wide-parent-00" });
const wideRevocations = cascadeRevoke("wide-parent-00", wideTree);
assert(wideRevocations.length === 11, `F16.B4: Wide parent revocation cascades to all 10 children (got ${wideRevocations.length})`);

// WASM Revocation Sync Triggering Rule 9
console.log("\nF16.B5: WASM Context Revocation Sync Triggering Rule 9");
const activePkt = JSON.parse(baselinePacketJson);
const revokedJti = activePkt.delegation_chain[0].jti;
const revokedContext = JSON.parse(baselineContextJson);
revokedContext.revoked_jtis = [revokedJti];
revokedContext.revoked_token_ids = [revokedJti];

const revokedRepStr = wasm.verify_evidence_packet(baselinePacketJson, JSON.stringify(revokedContext));
const revokedRep = JSON.parse(revokedRepStr);
const rule9Check = revokedRep.checks.find(c => c.rule === "REVOCATION");

assert(rule9Check?.pass === false, "F16.B5: Rule 9 (REVOCATION) FAILS when token JTI is in revoked_jtis");
assert(revokedRep.valid === false, "F16.B5: Overall valid is FALSE upon revocation");
assert(revokedRep.trust_floor === "AGENT_SIGNED" || revokedRep.trust_floor === "UNVERIFIED", "F16.B5: Derived trust floor is downgraded");
assert(revokedRep.tampered === false, "F16.B5: Tamper evidence remains FALSE (revocation is authority invalidation)");


// ─────────────────────────────────────────────────────────────────────────────
// VECTOR 6: Zero-JS Verification Static Code Analysis
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n─── VECTOR 6: Zero-JS Verification Static Code Analysis ───");

const forbiddenCryptoPatterns = [
  { pattern: /\bcrypto\.subtle\.verify\b/, name: "crypto.subtle.verify" },
  { pattern: /\bcreateHash\s*\(/, name: "Node createHash" },
  { pattern: /\bsha256\s*\(/, name: "JS sha256 function" },
  { pattern: /\bed25519\.verify\b/, name: "JS Ed25519 verify" },
  { pattern: /\bnacl\.sign\.open\b/, name: "TweetNaCl sign open" },
  { pattern: /\b@noble\/ed25519\b/, name: "Noble Ed25519" },
];

function scanDirForCrypto(dirPath) {
  const files = fs.readdirSync(dirPath);
  for (const file of files) {
    const full = path.join(dirPath, file);
    if (fs.statSync(full).isDirectory()) {
      scanDirForCrypto(full);
    } else if (file.endsWith(".tsx") || file.endsWith(".ts")) {
      const content = fs.readFileSync(full, "utf8");
      for (const { pattern, name } of forbiddenCryptoPatterns) {
        assert(!pattern.test(content), `Zero-JS Invariant: ${file} does not contain ${name}`);
      }
    }
  }
}
scanDirForCrypto(TAMPER_DIR);
scanDirForCrypto(AUTHORITY_DIR);


// ─────────────────────────────────────────────────────────────────────────────
// FINAL EMPIRICAL SUMMARY & VERDICT
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n================================================================================");
console.log(`TOTAL TESTS EXECUTED : ${totalTests}`);
console.log(`PASSED TESTS         : ${passedTests}`);
console.log(`FAILED TESTS         : ${failedTests}`);
console.log(`SUCCESS RATE         : ${((passedTests / totalTests) * 100).toFixed(2)}%`);
console.log("================================================================================");

if (failedTests === 0) {
  console.log("EMPIRICAL CHALLENGER VERDICT: APPROVE (100% Pass across all 6 challenge vectors)");
  process.exit(0);
} else {
  console.error(`EMPIRICAL CHALLENGER VERDICT: REQUEST_CHANGES (${failedTests} tests failed)`);
  console.error("Identified Findings:");
  findings.forEach((f, idx) => {
    console.error(`  [${idx + 1}] ${f.testName} -> ${f.details}`);
  });
  process.exit(1);
}
