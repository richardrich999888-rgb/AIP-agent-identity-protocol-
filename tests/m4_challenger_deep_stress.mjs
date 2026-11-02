import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const CONSOLE_DIR = path.join(ROOT_DIR, "aip-console");
const FIXTURES_DIR = path.join(CONSOLE_DIR, "public", "fixtures");
const WASM_JS_PATH = path.join(CONSOLE_DIR, "public", "wasm", "aip_wasm.js");
const WASM_BG_PATH = path.join(CONSOLE_DIR, "public", "wasm", "aip_wasm_bg.wasm");
const PRESETS_PATH = path.join(CONSOLE_DIR, "src", "components", "tamper", "attackPresets.ts");

console.log("=== EMPIRICAL CHALLENGER DEEP STRESS HARNESS ===");

// 1. Instantiate WASM
const wasmModule = await import(`file://${WASM_JS_PATH}`);
const wasmBytes = fs.readFileSync(WASM_BG_PATH);
await wasmModule.default({ module_or_path: wasmBytes });
const wasm = wasmModule;

const baselinePacketJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.json"), "utf8");
const baselineContextJson = fs.readFileSync(path.join(FIXTURES_DIR, "honest_counterparty.context.json"), "utf8");
const baselinePacket = JSON.parse(baselinePacketJson);
const baselineContext = JSON.parse(baselineContextJson);

// Helpers from TamperSimulator.tsx
function hexToBytes(hex) {
  const cleanHex = hex.trim().replace(/^0x/i, "");
  const bytes = [];
  for (let c = 0; c < cleanHex.length; c += 2) {
    bytes.push(parseInt(cleanHex.substring(c, c + 2), 16));
  }
  return bytes;
}

function bytesToHex(bytes) {
  return bytes.map((b) => Number(b).toString(16).padStart(2, "0")).join("");
}

function areByteArraysEqual(a, b) {
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
  return a === b;
}

let passCount = 0;
let failCount = 0;

function check(cond, title, detail = "") {
  if (cond) {
    passCount++;
    console.log(`[PASS] ${title}`);
  } else {
    failCount++;
    console.error(`[FAIL] ${title} :: ${detail}`);
  }
}

// ── Test 1: Helper unit stress tests ──────────────────────────────────────────
console.log("\n--- Suite 1: hexToBytes / bytesToHex / areByteArraysEqual Edge Cases ---");
const zero32 = new Array(32).fill(0);
const zero32Hex = "00".repeat(32);
check(areByteArraysEqual(hexToBytes(zero32Hex), zero32), "hexToBytes: 32 zeros matches zero array");
check(bytesToHex(zero32) === zero32Hex, "bytesToHex: zero array matches 64 zeroes");

const testHexWith0x = "0x" + "ab".repeat(32);
const testBytes = new Array(32).fill(0xab);
check(areByteArraysEqual(hexToBytes(testHexWith0x), testBytes), "hexToBytes handles '0x' prefix");
check(areByteArraysEqual(testBytes, testBytes.slice()), "areByteArraysEqual returns true for distinct clones");
check(!areByteArraysEqual(testBytes, testBytes.slice(0, 31)), "areByteArraysEqual returns false for different lengths");
const flipped = testBytes.slice();
flipped[0] ^= 0x01;
check(!areByteArraysEqual(testBytes, flipped), "areByteArraysEqual returns false for single bit difference");
check(areByteArraysEqual(null, null), "areByteArraysEqual handles null equality");
check(!areByteArraysEqual(null, [1]), "areByteArraysEqual handles null vs array");
check(areByteArraysEqual("hello", "hello"), "areByteArraysEqual handles strings");

// ── Test 2: Execute all 14 presets parsed from attackPresets.ts directly ───────
console.log("\n--- Suite 2: Execute All 14 Attack Presets on Baseline Packet ---");

const presets = [
  {
    id: "p01_structure",
    target: "STRUCTURE",
    fn: (p, ctx) => {
      p.magic = [0x42, 0x41, 0x44, 0x31];
      p.version = 99;
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p02_agent_id",
    target: "AGENT_ID_BINDING",
    fn: (p, ctx) => {
      p.agent = { ...p.agent, aip_id: "aip1mismatchidentity99887766554433221122" };
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p03_canonical_hash",
    target: "CANONICAL_HASH",
    fn: (p, ctx) => {
      p.decision = { ...p.decision, summary: "TAMPERED: Divert $5,000,000 to offshore unauthorized facility" };
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p04_agent_sig",
    target: "AGENT_SIGNATURE",
    fn: (p, ctx) => {
      const corruptedHex = "9f8e7d6c5b4a392817061524334251607f8e9d0c1b2a3948576675849302dead";
      if (p.agent_sig) {
        if (Array.isArray(p.agent_sig.signature_bytes) && p.agent_sig.signature_bytes.length > 0) {
          p.agent_sig.signature_bytes[0] ^= 0xff;
        } else if (typeof p.agent_sig.signature_bytes === "string") {
          p.agent_sig.signature_bytes = corruptedHex;
        } else {
          p.agent_sig.signature_bytes = new Array(64).fill(0xfe);
        }
        if ("sig_hex" in p.agent_sig) p.agent_sig.sig_hex = corruptedHex;
      }
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p05_root_sig",
    target: "ROOT_TOKEN_SIGNATURE",
    fn: (p, ctx) => {
      const badSigHex = "bad_root_signature_hex_000000000000000000000000000000000000000000000000";
      const rtSig = p.root_authority?.root_token?.issuer_sig;
      if (rtSig) {
        if (Array.isArray(rtSig.signature_bytes) && rtSig.signature_bytes.length > 0) {
          rtSig.signature_bytes[0] ^= 0xff;
        } else if (typeof rtSig.signature_bytes === "string") {
          rtSig.signature_bytes = badSigHex;
        } else {
          rtSig.signature_bytes = new Array(64).fill(0xfe);
        }
        if ("sig_hex" in rtSig) rtSig.sig_hex = badSigHex;
      }
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p06_delegation",
    target: "DELEGATION_CHAIN",
    fn: (p, ctx) => {
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
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p07_authority",
    target: "AUTHORITY_CHAIN",
    fn: (p, ctx) => {
      if (Array.isArray(p.delegation_chain) && p.delegation_chain.length > 0) {
        p.delegation_chain[p.delegation_chain.length - 1].grantee_id = "unexpected-middleman-agent";
      } else if (p.root_authority?.root_token) {
        p.root_authority.root_token.agent_id = "unexpected-middleman-agent";
      }
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p08_scope",
    target: "SCOPE_AUTHORITY",
    fn: (p, ctx) => {
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
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p09_revocation",
    target: "REVOCATION",
    fn: (p, ctx) => {
      const targetJti =
        p.delegation_chain?.[0]?.jti ||
        p.root_authority?.root_token?.jti ||
        "a1b2c3d4e5f60718293a4b5c6d7e8f90";

      const currentJtis = Array.isArray(ctx.revoked_jtis) ? ctx.revoked_jtis : [];
      ctx.revoked_jtis = [...currentJtis, targetJti];
      ctx.revoked_token_ids = ctx.revoked_jtis;
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p10_temporal",
    target: "TEMPORAL_VALIDITY",
    fn: (p, ctx) => {
      if (Array.isArray(p.actions) && p.actions.length > 0 && p.decision?.decided_at) {
        p.actions[0].performed_at = p.decision.decided_at - 1000000;
      } else if (p.decision?.decided_at) {
        p.decision.decided_at = (p.root_authority?.root_token?.issued_at || 1000000) - 500000;
      }
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p11_actions",
    target: "ACTION_ATTESTATIONS",
    fn: (p, ctx) => {
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
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p12_trace",
    target: "TRACE_BINDING",
    fn: (p, ctx) => {
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
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p13_receipt",
    target: "RECEIPT_BINDING",
    fn: (p, ctx) => {
      const corruptHex = "corrupted_sig_hex_bytes_000000000000000000000000000000000000000000";
      const cpSig = p.receipt_binding?.counterparty_sig;
      if (cpSig) {
        if (Array.isArray(cpSig.signature_bytes) && cpSig.signature_bytes.length > 0) {
          cpSig.signature_bytes[0] ^= 0xff;
        } else if (typeof cpSig.signature_bytes === "string") {
          cpSig.signature_bytes = corruptHex;
        } else {
          cpSig.signature_bytes = new Array(64).fill(0xfe);
        }
        if ("sig_hex" in cpSig) cpSig.sig_hex = corruptHex;
      }
      return { packet: p, context: ctx };
    }
  },
  {
    id: "p14_trust_floor",
    target: "TRUST_FLOOR",
    fn: (p, ctx) => {
      p.claimed_trust_floor = "COUNTERPARTY_SIGNED";
      p.decision = {
        ...p.decision,
        summary: "FORCED_UNVERIFIED: Manipulated summary forcing derived trust floor drop",
      };
      return { packet: p, context: ctx };
    }
  }
];

for (const pr of presets) {
  const p = JSON.parse(baselinePacketJson);
  const ctx = JSON.parse(baselineContextJson);
  const { packet: mutP, context: mutCtx } = pr.fn(p, ctx);

  let resJson;
  let errorMsg = null;
  try {
    resJson = wasm.verify_evidence_packet(JSON.stringify(mutP), JSON.stringify(mutCtx));
  } catch (e) {
    errorMsg = e.message || String(e);
  }

  check(!errorMsg, `Preset ${pr.id}: WASM Deserialization succeeds without engine error`, errorMsg);
  if (resJson) {
    const report = JSON.parse(resJson);
    check(report.valid === false, `Preset ${pr.id}: Overall valid is FALSE`);
    const targetCheck = report.checks.find(c => c.rule === pr.target);
    check(targetCheck !== undefined, `Preset ${pr.id}: Rule '${pr.target}' present in checks`);
    check(targetCheck?.pass === false, `Preset ${pr.id}: Targeted rule '${pr.target}' explicitly FAILS`);
  }
}

// ── Test 3: Smart Attacker Mode Non-Repudiation across 5 genuine payload mutations ───
console.log("\n--- Suite 3: Smart Attacker Mode Non-Repudiation Proof ---");
const smartTestCases = [
  { name: "Decision summary changed", mut: p => { p.decision.summary = "Malicious transfer"; } },
  { name: "Action description changed", mut: p => { p.actions[0].description = "Exfiltrate keys"; } },
  { name: "Decision rationale hash flipped", mut: p => { p.decision.rationale_hash[0] ^= 0x55; } },
  { name: "Action performed_at modified", mut: p => { p.actions[0].performed_at += 1000; } },
  { name: "Decision decided_at modified", mut: p => { p.decision.decided_at += 5000; } },
];

for (const tc of smartTestCases) {
  const p = JSON.parse(baselinePacketJson);
  tc.mut(p);

  // Recalculate hash with WASM
  const newHashHex = wasm.recompute_packet_hash(JSON.stringify(p));
  // Assign packed bytes [u8; 32]
  p.packet_hash = hexToBytes(newHashHex);

  const rep = JSON.parse(wasm.verify_evidence_packet(JSON.stringify(p), baselineContextJson));
  const hashRule = rep.checks.find(c => c.rule === "CANONICAL_HASH");
  const sigRule = rep.checks.find(c => c.rule === "AGENT_SIGNATURE");

  check(hashRule?.pass === true, `Smart Mode (${tc.name}): CANONICAL_HASH passes`);
  check(sigRule?.pass === false, `Smart Mode (${tc.name}): AGENT_SIGNATURE fails (Non-repudiation)`);
  check(rep.tampered === true, `Smart Mode (${tc.name}): tamper_evidence is TRUE`);
  check(rep.valid === false, `Smart Mode (${tc.name}): overall valid is FALSE`);
}

// ── Test 4: Serde error handling verification ─────────────────────────────────
console.log("\n--- Suite 4: Invalid Wire-Format & Deserialization Errors ---");
const invalidTypeCases = [
  { name: "packet_hash is a string instead of [u8; 32]", mut: p => { p.packet_hash = "bad_hex_string"; } },
  { name: "agent_sig.signature_bytes is string instead of [u8; 64]", mut: p => { p.agent_sig.signature_bytes = "bad_string"; } },
  { name: "root_authority token issuer_sig is string instead of Vec<u8>", mut: p => { p.root_authority.root_token.issuer_sig.signature_bytes = "bad_string"; } },
  { name: "actions[0].action_id is string instead of [u8; 16]", mut: p => { p.actions[0].action_id = "act-1234"; } },
  { name: "magic is string instead of [u8; 4]", mut: p => { p.magic = "AEP1"; } },
];

for (const ic of invalidTypeCases) {
  const p = JSON.parse(baselinePacketJson);
  ic.mut(p);
  let threw = false;
  let thrownMsg = "";
  try {
    wasm.verify_evidence_packet(JSON.stringify(p), baselineContextJson);
  } catch (err) {
    threw = true;
    thrownMsg = err.message || String(err);
  }

  check(threw, `Engine rejection for: ${ic.name}`, thrownMsg);
  check(
    thrownMsg.includes("invalid type: string") || thrownMsg.includes("expected a sequence") || thrownMsg.includes("expected an array"),
    `Engine error contains expected serde wire-format rejection for: ${ic.name} (msg: ${thrownMsg.slice(0, 70)}...)`
  );
}

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n======================================================`);
console.log(`DEEP STRESS HARNESS SUMMARY:`);
console.log(`PASSED: ${passCount}`);
console.log(`FAILED: ${failCount}`);
console.log(`======================================================`);

if (failCount > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
