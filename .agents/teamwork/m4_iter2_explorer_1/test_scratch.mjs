import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "../../..");
const CONSOLE_DIR = path.join(ROOT_DIR, "aip-console");
const WASM_JS_PATH = path.join(CONSOLE_DIR, "public", "wasm", "aip_wasm.js");
const WASM_BG_PATH = path.join(CONSOLE_DIR, "public", "wasm", "aip_wasm_bg.wasm");

const wasmModule = await import(`file://${WASM_JS_PATH}`);
const wasmBytes = fs.readFileSync(WASM_BG_PATH);
await wasmModule.default({ module_or_path: wasmBytes });
const wasm = wasmModule;

const baselinePacket = JSON.parse(
  fs.readFileSync(path.join(CONSOLE_DIR, "public", "fixtures", "honest_counterparty.json"), "utf8")
);
const baselineContext = fs.readFileSync(
  path.join(CONSOLE_DIR, "public", "fixtures", "honest_counterparty.context.json"),
  "utf8"
);

const presets = [
  {
    id: "p01_structure",
    target: "STRUCTURE",
    fn: (p) => {
      p.magic = [0x42, 0x41, 0x44, 0x31];
      p.version = 99;
    },
  },
  {
    id: "p02_agent_id",
    target: "AGENT_ID_BINDING",
    fn: (p) => {
      p.agent = { ...p.agent, aip_id: "aip1mismatchidentity99887766554433221122" };
    },
  },
  {
    id: "p03_canonical_hash",
    target: "CANONICAL_HASH",
    fn: (p) => {
      p.decision = {
        ...p.decision,
        summary: "TAMPERED: Divert $5,000,000 to offshore unauthorized facility",
      };
    },
  },
  {
    id: "p04_agent_sig",
    target: "AGENT_SIGNATURE",
    fn: (p) => {
      const corruptedHex = "9f8e7d6c5b4a392817061524334251607f8e9d0c1b2a3948576675849302dead";
      if (p.agent_sig) {
        if (Array.isArray(p.agent_sig.signature_bytes) && p.agent_sig.signature_bytes.length > 0) {
          p.agent_sig.signature_bytes[0] ^= 0xff;
        } else if (typeof p.agent_sig.signature_bytes === "string") {
          p.agent_sig.signature_bytes = corruptedHex;
        } else {
          p.agent_sig.signature_bytes = new Array(64).fill(0xfe);
        }
        if ("sig_hex" in p.agent_sig) {
          p.agent_sig.sig_hex = corruptedHex;
        }
      }
    },
  },
  {
    id: "p05_root_sig",
    target: "ROOT_TOKEN_SIGNATURE",
    fn: (p) => {
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
        if ("sig_hex" in rtSig) {
          rtSig.sig_hex = badSigHex;
        }
      }
    },
  },
  {
    id: "p06_delegation",
    target: "DELEGATION_CHAIN",
    fn: (p) => {
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
    },
  },
  {
    id: "p07_authority",
    target: "AUTHORITY_CHAIN",
    fn: (p) => {
      if (Array.isArray(p.delegation_chain) && p.delegation_chain.length > 0) {
        p.delegation_chain[p.delegation_chain.length - 1].grantee_id = "unexpected-middleman-agent";
      } else if (p.root_authority?.root_token) {
        p.root_authority.root_token.agent_id = "unexpected-middleman-agent";
      }
    },
  },
  {
    id: "p08_scope",
    target: "SCOPE_AUTHORITY",
    fn: (p) => {
      if (Array.isArray(p.actions)) {
        const template = p.actions[0] ? JSON.parse(JSON.stringify(p.actions[0])) : null;
        const isWire = !template || Array.isArray(template.action_id);
        const actionId = isWire
          ? [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
          : "0102030405060708090a0b0c0d0e0f10";
        const actionKind =
          template?.action_kind && "kind" in template.action_kind
            ? { kind: "Custom", name: "unpermitted:action_divert" }
            : { Custom: "unpermitted:action_divert" };
        const payloadHash = isWire
          ? new Array(32).fill(0)
          : "0000000000000000000000000000000000000000000000000000000000000000";
        const agentSig = template?.agent_sig
          ? template.agent_sig
          : p.agent_sig
          ? JSON.parse(JSON.stringify(p.agent_sig))
          : {
              algorithm: "Ed25519",
              signer_id: p.agent?.aip_id || "aip12x9K8yM4QvB7eR6tP3sW1uZbAcD5fGhJ7",
              timestamp: Date.now(),
              nonce: isWire ? new Array(16).fill(0) : "00".repeat(16),
              payload_hash: payloadHash,
              signature_bytes: isWire ? new Array(64).fill(0) : "00".repeat(64),
            };
        p.actions.push({
          action_id: actionId,
          action_kind: actionKind,
          description: "Unauthorized funds transfer outside authority scope",
          payload_hash: payloadHash,
          performed_at: Date.now(),
          agent_sig: agentSig,
        });
      }
    },
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
    },
  },
  {
    id: "p10_temporal",
    target: "TEMPORAL_VALIDITY",
    fn: (p) => {
      if (Array.isArray(p.actions) && p.actions.length > 0 && p.decision?.decided_at) {
        p.actions[0].performed_at = p.decision.decided_at - 1000000;
      }
    },
  },
  {
    id: "p11_actions",
    target: "ACTION_ATTESTATIONS",
    fn: (p) => {
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
    },
  },
  {
    id: "p12_trace",
    target: "TRACE_BINDING",
    fn: (p) => {
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
    },
  },
  {
    id: "p13_receipt",
    target: "RECEIPT_BINDING",
    fn: (p) => {
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
        if ("sig_hex" in cpSig) {
          cpSig.sig_hex = corruptHex;
        }
      }
    },
  },
  {
    id: "p14_trust_floor",
    target: "TRUST_FLOOR",
    fn: (p) => {
      p.claimed_trust_floor = "COUNTERPARTY_SIGNED";
      p.decision = {
        ...p.decision,
        summary: "FORCED_UNVERIFIED: Manipulated summary forcing derived trust floor drop",
      };
    },
  },
];

let okCount = 0;
for (const pr of presets) {
  const p = JSON.parse(JSON.stringify(baselinePacket));
  const ctx = JSON.parse(baselineContext);
  pr.fn(p, ctx);
  try {
    const raw = wasm.verify_evidence_packet(JSON.stringify(p), JSON.stringify(ctx));
    const rep = JSON.parse(raw);
    const targetCheck = rep.checks.find((c) => c.rule === pr.target);
    const targetFailed = targetCheck && targetCheck.pass === false;
    console.log(
      `[PASS] ${pr.id} (${pr.target}): Deserialized OK | Target rule failed: ${targetFailed} (overall valid: ${rep.valid})`
    );
    if (targetFailed) okCount++;
  } catch (err) {
    console.error(`[FAIL] ${pr.id} (${pr.target}): Deserialization ERROR -> ${err.message || err}`);
  }
}
console.log(`\nResult: ${okCount}/14 presets successfully deserialized and triggered target rule failure!`);
