import type { RuleIdentifier, RuleLayer } from "@/types/verification";

export interface AttackPreset {
  id: string;
  index: number;
  name: string;
  targetRule: RuleIdentifier;
  category: RuleLayer;
  description: string;
  mutationExplanation: string;
  mutate: (
    packet: any,
    context?: any
  ) => {
    packet: any;
    context?: any;
  };
}

export const ATTACK_PRESETS: AttackPreset[] = [
  {
    id: "p01_structure",
    index: 1,
    name: "Malformed Wire Format Header",
    targetRule: "STRUCTURE",
    category: "INTEGRITY",
    description: "Corrupts protocol magic header bytes from 'AEP1' to 'BAD1' and sets invalid version 99.",
    mutationExplanation: "Sets packet.magic = [0x42, 0x41, 0x44, 0x31] ('BAD1') and packet.version = 99.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      p.magic = [0x42, 0x41, 0x44, 0x31]; // "BAD1"
      p.version = 99;
      return { packet: p, context };
    },
  },
  {
    id: "p02_agent_id",
    index: 2,
    name: "Agent Identity Hijacking",
    targetRule: "AGENT_ID_BINDING",
    category: "INTEGRITY",
    description: "Replaces the acting agent's AIP-ID with an unregistered foreign identifier.",
    mutationExplanation: "Sets packet.agent.aip_id = 'aip1mismatchidentity99887766554433221122'.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      p.agent = {
        ...p.agent,
        aip_id: "aip1mismatchidentity99887766554433221122",
      };
      return { packet: p, context };
    },
  },
  {
    id: "p03_canonical_hash",
    index: 3,
    name: "Decision Summary Tampering",
    targetRule: "CANONICAL_HASH",
    category: "INTEGRITY",
    description: "Modifies the decision summary text without recalculating canonical hash, simulating in-flight payload alteration.",
    mutationExplanation: "Sets packet.decision.summary = 'TAMPERED: Divert $5,000,000 to offshore unauthorized facility'.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      p.decision = {
        ...p.decision,
        summary: "TAMPERED: Divert $5,000,000 to offshore unauthorized facility",
      };
      return { packet: p, context };
    },
  },
  {
    id: "p04_agent_sig",
    index: 4,
    name: "Agent Signature Corruption",
    targetRule: "AGENT_SIGNATURE",
    category: "INTEGRITY",
    description: "Corrupts the agent's Ed25519 signature bytes over the sealed packet.",
    mutationExplanation: "Flips bits in packet.agent_sig.signature_bytes or assigns corrupted hex string.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
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
      return { packet: p, context };
    },
  },
  {
    id: "p05_root_sig",
    index: 5,
    name: "Root Authority Token Forgery",
    targetRule: "ROOT_TOKEN_SIGNATURE",
    category: "AUTHORITY",
    description: "Mutates the principal root authority issuer signature, simulating a forged root grant.",
    mutationExplanation: "Flips bits in packet.root_authority.root_token.issuer_sig.signature_bytes or assigns corrupted hex string.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
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
      return { packet: p, context };
    },
  },
  {
    id: "p06_delegation",
    index: 6,
    name: "Scope Escalation Attack",
    targetRule: "DELEGATION_CHAIN",
    category: "AUTHORITY",
    description: "Injects forbidden 'Admin' permission into delegation hop scope, violating monotonic attenuation.",
    mutationExplanation: "Appends { Standard: 'Admin' } to delegation_chain[0].scope.allowed.",
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
    index: 7,
    name: "Broken Authority Chain Handoff",
    targetRule: "AUTHORITY_CHAIN",
    category: "AUTHORITY",
    description: "Modifies downstream delegation grantee ID to an unknown middleman, breaking cryptographic continuity to the acting agent.",
    mutationExplanation: "Sets packet.delegation_chain[last].grantee_id = 'unexpected-middleman-agent'.",
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
    index: 8,
    name: "Unpermitted Action Execution",
    targetRule: "SCOPE_AUTHORITY",
    category: "AUTHORITY",
    description: "Appends an ungranted custom action verb outside the effective capability lattice scope.",
    mutationExplanation: "Appends action with action_kind { Custom: 'unpermitted:action_divert' } outside effective scope.",
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
    index: 9,
    name: "Revoked Credential Injection",
    targetRule: "REVOCATION",
    category: "AUTHORITY",
    description: "Injects delegation token JTI into verifier revocation blacklist, simulating an operational revocation event.",
    mutationExplanation: "Adds delegation token JTI to context.revoked_jtis and context.revoked_token_ids.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      const ctx = context ? JSON.parse(JSON.stringify(context)) : {};
      const targetJti =
        p.delegation_chain?.[0]?.jti ||
        p.root_authority?.root_token?.jti ||
        "a1b2c3d4e5f60718293a4b5c6d7e8f90";

      const currentJtis = Array.isArray(ctx.revoked_jtis) ? ctx.revoked_jtis : [];
      ctx.revoked_jtis = [...currentJtis, targetJti];
      ctx.revoked_token_ids = ctx.revoked_jtis;
      return { packet: p, context: ctx };
    },
  },
  {
    id: "p10_temporal",
    index: 10,
    name: "Inverted Timestamp Fraud",
    targetRule: "TEMPORAL_VALIDITY",
    category: "VALIDITY",
    description: "Sets an action execution timestamp prior to the authorizing decision timestamp, proving causality fraud.",
    mutationExplanation: "Sets actions[0].performed_at = decision.decided_at - 1000000 ms.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
      if (Array.isArray(p.actions) && p.actions.length > 0 && p.decision?.decided_at) {
        p.actions[0].performed_at = p.decision.decided_at - 1000000;
      } else if (p.decision?.decided_at) {
        p.decision.decided_at = (p.root_authority?.root_token?.issued_at || 1000000) - 500000;
      }
      return { packet: p, context };
    },
  },
  {
    id: "p11_actions",
    index: 11,
    name: "Action Payload Mutation",
    targetRule: "ACTION_ATTESTATIONS",
    category: "VALIDITY",
    description: "Modifies an action's attested payload hash without updating its cryptographic signature.",
    mutationExplanation: "Flips bits in actions[0].payload_hash or assigns corrupted hex string.",
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
    index: 12,
    name: "Distributed Trace Spoofing",
    targetRule: "TRACE_BINDING",
    category: "VALIDITY",
    description: "Alters the SHA-256 trace commitment hash bound to distributed telemetry.",
    mutationExplanation: "Flips bits in packet.trace_binding.trace_hash or assigns corrupted hex string.",
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
    index: 13,
    name: "Counterparty Signature Corruption",
    targetRule: "RECEIPT_BINDING",
    category: "BILATERAL",
    description: "Corrupts the external bilateral countersignature bytes on the execution receipt.",
    mutationExplanation: "Flips bits in packet.receipt_binding.counterparty_sig.signature_bytes or assigns corrupted hex string.",
    mutate: (packet, context) => {
      const p = JSON.parse(JSON.stringify(packet));
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
      return { packet: p, context };
    },
  },
  {
    id: "p14_trust_floor",
    index: 14,
    name: "Trust Floor Claim Inflation",
    targetRule: "TRUST_FLOOR",
    category: "INTEGRITY",
    description: "Mutates packet fields dropping the engine-derived floor to UNVERIFIED while keeping claimed_trust_floor at COUNTERPARTY_SIGNED.",
    mutationExplanation: "Sets claimed_trust_floor = 'COUNTERPARTY_SIGNED' while altering decision summary to invalidate cryptographic floor.",
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
