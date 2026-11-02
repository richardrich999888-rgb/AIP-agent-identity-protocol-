import { EvidencePacket, VerificationContext } from "../support/types.js";
import { recomputePacketHash, sha256Hex } from "../support/reference_oracle.js";

export const TEST_ISSUER_KEY = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
export const TEST_AGENT_KEY = "e2c39d7373b9e4a81907e4d8a1c92bc44369e3a648b2eb594b2a8d11c43b8117";
export const TEST_COUNTERPARTY_KEY = "4a18e9d3b45a6c729e81b654f128c734091a2e557b32c6d48291f03847261a9c";

export const DEFAULT_VERIFICATION_CONTEXT: VerificationContext = {
  issuer_public_keys: {
    "cro-principal-001": TEST_ISSUER_KEY,
    "treasury-vp-002": TEST_ISSUER_KEY,
  },
  counterparty_public_keys: {
    "core-banking-gateway": TEST_COUNTERPARTY_KEY,
  },
  revoked_jtis: [],
};

/**
 * Base valid packet factory
 */
export function createBasePacket(): EvidencePacket {
  const packet: EvidencePacket = {
    magic: [0x41, 0x45, 0x50, 0x31], // "AEP1"
    version: 1,
    packet_hash: "", // computed below
    agent_sig: {
      signer_id: "aip12x9K8yM4QvB7eR6tP3sW1uZbAcD5fGhJ7",
      algorithm: "Ed25519",
      signature_bytes: "9f8e7d6c5b4a392817061524334251607f8e9d0c1b2a394857667584930211aa",
      payload_hash: "",
      signed_at: 1772528400000,
    },
    claimed_trust_floor: "COUNTERPARTY_SIGNED",
    agent: {
      aip_id: "aip12x9K8yM4QvB7eR6tP3sW1uZbAcD5fGhJ7",
      public_key: {
        algorithm: "Ed25519",
        key_bytes: TEST_AGENT_KEY,
      },
      provenance: {
        model_hash: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
        environment_hash: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        toolchain_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
    },
    root_authority: {
      principal_id: "cro-principal-001",
      display_role: "Chief Risk Officer",
      root_token: {
        jti: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        issuer_id: "cro-principal-001",
        agent_id: "treasury-vp-002",
        scope: {
          allowed: [
            { kind: "Standard", action: "Read" },
            { kind: "Standard", action: "Write" },
            { kind: "Standard", action: "Execute" },
            { kind: "Standard", action: "Delegate" },
            { kind: "Custom", name: "loan:approve" },
          ],
          denied: [{ kind: "Standard", action: "Admin" }],
        },
        issued_at: 1772520000000,
        expires_at: 1772534400000,
        issuer_sig: {
          signer_id: "cro-principal-001",
          algorithm: "Ed25519",
          signature_bytes: "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
          payload_hash: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
          signed_at: 1772520000000,
        },
      },
    },
    delegation_chain: [
      {
        jti: "b2c3d4e5f6a10718293a4b5c6d7e8f91",
        parent_jti: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        issuer_id: "treasury-vp-002",
        grantee_id: "aip12x9K8yM4QvB7eR6tP3sW1uZbAcD5fGhJ7",
        depth: 1,
        scope: {
          allowed: [
            { kind: "Standard", action: "Read" },
            { kind: "Standard", action: "Write" },
            { kind: "Custom", name: "loan:approve" },
          ],
          denied: [
            { kind: "Standard", action: "Admin" },
            { kind: "Standard", action: "Delegate" },
          ],
        },
        issued_at: 1772523600000,
        expires_at: 1772530800000,
        issuer_sig: {
          signer_id: "treasury-vp-002",
          algorithm: "Ed25519",
          signature_bytes: "223344556677889900aabbccddeeff11223344556677889900aabbccddeeff22",
          payload_hash: "b2c3d4e5f6a10718293a4b5c6d7e8f91",
          signed_at: 1772523600000,
        },
      },
    ],
    decision: {
      decision_id: "d001-loan-approval-acme-corp",
      action_kind: { kind: "Custom", name: "loan:approve" },
      summary: "Approve commercial credit facility of $5,000,000 for Acme Corp",
      input_hash: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
      rationale_hash: "18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
      decided_at: 1772527200000,
    },
    actions: [
      {
        action_id: "act-001-transfer",
        action_kind: { kind: "Standard", action: "Write" },
        description: "Disburse tranche A of $2,500,000 via Fedwire",
        payload_hash: "3b918f4a72d3e9198642a42095b6a7824b2f5cd61e3d7890a1bc45ef20394812",
        performed_at: 1772527800000,
        agent_sig: {
          signer_id: "aip12x9K8yM4QvB7eR6tP3sW1uZbAcD5fGhJ7",
          algorithm: "Ed25519",
          signature_bytes: "3344556677889900aabbccddeeff11223344556677889900aabbccddeeff3344",
          payload_hash: "3b918f4a72d3e9198642a42095b6a7824b2f5cd61e3d7890a1bc45ef20394812",
          signed_at: 1772527800000,
        },
      },
    ],
    trace_binding: {
      trace_id: "trace-tx-9948271a",
      trace_hash: sha256Hex("trace-execution-data-log-payload-001"),
    },
    receipt_binding: {
      receipt_system: "core-banking-gateway",
      receipt_id: "rcpt-wire-5590214",
      receipt_hash: sha256Hex("receipt-core-banking-confirmed-transfer-wire-001"),
      counterparty_id: "core-banking-gateway",
      counterparty_sig: {
        signer_id: "core-banking-gateway",
        algorithm: "Ed25519",
        signature_bytes: "44556677889900aabbccddeeff11223344556677889900aabbccddeeff445566",
        payload_hash: sha256Hex("receipt-core-banking-confirmed-transfer-wire-001"),
        signed_at: 1772528000000,
      },
    },
  };

  const hash = recomputePacketHash(packet);
  packet.packet_hash = hash;
  packet.agent_sig.payload_hash = hash;
  return packet;
}

/**
 * Fixture: Fully valid CounterpartySigned EvidencePacket
 */
export const validHonestCounterpartyPacket: EvidencePacket = createBasePacket();

/**
 * Fixture: Valid AuthorityBound EvidencePacket (no counterparty countersignature)
 */
export function createAuthorityBoundPacket(): EvidencePacket {
  const p = createBasePacket();
  p.claimed_trust_floor = "AUTHORITY_BOUND";
  p.receipt_binding = {
    receipt_system: "internal-accounting-db",
    receipt_id: "ledger-entry-88391",
    receipt_hash: sha256Hex("internal-ledger-record"),
  };
  const hash = recomputePacketHash(p);
  p.packet_hash = hash;
  p.agent_sig.payload_hash = hash;
  return p;
}

/**
 * Fixture: Valid AgentSigned EvidencePacket (no root authority / delegation)
 */
export function createAgentSignedPacket(): EvidencePacket {
  const p = createBasePacket();
  p.claimed_trust_floor = "AGENT_SIGNED";
  p.root_authority.root_token.agent_id = "other-party-99"; // broken authority chain
  p.delegation_chain = [];
  delete p.receipt_binding;
  delete p.trace_binding;
  const hash = recomputePacketHash(p);
  p.packet_hash = hash;
  p.agent_sig.payload_hash = hash;
  return p;
}

/**
 * Fixture: Tampered summary (modifies decision summary without recomputing hash)
 */
export function createTamperedSummaryPacket(): EvidencePacket {
  const p = createBasePacket();
  p.decision.summary = "TAMPERED: Approve commercial credit facility of $500,000,000 for Attacker Corp";
  return p;
}

/**
 * Fixture: Smart Attacker (tampered summary + recomputed packet_hash, but agent_sig invalid)
 */
export function createTamperedHashPacket(): EvidencePacket {
  const p = createBasePacket();
  p.decision.summary = "TAMPERED: Approve commercial credit facility of $500,000,000 for Attacker Corp";
  p.packet_hash = recomputePacketHash(p); // Attacker recalculated packet_hash!
  return p;
}

/**
 * Fixture: Tampered agent signature bytes
 */
export function createTamperedSignaturePacket(): EvidencePacket {
  const p = createBasePacket();
  p.agent_sig.signature_bytes = "corrupted_signature_payload_bad_hex_bytes";
  return p;
}

/**
 * Fixture: Scope escalation (delegation hop expands scope beyond parent)
 */
export function createScopeEscalationPacket(): EvidencePacket {
  const p = createBasePacket();
  p.delegation_chain[0].scope.allowed.push({ kind: "Standard", action: "Admin" });
  const hash = recomputePacketHash(p);
  p.packet_hash = hash;
  p.agent_sig.payload_hash = hash;
  return p;
}

/**
 * Fixture: Revoked token in authority chain
 */
export function createRevokedTokenPacket(): EvidencePacket {
  const p = createBasePacket();
  return p; // Revocation is tested by adding p.delegation_chain[0].jti to context.revoked_jtis
}

/**
 * Fixture: Temporal violation (action performed before decision)
 */
export function createTemporalViolationPacket(): EvidencePacket {
  const p = createBasePacket();
  p.actions[0].performed_at = p.decision.decided_at - 10000;
  const hash = recomputePacketHash(p);
  p.packet_hash = hash;
  p.agent_sig.payload_hash = hash;
  return p;
}

/**
 * Fixture: Broken authority handoff
 */
export function createBrokenHandoffPacket(): EvidencePacket {
  const p = createBasePacket();
  p.delegation_chain[0].grantee_id = "unexpected-middleman";
  const hash = recomputePacketHash(p);
  p.packet_hash = hash;
  p.agent_sig.payload_hash = hash;
  return p;
}
