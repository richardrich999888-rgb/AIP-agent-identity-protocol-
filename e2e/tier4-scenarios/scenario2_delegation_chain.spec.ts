import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle, recomputePacketHash } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";
import { DelegationToken } from "../support/types.js";

describe("Tier 4 - Scenario 2: Multi-Hop Autonomous Agent Delegation Chain", () => {
  function createMultiHopPacket(hopCount: number) {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    packet.delegation_chain = [];

    let prevJti = packet.root_authority.root_token.jti;
    let prevGrantee = packet.root_authority.root_token.agent_id; // "treasury-vp-002"

    for (let depth = 1; depth <= hopCount; depth++) {
      const hopJti = `jti-hop-00${depth}-` + "a".repeat(20);
      const isLast = depth === hopCount;
      const granteeId = isLast ? packet.agent.aip_id : `intermediate-agent-${depth}`;

      const hop: DelegationToken = {
        jti: hopJti,
        parent_jti: prevJti,
        issuer_id: prevGrantee,
        grantee_id: granteeId,
        depth: depth,
        scope: {
          allowed: [
            { kind: "Standard", action: "Read" },
            { kind: "Standard", action: "Write" },
            { kind: "Custom", name: "loan:approve" },
          ],
          denied: [{ kind: "Standard", action: "Admin" }],
        },
        issued_at: packet.root_authority.root_token.issued_at + depth * 1000,
        expires_at: packet.root_authority.root_token.expires_at,
        issuer_sig: {
          signer_id: prevGrantee,
          algorithm: "Ed25519",
          signature_bytes: "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
          payload_hash: hopJti,
          signed_at: packet.root_authority.root_token.issued_at + depth * 1000,
        },
      };

      packet.delegation_chain.push(hop);
      prevJti = hopJti;
      prevGrantee = granteeId;
    }

    const hash = recomputePacketHash(packet);
    packet.packet_hash = hash;
    packet.agent_sig.payload_hash = hash;
    return packet;
  }

  it("S2.1: executes clean 4-tier delegation chain from Principal to leaf Agent", () => {
    const packet = createMultiHopPacket(4);
    expect(packet.delegation_chain.length).toBe(4);
    expect(packet.delegation_chain[3].grantee_id).toBe(packet.agent.aip_id);
  });

  it("S2.2: verifies strict parent JTI linkage across all hops", () => {
    const packet = createMultiHopPacket(4);
    let expectedParent = packet.root_authority.root_token.jti;
    for (const hop of packet.delegation_chain) {
      expect(hop.parent_jti).toBe(expectedParent);
      expectedParent = hop.jti;
    }
  });

  it("S2.3: verifies depth monotonicity constraint (d_i = d_{i-1} + 1)", () => {
    const packet = createMultiHopPacket(4);
    packet.delegation_chain.forEach((hop: DelegationToken, i: number) => {
      expect(hop.depth).toBe(i + 1);
    });
  });

  it("S2.4: engine validates multi-hop chain without error", () => {
    const packet = createMultiHopPacket(4);
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const delCheck = report.checks.find((c) => c.rule === "DELEGATION_CHAIN");
    expect(delCheck?.pass).toBe(true);
    expect(delCheck?.detail).toContain("4-hop delegation chain verified");
  });

  it("S2.5: enforces maximum delegation depth ceiling (depth >= 8 rejected)", () => {
    const deepPacket = createMultiHopPacket(8);
    const report = verifyEvidencePacketOracle(deepPacket, DEFAULT_VERIFICATION_CONTEXT);
    const delCheck = report.checks.find((c) => c.rule === "DELEGATION_CHAIN");
    expect(delCheck?.pass).toBe(false);
    expect(delCheck?.detail).toContain("depth exceeds maximum");
  });
});
