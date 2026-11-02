import { describe, it, expect } from "vitest";
import { meetCapabilityScopes, computeCascadeRevocations, STANDARD_SCOPES } from "../support/lattice_oracle.js";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import { validHonestCounterpartyPacket, DEFAULT_VERIFICATION_CONTEXT } from "../fixtures/evidence_packets.js";
import { CapabilityScope } from "../support/types.js";

describe("Tier 3 - Pipeline 3: Authority Matrix -> Lattice Attenuation -> Cascade Revocation", () => {
  it("P3.1: custom action configured in matrix attenuates correctly via meet operator", () => {
    const parentScope: CapabilityScope = {
      allowed: [
        { kind: "Standard", action: "Read" },
        { kind: "Standard", action: "Write" },
        { kind: "Custom", name: "credit:underwrite" },
      ],
      denied: [{ kind: "Standard", action: "Admin" }],
    };

    const requestedChildScope: CapabilityScope = {
      allowed: [
        { kind: "Standard", action: "Read" },
        { kind: "Custom", name: "credit:underwrite" },
      ],
      denied: [{ kind: "Standard", action: "Write" }],
    };

    const effective = meetCapabilityScopes(parentScope, requestedChildScope);
    expect(effective).not.toBeNull();
    expect(effective?.allowed.length).toBe(2);
    expect(effective?.denied.some((d) => d.kind === "Standard" && d.action === "Write")).toBe(true);
  });

  it("P3.2: revoking intermediate delegation hop propagates cascade entries through revocation log", () => {
    const rootJti = "root-jti-001";
    const hop1Jti = "hop-1-jti-002";
    const hop2Jti = "hop-2-jti-003";

    const tree = [
      { jti: rootJti, parent_jti: undefined },
      { jti: hop1Jti, parent_jti: rootJti },
      { jti: hop2Jti, parent_jti: hop1Jti },
    ];

    const revs = computeCascadeRevocations(hop1Jti, tree, "security-lead");
    expect(revs.length).toBe(2); // hop1 and hop2
    const revokedJtis = revs.map((r) => r.jti);
    expect(revokedJtis).toContain(hop1Jti);
    expect(revokedJtis).toContain(hop2Jti);
    expect(revokedJtis).not.toContain(rootJti);
  });

  it("P3.3: revoked token in delegation chain causes Rule 9 REVOCATION failure in engine", () => {
    const packet = JSON.parse(JSON.stringify(validHonestCounterpartyPacket));
    const targetHopJti = packet.delegation_chain[0].jti;

    const report = verifyEvidencePacketOracle(packet, {
      ...DEFAULT_VERIFICATION_CONTEXT,
      revoked_jtis: [targetHopJti],
    });

    const revCheck = report.checks.find((c) => c.rule === "REVOCATION");
    expect(revCheck?.pass).toBe(false);
    expect(revCheck?.detail).toContain(`revoked tokens in chain: hop_1 (${targetHopJti})`);
    expect(report.overall_valid).toBe(false);
  });

  it("P3.4: lattice meet with empty intersection (⊥) prevents invalid delegation creation", () => {
    const readerOnly = STANDARD_SCOPES.AUDIT_READER;
    const writeOnly = STANDARD_SCOPES.SUBMITTER;

    const illegalMeet = meetCapabilityScopes(readerOnly, writeOnly);
    expect(illegalMeet).toBeNull(); // ⊥ bottom
  });

  it("P3.5: cascade revocation leaves sibling delegation branches valid", () => {
    const tree = [
      { jti: "branch-root", parent_jti: undefined },
      { jti: "branch-a1", parent_jti: "branch-root" },
      { jti: "branch-b1", parent_jti: "branch-root" },
    ];

    const revs = computeCascadeRevocations("branch-a1", tree, "admin");
    const revokedSet = new Set(revs.map((r) => r.jti));

    expect(revokedSet.has("branch-a1")).toBe(true);
    expect(revokedSet.has("branch-b1")).toBe(false); // sibling remains safe
  });
});
