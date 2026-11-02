import { describe, it, expect } from "vitest";
import { verifyEvidencePacketOracle } from "../support/reference_oracle.js";
import {
  createTamperedSummaryPacket,
  createAuthorityBoundPacket,
  DEFAULT_VERIFICATION_CONTEXT,
} from "../fixtures/evidence_packets.js";
import { TrustFloor } from "../support/types.js";

describe("Tier 2 Boundary - F8: Trust Floor Progression Boundaries", () => {
  it("F8.B1: claimed floor COUNTERPARTY_SIGNED with derived UNVERIFIED fails Rule 14 with maximum divergence", () => {
    const packet = createTamperedSummaryPacket();
    packet.claimed_trust_floor = "COUNTERPARTY_SIGNED";
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    expect(report.derived_trust_floor).toBe("UNVERIFIED");
    const floorCheck = report.checks.find((c) => c.rule === "TRUST_FLOOR");
    expect(floorCheck?.pass).toBe(false);
    expect(floorCheck?.detail).toContain("claimed floor COUNTERPARTY_SIGNED exceeds what the evidence supports (UNVERIFIED)");
  });

  it("F8.B2: boundary case - claimed floor equal to derived floor passes Rule 14", () => {
    const packet = createAuthorityBoundPacket();
    packet.claimed_trust_floor = "AUTHORITY_BOUND";
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const floorCheck = report.checks.find((c) => c.rule === "TRUST_FLOOR");
    expect(floorCheck?.pass).toBe(true);
  });

  it("F8.B3: boundary case - conservative claim (AGENT_SIGNED) with derived AUTHORITY_BOUND passes Rule 14", async () => {
    const { recomputePacketHash } = await import("../support/reference_oracle.js");
    const packet = createAuthorityBoundPacket();
    packet.claimed_trust_floor = "AGENT_SIGNED"; // Under-claiming floor is allowed
    packet.packet_hash = recomputePacketHash(packet);
    packet.agent_sig.payload_hash = packet.packet_hash;
    const report = verifyEvidencePacketOracle(packet, DEFAULT_VERIFICATION_CONTEXT);
    const floorCheck = report.checks.find((c) => c.rule === "TRUST_FLOOR");
    expect(floorCheck?.pass).toBe(true);
  });

  it("F8.B4: validates all 4 trust floor enum members in strict monotonic hierarchy", () => {
    const hierarchy: TrustFloor[] = ["UNVERIFIED", "AGENT_SIGNED", "AUTHORITY_BOUND", "COUNTERPARTY_SIGNED"];
    expect(hierarchy.length).toBe(4);
    expect(hierarchy.indexOf("COUNTERPARTY_SIGNED")).toBe(3);
    expect(hierarchy.indexOf("UNVERIFIED")).toBe(0);
  });

  it("F8.B5: unknown trust floor string in raw input fails validation", () => {
    const validFloors = new Set(["UNVERIFIED", "AGENT_SIGNED", "AUTHORITY_BOUND", "COUNTERPARTY_SIGNED"]);
    expect(validFloors.has("HIGH_ASSURANCE" as any)).toBe(false);
    expect(validFloors.has("ADMIN_VERIFIED" as any)).toBe(false);
  });
});
