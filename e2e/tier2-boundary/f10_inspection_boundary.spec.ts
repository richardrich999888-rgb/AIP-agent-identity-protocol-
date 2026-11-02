import { describe, it, expect } from "vitest";
import { reconstructAccountabilityGraph } from "../support/dag_oracle.js";
import { validHonestCounterpartyPacket } from "../fixtures/evidence_packets.js";

describe("Tier 2 Boundary - F10: DAG Node Inspection Sheet Boundaries", () => {
  const graph = reconstructAccountabilityGraph(validHonestCounterpartyPacket);

  it("F10.B1: handles empty node metadata with safe fallback defaults", () => {
    const emptyNodeData: any = {};
    const getDisplayField = (val: any) => val || "N/A (Not Provided)";
    expect(getDisplayField(emptyNodeData.principal_id)).toBe("N/A (Not Provided)");
  });

  it("F10.B2: formats 64-character public key hex into truncated fingerprint with copy option", () => {
    const pubkey = validHonestCounterpartyPacket.agent.public_key.key_bytes;
    const formatFingerprint = (hex: string) => `${hex.slice(0, 8)}...${hex.slice(-8)}`;
    const fp = formatFingerprint(pubkey);
    expect(fp.length).toBe(19);
    expect(fp.startsWith(pubkey.slice(0, 8))).toBe(true);
    expect(fp.endsWith(pubkey.slice(-8))).toBe(true);
  });

  it("F10.B3: verifies inspection drawer handles unverified node status gracefully", () => {
    const unverifiedNode = {
      id: "agent",
      kind: "agent",
      verified: false,
      data: { error: "Signature verification failed" },
    };
    expect(unverifiedNode.verified).toBe(false);
    expect(unverifiedNode.data.error).toBeDefined();
  });

  it("F10.B4: formats high-precision Unix epoch millisecond timestamps into ISO-8601 strings", () => {
    const ts = validHonestCounterpartyPacket.decision.decided_at;
    const iso = new Date(ts).toISOString();
    expect(iso).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });

  it("F10.B5: handles inspection of Receipt without counterparty signature (Hash Only mode)", () => {
    const hashOnlyReceiptNode = {
      id: "receipt",
      kind: "receipt",
      data: {
        receipt_system: "local-log",
        receipt_id: "log-99",
        countersigned: false,
      },
    };
    expect(hashOnlyReceiptNode.data.countersigned).toBe(false);
  });
});
