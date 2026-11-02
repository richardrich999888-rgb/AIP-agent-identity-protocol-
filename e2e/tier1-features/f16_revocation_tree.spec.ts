import { describe, it, expect } from "vitest";
import { computeCascadeRevocations } from "../support/lattice_oracle.js";

describe("Tier 1 - F16: Cascade Revocation Tree", () => {
  const delegationTree = [
    { jti: "token-root", parent_jti: undefined },
    { jti: "token-hop-1a", parent_jti: "token-root" },
    { jti: "token-hop-2a", parent_jti: "token-hop-1a" },
    { jti: "token-hop-1b", parent_jti: "token-root" },
    { jti: "token-hop-2b", parent_jti: "token-hop-1b" },
  ];

  it("F16.1: revokes primary token and records primary Compromise reason", () => {
    const revocations = computeCascadeRevocations("token-hop-1a", delegationTree, "security-admin");
    const primary = revocations.find((r) => r.jti === "token-hop-1a");
    expect(primary).toBeDefined();
    expect(primary?.reason).toBe("Compromise");
    expect(primary?.revoked_by).toBe("security-admin");
  });

  it("F16.2: cascades revocation recursively down child subtree", () => {
    const revocations = computeCascadeRevocations("token-hop-1a", delegationTree, "security-admin");
    const child = revocations.find((r) => r.jti === "token-hop-2a");
    expect(child).toBeDefined();
    expect(child?.reason).toBe("AdminRevocation");
  });

  it("F16.3: leaves independent sibling branches unaffected", () => {
    const revocations = computeCascadeRevocations("token-hop-1a", delegationTree, "security-admin");
    const revokedJtis = revocations.map((r) => r.jti);
    expect(revokedJtis).not.toContain("token-hop-1b");
    expect(revokedJtis).not.toContain("token-hop-2b");
    expect(revokedJtis).not.toContain("token-root");
  });

  it("F16.4: root revocation invalidates entire organization delegation tree", () => {
    const revocations = computeCascadeRevocations("token-root", delegationTree, "security-admin");
    expect(revocations.length).toBe(5);
    const jtis = revocations.map((r) => r.jti);
    expect(jtis).toEqual(expect.arrayContaining(["token-root", "token-hop-1a", "token-hop-2a", "token-hop-1b", "token-hop-2b"]));
  });

  it("F16.5: produces timestamped revocation entries with cascade flag true", () => {
    const revocations = computeCascadeRevocations("token-hop-1a", delegationTree, "admin");
    for (const entry of revocations) {
      expect(entry.cascade).toBe(true);
      expect(entry.revoked_at).toBeGreaterThan(0);
    }
  });
});
