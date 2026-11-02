import { describe, it, expect } from "vitest";
import { computeCascadeRevocations } from "../support/lattice_oracle.js";

describe("Tier 2 Boundary - F16: Cascade Revocation Tree Boundaries", () => {
  const tree = [
    { jti: "root-jti", parent_jti: undefined },
    { jti: "hop-1-jti", parent_jti: "root-jti" },
    { jti: "hop-2-jti", parent_jti: "hop-1-jti" },
    { jti: "hop-3-jti", parent_jti: "hop-2-jti" },
  ];

  it("F16.B1: revoking leaf token produces exactly 1 revocation entry (0 descendants)", () => {
    const revs = computeCascadeRevocations("hop-3-jti", tree, "operator");
    expect(revs.length).toBe(1);
    expect(revs[0].jti).toBe("hop-3-jti");
    expect(revs[0].reason).toBe("Compromise");
  });

  it("F16.B2: revoking deep chain (depth 4) traverses all linear descendants in BFS order", () => {
    const revs = computeCascadeRevocations("hop-1-jti", tree, "operator");
    expect(revs.length).toBe(3); // hop-1, hop-2, hop-3
    const order = revs.map((r) => r.jti);
    expect(order).toEqual(["hop-1-jti", "hop-2-jti", "hop-3-jti"]);
  });

  it("F16.B3: querying non-existent JTI produces single entry and terminates cleanly", () => {
    const revs = computeCascadeRevocations("non-existent-token-jti", tree, "operator");
    expect(revs.length).toBe(1);
    expect(revs[0].jti).toBe("non-existent-token-jti");
  });

  it("F16.B4: wide branching tree (1 parent with 10 child tokens) cascades to all 10 children", () => {
    const wideTree: { jti: string; parent_jti?: string }[] = [{ jti: "wide-root", parent_jti: undefined }];
    for (let i = 0; i < 10; i++) {
      wideTree.push({ jti: `child-${i}`, parent_jti: "wide-root" });
    }
    const revs = computeCascadeRevocations("wide-root", wideTree, "admin");
    expect(revs.length).toBe(11);
  });

  it("F16.B5: all cascaded entries retain valid timestamp within current test invocation", () => {
    const now = Date.now();
    const revs = computeCascadeRevocations("root-jti", tree, "admin");
    for (const entry of revs) {
      expect(entry.revoked_at).toBeGreaterThanOrEqual(now - 1000);
      expect(entry.revoked_at).toBeLessThanOrEqual(Date.now() + 1000);
    }
  });
});
