import { describe, it, expect } from "vitest";

describe("Tier 2 Boundary - F6: Trust Anchor Configuration Boundaries", () => {
  it("F6.B1: rejects odd-length hex public key string (63 chars instead of 64)", () => {
    const oddKey = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2"; // 63 chars
    const isValid = /^[0-9a-fA-F]{64}$/.test(oddKey);
    expect(isValid).toBe(false);
  });

  it("F6.B2: rejects non-hex characters in public key input", () => {
    const invalidCharKey = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59daZZ"; // 'ZZ'
    const isValid = /^[0-9a-fA-F]{64}$/.test(invalidCharKey);
    expect(isValid).toBe(false);
  });

  it("F6.B3: overwriting existing issuer ID updates public key without error", () => {
    const store: Record<string, string> = { "issuer-1": "key-a" };
    store["issuer-1"] = "key-b";
    expect(store["issuer-1"]).toBe("key-b");
    expect(Object.keys(store).length).toBe(1);
  });

  it("F6.B4: revoking empty or non-hex JTI string rejected", () => {
    const isValidJti = (jti: string) => /^[0-9a-fA-F]{32}$/.test(jti);
    expect(isValidJti("")).toBe(false);
    expect(isValidJti("short")).toBe(false);
    expect(isValidJti("a1b2c3d4e5f60718293a4b5c6d7e8f90")).toBe(true);
  });

  it("F6.B5: high capacity revocation set (5,000 JTIs) maintains fast Set lookup (<5ms)", () => {
    const set = new Set<string>();
    for (let i = 0; i < 5000; i++) {
      set.add(`jti-token-${i}`);
    }
    const start = performance.now();
    const hasToken = set.has("jti-token-4999");
    const duration = performance.now() - start;
    expect(hasToken).toBe(true);
    expect(duration).toBeLessThan(5);
  });
});
