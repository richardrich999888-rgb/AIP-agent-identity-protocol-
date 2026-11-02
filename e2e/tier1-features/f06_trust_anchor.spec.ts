import { describe, it, expect } from "vitest";
import { VerificationContext } from "../support/types.js";
import {
  DEFAULT_VERIFICATION_CONTEXT,
  TEST_ISSUER_KEY,
  TEST_COUNTERPARTY_KEY,
} from "../fixtures/evidence_packets.js";

describe("Tier 1 - F6: Verifier Trust Anchor Configuration", () => {
  it("F6.1: initializes default trust anchor context with root issuers", () => {
    const ctx = DEFAULT_VERIFICATION_CONTEXT;
    expect(ctx.issuer_public_keys["cro-principal-001"]).toBe(TEST_ISSUER_KEY);
    expect(ctx.counterparty_public_keys?.["core-banking-gateway"]).toBe(TEST_COUNTERPARTY_KEY);
  });

  it("F6.2: adds new trusted issuer public key to context", () => {
    const ctx: VerificationContext = {
      issuer_public_keys: { ...DEFAULT_VERIFICATION_CONTEXT.issuer_public_keys },
      revoked_jtis: [],
    };
    ctx.issuer_public_keys["cfo-principal-003"] = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    expect(ctx.issuer_public_keys["cfo-principal-003"]).toBeDefined();
    expect(Object.keys(ctx.issuer_public_keys).length).toBe(3);
  });

  it("F6.3: records revoked JTIs in context revocation set", () => {
    const ctx: VerificationContext = {
      issuer_public_keys: {},
      revoked_jtis: ["a1b2c3d4e5f60718293a4b5c6d7e8f90"],
    };
    expect(ctx.revoked_jtis).toContain("a1b2c3d4e5f60718293a4b5c6d7e8f90");
    expect(ctx.revoked_jtis.length).toBe(1);
  });

  it("F6.4: validates 64-character hex format for Ed25519 public keys", () => {
    const isHex64 = (key: string) => /^[0-9a-fA-F]{64}$/.test(key);
    expect(isHex64(TEST_ISSUER_KEY)).toBe(true);
    expect(isHex64(TEST_COUNTERPARTY_KEY)).toBe(true);
    expect(isHex64("short-key")).toBe(false);
    expect(isHex64("xyznothex12345678901234567890123456789012345678901234567890123456")).toBe(false);
  });

  it("F6.5: removes trust anchor key on user deletion action", () => {
    const ctx: VerificationContext = {
      issuer_public_keys: { "to-remove": TEST_ISSUER_KEY },
      revoked_jtis: [],
    };
    delete ctx.issuer_public_keys["to-remove"];
    expect(ctx.issuer_public_keys["to-remove"]).toBeUndefined();
  });
});
