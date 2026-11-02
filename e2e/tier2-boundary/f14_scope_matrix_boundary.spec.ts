import { describe, it, expect } from "vitest";
import { scopePermitsAction } from "../support/reference_oracle.js";
import { CapabilityScope } from "../support/types.js";

describe("Tier 2 Boundary - F14: Scope Matrix Editor Boundaries", () => {
  it("F14.B1: explicit deny takes absolute priority over allowed list for same action", () => {
    const conflictingScope: CapabilityScope = {
      allowed: [{ kind: "Standard", action: "Write" }],
      denied: [{ kind: "Standard", action: "Write" }], // Deny overrides allow
    };
    const permits = scopePermitsAction(conflictingScope, { kind: "Standard", action: "Write" });
    expect(permits).toBe(false);
  });

  it("F14.B2: empty allowed array yields zero permitted actions", () => {
    const emptyScope: CapabilityScope = {
      allowed: [],
      denied: [],
    };
    expect(scopePermitsAction(emptyScope, { kind: "Standard", action: "Read" })).toBe(false);
    expect(scopePermitsAction(emptyScope, { kind: "Standard", action: "Write" })).toBe(false);
  });

  it("F14.B3: custom action names with slashes, colons, and hyphens supported", () => {
    const complexScope: CapabilityScope = {
      allowed: [{ kind: "Custom", name: "ledger/treasury:transfer-wire_v2" }],
      denied: [],
    };
    expect(scopePermitsAction(complexScope, { kind: "Custom", name: "ledger/treasury:transfer-wire_v2" })).toBe(true);
    expect(scopePermitsAction(complexScope, { kind: "Custom", name: "ledger/treasury:transfer-wire_v1" })).toBe(false);
  });

  it("F14.B4: case sensitivity enforced strictly on action verbs", () => {
    const scope: CapabilityScope = {
      allowed: [{ kind: "Custom", name: "loan:approve" }],
      denied: [],
    };
    expect(scopePermitsAction(scope, { kind: "Custom", name: "LOAN:APPROVE" })).toBe(false);
    expect(scopePermitsAction(scope, { kind: "Custom", name: "Loan:Approve" })).toBe(false);
  });

  it("F14.B5: Admin standard action grants all standard verbs when not explicitly denied", () => {
    const adminScope: CapabilityScope = {
      allowed: [{ kind: "Standard", action: "Admin" }],
      denied: [{ kind: "Standard", action: "Delete" }], // explicitly denied
    };
    expect(scopePermitsAction(adminScope, { kind: "Standard", action: "Read" })).toBe(true);
    expect(scopePermitsAction(adminScope, { kind: "Standard", action: "Write" })).toBe(true);
    expect(scopePermitsAction(adminScope, { kind: "Standard", action: "Delete" })).toBe(false);
  });
});
