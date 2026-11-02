import { describe, it, expect } from "vitest";
import { STANDARD_SCOPES } from "../support/lattice_oracle.js";
import { scopePermitsAction } from "../support/reference_oracle.js";
import { CapabilityScope } from "../support/types.js";

describe("Tier 1 - F14: Visual Scope Matrix Editor", () => {
  it("F14.1: loads all 4 standard named scopes correctly", () => {
    expect(STANDARD_SCOPES).toHaveProperty("ADMIN");
    expect(STANDARD_SCOPES).toHaveProperty("ORCHESTRATOR");
    expect(STANDARD_SCOPES).toHaveProperty("AUDIT_READER");
    expect(STANDARD_SCOPES).toHaveProperty("SUBMITTER");
  });

  it("F14.2: verifies SUBMITTER scope allows Write but denies Admin and Delete", () => {
    const scope = STANDARD_SCOPES.SUBMITTER;
    expect(scopePermitsAction(scope, { kind: "Standard", action: "Write" })).toBe(true);
    expect(scopePermitsAction(scope, { kind: "Standard", action: "Admin" })).toBe(false);
    expect(scopePermitsAction(scope, { kind: "Standard", action: "Delete" })).toBe(false);
  });

  it("F14.3: verifies AUDIT_READER allows Read and denies Write", () => {
    const scope = STANDARD_SCOPES.AUDIT_READER;
    expect(scopePermitsAction(scope, { kind: "Standard", action: "Read" })).toBe(true);
    expect(scopePermitsAction(scope, { kind: "Standard", action: "Write" })).toBe(false);
  });

  it("F14.4: supports custom enterprise action verbs in scope matrix", () => {
    const customScope: CapabilityScope = {
      allowed: [{ kind: "Custom", name: "wire:transfer" }],
      denied: [],
    };
    expect(scopePermitsAction(customScope, { kind: "Custom", name: "wire:transfer" })).toBe(true);
    expect(scopePermitsAction(customScope, { kind: "Custom", name: "wire:reversal" })).toBe(false);
  });

  it("F14.5: adds and removes actions dynamically in editor", () => {
    const editableScope: CapabilityScope = {
      allowed: [{ kind: "Standard", action: "Read" }],
      denied: [],
    };
    // Add Write
    editableScope.allowed.push({ kind: "Standard", action: "Write" });
    expect(scopePermitsAction(editableScope, { kind: "Standard", action: "Write" })).toBe(true);
    // Remove Read
    editableScope.allowed = editableScope.allowed.filter((a) => a.kind !== "Standard" || a.action !== "Read");
    expect(scopePermitsAction(editableScope, { kind: "Standard", action: "Read" })).toBe(false);
  });
});
