import { describe, it, expect } from "vitest";
import { meetCapabilityScopes, isScopeSubset, STANDARD_SCOPES } from "../support/lattice_oracle.js";
import { CapabilityScope } from "../support/types.js";

describe("Tier 1 - F15: Capability Lattice Attenuation Preview", () => {
  it("F15.1: calculates meet (⊓) between ADMIN parent and ORCHESTRATOR child", () => {
    const parent = STANDARD_SCOPES.ADMIN;
    const child = STANDARD_SCOPES.ORCHESTRATOR;
    const result = meetCapabilityScopes(parent, child);
    expect(result).not.toBeNull();
    expect(result?.allowed.length).toBe(4); // Read, Write, Execute, Delegate
    expect(result?.denied.some((d) => d.kind === "Standard" && d.action === "Admin")).toBe(true);
  });

  it("F15.2: detects bottom (⊥) when intersection is empty", () => {
    const parent = STANDARD_SCOPES.AUDIT_READER; // Read only
    const child = STANDARD_SCOPES.SUBMITTER;    // Write only
    const result = meetCapabilityScopes(parent, child);
    expect(result).toBeNull(); // Empty intersection: bottom (⊥)
  });

  it("F15.3: verifies subset relation for valid monotonic delegation", () => {
    const parent = STANDARD_SCOPES.ADMIN;
    const child = STANDARD_SCOPES.AUDIT_READER;
    expect(isScopeSubset(parent, child)).toBe(true);
  });

  it("F15.4: rejects scope expansion where child attempts to gain ungranted permissions", () => {
    const parent = STANDARD_SCOPES.SUBMITTER; // Write only
    const greedyChild = STANDARD_SCOPES.ADMIN; // Attempts all permissions
    expect(isScopeSubset(parent, greedyChild)).toBe(false);
  });

  it("F15.5: unions denied sets across successive attenuation levels", () => {
    const p1: CapabilityScope = {
      allowed: [{ kind: "Standard", action: "Read" }, { kind: "Standard", action: "Write" }],
      denied: [{ kind: "Standard", action: "Delete" }],
    };
    const p2: CapabilityScope = {
      allowed: [{ kind: "Standard", action: "Read" }],
      denied: [{ kind: "Standard", action: "Admin" }],
    };
    const meet = meetCapabilityScopes(p1, p2);
    expect(meet).not.toBeNull();
    const deniedActions = meet?.denied.map((d) => (d.kind === "Standard" ? d.action : ""));
    expect(deniedActions).toContain("Delete");
    expect(deniedActions).toContain("Admin");
  });
});
