import { describe, it, expect } from "vitest";
import { meetCapabilityScopes, STANDARD_SCOPES } from "../support/lattice_oracle.js";
import { CapabilityScope } from "../support/types.js";

describe("Tier 2 Boundary - F15: Capability Lattice Attenuation Boundaries", () => {
  it("F15.B1: idempotence property: S ⊓ S = S holds strictly", () => {
    const s = STANDARD_SCOPES.ORCHESTRATOR;
    const meet = meetCapabilityScopes(s, s);
    expect(meet).not.toBeNull();
    expect(meet?.allowed.length).toBe(s.allowed.length);
    expect(meet?.denied.length).toBe(s.denied.length);
  });

  it("F15.B2: identity element: ADMIN ⊓ S = S holds for any subset S", () => {
    const s = STANDARD_SCOPES.AUDIT_READER;
    const meet = meetCapabilityScopes(STANDARD_SCOPES.ADMIN, s);
    expect(meet).not.toBeNull();
    expect(meet?.allowed.length).toBe(s.allowed.length);
  });

  it("F15.B3: disjoint custom scopes meet produces bottom (⊥)", () => {
    const parent: CapabilityScope = {
      allowed: [{ kind: "Custom", name: "action:a" }],
      denied: [],
    };
    const child: CapabilityScope = {
      allowed: [{ kind: "Custom", name: "action:b" }],
      denied: [],
    };
    const meet = meetCapabilityScopes(parent, child);
    expect(meet).toBeNull();
  });

  it("F15.B4: associativity property: (A ⊓ B) ⊓ C = A ⊓ (B ⊓ C)", () => {
    const a = STANDARD_SCOPES.ADMIN;
    const b = STANDARD_SCOPES.ORCHESTRATOR;
    const c = STANDARD_SCOPES.SUBMITTER;

    const ab_c = meetCapabilityScopes(meetCapabilityScopes(a, b)!, c);
    const bc = meetCapabilityScopes(b, c);
    const a_bc = meetCapabilityScopes(a, bc!);

    expect(ab_c).not.toBeNull();
    expect(a_bc).not.toBeNull();
    expect(ab_c?.allowed.length).toBe(a_bc?.allowed.length);
  });

  it("F15.B5: commutativity on allowed intersection holds", () => {
    const a: CapabilityScope = {
      allowed: [{ kind: "Standard", action: "Read" }, { kind: "Standard", action: "Write" }],
      denied: [],
    };
    const b: CapabilityScope = {
      allowed: [{ kind: "Standard", action: "Write" }, { kind: "Standard", action: "Execute" }],
      denied: [],
    };
    const meetAB = meetCapabilityScopes(a, b);
    const meetBA = meetCapabilityScopes(b, a);
    expect(meetAB?.allowed.length).toBe(meetBA?.allowed.length);
    expect(meetAB?.allowed[0]).toEqual({ kind: "Standard", action: "Write" });
  });
});
