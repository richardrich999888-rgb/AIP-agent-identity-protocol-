import { CapabilityScope, ActionVerb, StandardAction } from "./types.js";

/**
 * Standard named scopes according to aip-core and AIP_SPEC.md §8
 */
export const STANDARD_SCOPES: Record<string, CapabilityScope> = {
  ADMIN: {
    allowed: [
      { kind: "Standard", action: "Read" },
      { kind: "Standard", action: "Write" },
      { kind: "Standard", action: "Delete" },
      { kind: "Standard", action: "Admin" },
      { kind: "Standard", action: "Execute" },
      { kind: "Standard", action: "Delegate" },
    ],
    denied: [],
  },
  ORCHESTRATOR: {
    allowed: [
      { kind: "Standard", action: "Read" },
      { kind: "Standard", action: "Write" },
      { kind: "Standard", action: "Execute" },
      { kind: "Standard", action: "Delegate" },
    ],
    denied: [{ kind: "Standard", action: "Admin" }],
  },
  AUDIT_READER: {
    allowed: [{ kind: "Standard", action: "Read" }],
    denied: [
      { kind: "Standard", action: "Write" },
      { kind: "Standard", action: "Admin" },
      { kind: "Standard", action: "Delete" },
    ],
  },
  SUBMITTER: {
    allowed: [{ kind: "Standard", action: "Write" }],
    denied: [
      { kind: "Standard", action: "Admin" },
      { kind: "Standard", action: "Delete" },
    ],
  },
};

function verbEquals(a: ActionVerb, b: ActionVerb): boolean {
  if (a.kind === "Standard" && b.kind === "Standard") {
    return a.action === b.action;
  }
  if (a.kind === "Custom" && b.kind === "Custom") {
    return a.name === b.name;
  }
  return false;
}

function hasVerb(list: ActionVerb[], verb: ActionVerb): boolean {
  return list.some((item) => verbEquals(item, verb));
}

/**
 * Meet operator (⊓) for capability scopes
 * Allowed(P ⊓ C) = C.Allowed ∩ (P.Allowed \ P.Denied)
 * Denied(P ⊓ C) = P.Denied ∪ C.Denied
 * Returns null if Allowed(P ⊓ C) is empty (bottom: ⊥)
 */
export function meetCapabilityScopes(
  parent: CapabilityScope,
  child: CapabilityScope
): CapabilityScope | null {
  const pAllowedMinusDenied = parent.allowed.filter((a) => !hasVerb(parent.denied, a));
  const newAllowed = child.allowed.filter((c) => hasVerb(pAllowedMinusDenied, c));

  if (newAllowed.length === 0) {
    return null; // Empty intersection: bottom (⊥)
  }

  // Denied is union of parent.denied and child.denied
  const newDenied: ActionVerb[] = [...parent.denied];
  for (const d of child.denied) {
    if (!hasVerb(newDenied, d)) {
      newDenied.push(d);
    }
  }

  return {
    allowed: newAllowed,
    denied: newDenied,
  };
}

/**
 * Checks if child scope is a subset of parent scope
 */
export function isScopeSubset(parent: CapabilityScope, child: CapabilityScope): boolean {
  // Child allowed must be subset of parent allowed
  for (const c of child.allowed) {
    if (hasVerb(parent.denied, c)) return false;
    if (!hasVerb(parent.allowed, c)) return false;
  }
  return true;
}

export interface RevocationEntry {
  jti: string;
  revoked_at: number;
  reason: "Compromise" | "AdminRevocation" | "KeyRotation" | "Expired";
  cascade: boolean;
  revoked_by: string;
}

/**
 * Simulates cascade revocation traversal
 */
export function computeCascadeRevocations(
  targetJti: string,
  delegationTree: { jti: string; parent_jti?: string }[],
  revokedBy: string
): RevocationEntry[] {
  const result: RevocationEntry[] = [];
  const queue: string[] = [targetJti];

  // Primary revocation
  result.push({
    jti: targetJti,
    revoked_at: Date.now(),
    reason: "Compromise",
    cascade: true,
    revoked_by: revokedBy,
  });

  while (queue.length > 0) {
    const current = queue.shift()!;
    // Find all children
    const children = delegationTree.filter((node) => node.parent_jti === current);
    for (const child of children) {
      result.push({
        jti: child.jti,
        revoked_at: Date.now(),
        reason: "AdminRevocation",
        cascade: true,
        revoked_by: revokedBy,
      });
      queue.push(child.jti);
    }
  }

  return result;
}
