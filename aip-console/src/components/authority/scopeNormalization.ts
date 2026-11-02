import { ActionVerb, CapabilityScope, StandardActionName } from "./types";

export const STANDARD_ACTIONS: StandardActionName[] = [
  "Read",
  "Write",
  "Delete",
  "Admin",
  "Execute",
  "Delegate",
];

export function actionToString(verb: ActionVerb): string {
  return verb.kind === "Standard" ? verb.action : verb.name;
}

export function stringToAction(str: string): ActionVerb {
  const trimmed = str.trim();
  const match = STANDARD_ACTIONS.find((a) => a.toLowerCase() === trimmed.toLowerCase());
  if (match) {
    return { kind: "Standard", action: match };
  }
  return { kind: "Custom", name: trimmed };
}

export function verbEquals(a: ActionVerb, b: ActionVerb): boolean {
  if (a.kind === "Standard" && b.kind === "Standard") {
    return a.action === b.action;
  }
  if (a.kind === "Custom" && b.kind === "Custom") {
    return a.name === b.name;
  }
  return false;
}

export function hasVerb(list: ActionVerb[], verb: ActionVerb): boolean {
  return list.some((item) => verbEquals(item, verb));
}

/**
 * Prepares CapabilityScope for WASM functions (meet_capability_scopes, check_scope_permits).
 * Uses string array representations which parse_scope_loose safely handles.
 */
export function scopeToWasmJson(scope: CapabilityScope): string {
  const allowedStrings = scope.allowed.map(actionToString);
  const deniedStrings = scope.denied.map(actionToString);
  return JSON.stringify({
    allowed: allowedStrings,
    denied: deniedStrings,
  });
}

/**
 * Parses WASM meet_capability_scopes JSON output back into normalized CapabilityScope.
 */
export function wasmJsonToMeetResult(jsonStr: string): {
  scope: CapabilityScope | null;
  isBottom: boolean;
  allowed: ActionVerb[];
  denied: ActionVerb[];
} {
  try {
    const parsed = JSON.parse(jsonStr);
    const isBottom = Boolean(
      parsed.is_bottom || (Array.isArray(parsed.allowed) && parsed.allowed.length === 0)
    );

    const allowed: ActionVerb[] = (parsed.allowed || []).map((item: any) => {
      if (typeof item === "string") return stringToAction(item);
      if (item.Standard) return { kind: "Standard", action: item.Standard };
      if (item.Custom) return { kind: "Custom", name: item.Custom };
      if (item.kind === "Standard" && item.action) return item;
      if (item.kind === "Custom" && item.name) return item;
      return stringToAction(String(item));
    });

    const denied: ActionVerb[] = (parsed.denied || []).map((item: any) => {
      if (typeof item === "string") return stringToAction(item);
      if (item.Standard) return { kind: "Standard", action: item.Standard };
      if (item.Custom) return { kind: "Custom", name: item.Custom };
      if (item.kind === "Standard" && item.action) return item;
      if (item.kind === "Custom" && item.name) return item;
      return stringToAction(String(item));
    });

    if (isBottom) {
      return {
        scope: null,
        isBottom: true,
        allowed: [],
        denied,
      };
    }

    return {
      scope: { allowed, denied },
      isBottom: false,
      allowed,
      denied,
    };
  } catch (err) {
    console.error("Failed to parse WASM meet result:", err);
    return {
      scope: null,
      isBottom: true,
      allowed: [],
      denied: [],
    };
  }
}

/**
 * Pure meet operator (⊓) matching e2e/support/lattice_oracle.ts
 * Used for instant preview and validation:
 * Allowed(P ⊓ C) = C.Allowed ∩ (P.Allowed \ P.Denied)
 * Denied(P ⊓ C) = P.Denied ∪ C.Denied
 */
export function meetCapabilityScopesPure(
  parent: CapabilityScope,
  child: CapabilityScope
): CapabilityScope | null {
  // If parent has Admin, treat all standard actions not in parent.denied as allowed
  const hasAdmin = parent.allowed.some((a) => a.kind === "Standard" && a.action === "Admin");
  let effectiveParentAllowed = [...parent.allowed];
  if (hasAdmin) {
    for (const act of STANDARD_ACTIONS) {
      const verb: ActionVerb = { kind: "Standard", action: act };
      if (!hasVerb(effectiveParentAllowed, verb) && !hasVerb(parent.denied, verb)) {
        effectiveParentAllowed.push(verb);
      }
    }
  }

  const pAllowedMinusDenied = effectiveParentAllowed.filter((a) => !hasVerb(parent.denied, a));
  const newAllowed = child.allowed.filter((c) => hasVerb(pAllowedMinusDenied, c));

  if (newAllowed.length === 0) {
    return null; // Empty intersection: bottom (⊥)
  }

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
 * Checks if child scope is a subset of parent scope (F15.3, F15.4)
 */
export function isScopeSubset(parent: CapabilityScope, child: CapabilityScope): boolean {
  const hasAdmin = parent.allowed.some((a) => a.kind === "Standard" && a.action === "Admin");
  let effectiveParentAllowed = [...parent.allowed];
  if (hasAdmin) {
    for (const act of STANDARD_ACTIONS) {
      const verb: ActionVerb = { kind: "Standard", action: act };
      if (!hasVerb(effectiveParentAllowed, verb) && !hasVerb(parent.denied, verb)) {
        effectiveParentAllowed.push(verb);
      }
    }
  }

  for (const c of child.allowed) {
    if (hasVerb(parent.denied, c)) return false;
    if (!hasVerb(effectiveParentAllowed, c)) return false;
  }
  return true;
}

/**
 * Checks if a scope permits an action verb with explicit deny precedence and admin inheritance
 */
export function scopePermitsAction(scope: CapabilityScope, action: ActionVerb): boolean {
  // 1. Explicit deny takes absolute precedence (F14.B1)
  if (hasVerb(scope.denied, action)) {
    return false;
  }

  // 2. Direct allow check (strict case-sensitive for custom actions)
  if (hasVerb(scope.allowed, action)) {
    return true;
  }

  // 3. Admin grants all standard actions unless explicitly denied (F14.B5)
  const hasAdmin = scope.allowed.some((a) => a.kind === "Standard" && a.action === "Admin");
  if (hasAdmin && action.kind === "Standard") {
    return true;
  }

  // 4. Default closed (F14.B2)
  return false;
}
