import { CapabilityScope, ScopePresetDefinition, StandardScopePreset } from "./types";

export const PRESET_SCOPES: Record<StandardScopePreset, ScopePresetDefinition> = {
  ADMIN: {
    name: "System Administrator",
    roleId: "ADMIN",
    protocolScope: "ADMIN",
    description: "Full administrative access. Grants all standard verbs and token delegation.",
    scope: {
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
    constraints: {
      environment: "production",
      mfa_required: "true",
    },
    resource_patterns: ["*"],
  },
  ORCHESTRATOR: {
    name: "Task Orchestrator",
    roleId: "ORCHESTRATOR",
    protocolScope: "ORCHESTRATOR",
    description: "Workflow coordination and sub-agent delegation. Explicitly denies Admin.",
    scope: {
      allowed: [
        { kind: "Standard", action: "Read" },
        { kind: "Standard", action: "Write" },
        { kind: "Standard", action: "Execute" },
        { kind: "Standard", action: "Delegate" },
      ],
      denied: [{ kind: "Standard", action: "Admin" }],
    },
    constraints: {
      max_delegation_depth: "3",
      environment: "production",
    },
    resource_patterns: ["workflows/**", "agents/**"],
  },
  AUDITOR: {
    name: "Compliance Auditor (AUDIT_READER)",
    roleId: "AUDITOR",
    protocolScope: "AUDIT_READER",
    description: "Read-only audit log inspection. Explicitly denies Write, Admin, Delete.",
    scope: {
      allowed: [{ kind: "Standard", action: "Read" }],
      denied: [
        { kind: "Standard", action: "Write" },
        { kind: "Standard", action: "Admin" },
        { kind: "Standard", action: "Delete" },
      ],
    },
    constraints: {
      export_allowed: "true",
    },
    resource_patterns: ["audit/**", "evidence/**", "reports/**"],
  },
  WORKER: {
    name: "Worker Submitter (SUBMITTER)",
    roleId: "WORKER",
    protocolScope: "SUBMITTER",
    description: "Task submission and evidence generation. Allows Write, denies Admin and Delete.",
    scope: {
      allowed: [{ kind: "Standard", action: "Write" }],
      denied: [
        { kind: "Standard", action: "Admin" },
        { kind: "Standard", action: "Delete" },
      ],
    },
    constraints: {
      max_batch_size: "100",
    },
    resource_patterns: ["tasks/**", "submissions/**"],
  },
  READ_ONLY: {
    name: "Read-Only Observer",
    roleId: "READ_ONLY",
    protocolScope: "CUSTOM",
    description: "Inspection and operational monitoring without state mutation or token delegation.",
    scope: {
      allowed: [
        { kind: "Standard", action: "Read" },
        { kind: "Standard", action: "Execute" },
      ],
      denied: [
        { kind: "Standard", action: "Write" },
        { kind: "Standard", action: "Delete" },
        { kind: "Standard", action: "Admin" },
        { kind: "Standard", action: "Delegate" },
      ],
    },
    constraints: {
      rate_limit: "60/min",
    },
    resource_patterns: ["public/**", "telemetry/**"],
  },
};

/**
 * Standard protocol scopes matching aip-core and lattice_oracle.ts
 */
export const STANDARD_SCOPES: Record<string, CapabilityScope> = {
  ADMIN: PRESET_SCOPES.ADMIN.scope,
  ORCHESTRATOR: PRESET_SCOPES.ORCHESTRATOR.scope,
  AUDIT_READER: PRESET_SCOPES.AUDITOR.scope,
  SUBMITTER: PRESET_SCOPES.WORKER.scope,
};
