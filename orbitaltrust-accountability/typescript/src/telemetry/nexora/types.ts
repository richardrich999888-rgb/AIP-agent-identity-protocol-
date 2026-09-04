/**
 * NEXORA Lifecycle Anchor & AIP EvidencePacket domain schemas.
 *
 * The five tiers, and what each is allowed to know:
 *
 *   Persistent Identity        — the durable subject (who/what the agent is)
 *   NEXORA Lifecycle Anchors   — verifiable history: every milestone in the
 *                                agent's life, hash-chained from genesis
 *   AIP Delegation Graph       — dynamic scope: who delegated what to whom,
 *                                attenuating at every hop
 *   AIP EvidencePacket         — consequential action, bound to the exact
 *                                lifecycle state it ran under
 *   Deterministic Verification — recomputes all of it, independently
 *
 * The binding rule that makes the tiers one system rather than four ledgers:
 * every evidence packet carries the anchor-chain head hash at execution
 * time, and every executed action seals an ACTION_EXECUTION_SEAL anchor
 * naming the packet — so history and action cross-reference each other, and
 * neither chain can be rewritten without contradicting the other.
 */

import type { ClearanceLevel } from "../agent-identity/agent-profile";
import type { AgentDidString } from "../agent-identity/persistent-identity";

/** Lifecycle milestone taxonomy. */
export type NexoraAnchorType =
  | "AGENT_GENESIS"             // Initial registration + model digest binding
  | "OWNERSHIP_BINDING"         // Binding/transfer of owning entity (e.g. Bank / MoD)
  | "SUPERVISOR_DELEGATION"     // Human officer/supervisor delegation ticket
  | "CAPABILITY_MODULATION"     // Scope expansion or limitation of tool verbs
  | "MODEL_VERSION_MIGRATION"   // LLM weights, quant, or prompt template update
  | "AIR_GAP_ENCLAVE_TRANSFER"  // Hardware enclave or bunker node migration
  | "AUTHORITY_REVOCATION"      // Terminal kill-switch or suspension
  | "ACTION_EXECUTION_SEAL";    // Action proof anchor

/**
 * One verifiable milestone in an agent's life. Anchors form a per-agent
 * hash chain: the first must be AGENT_GENESIS, an AUTHORITY_REVOCATION
 * with terminal=true closes the chain forever, and every anchor's hash
 * covers its payload — so the agent's history is not a mutable table but
 * an append-only, recomputable record.
 */
export interface NexoraLifecycleAnchor {
  /** UUID v4. */
  anchorId: string;
  /** Monotonic per-agent index, starting at 1 (the genesis anchor). */
  sequenceNumber: number;
  anchorType: NexoraAnchorType;
  agentDid: AgentDidString;
  /** Who caused the milestone: officer, owning organisation, or upstream
   * agent DID. Genesis is caused by the registering authority. */
  actorDid: string;
  timestampUtc: string;
  /** Milestone-specific facts: modelDigest at genesis or migration, the
   * owning entity at OWNERSHIP_BINDING, tool deltas at
   * CAPABILITY_MODULATION, `{ terminal: true }` at a kill-switch
   * revocation, `{ packetId, packetHash }` at an execution seal. */
  payload: Record<string, unknown>;
  /** anchorHash of the previous anchor; the genesis constant for the first. */
  previousAnchorHash: string;
  /** SHA-256(previousAnchorHash + canonical payload of this anchor). */
  anchorHash: string;
}

/**
 * One edge of the AIP authority delegation graph: a delegator conferring an
 * attenuated scope on a child agent. Scope only narrows down the tree —
 * a child's tools, clearance and multi-sig posture can never exceed its
 * parent's — which is what makes a delegation *graph* safe to walk.
 */
export interface AipDelegationEdge {
  /** UUID v4. */
  edgeId: string;
  /** Officer DID at the root; agent DID for sub-agent delegation. */
  parentDid: string;
  childDid: AgentDidString;
  /** Tool verbs conferred on the child. */
  scope: string[];
  /** Tools that additionally require a human co-signature per invocation.
   * A parent's multi-sig obligation is inherited: a child cannot shed it. */
  multiSigTools: string[];
  clearanceLevel: ClearanceLevel;
  validFromUtc: string;
  expiresAtUtc: string;
  status: "ACTIVE" | "REVOKED";
  /** The SUPERVISOR_DELEGATION anchor that recorded this edge in the
   * child's lifecycle chain. */
  anchorId: string;
  /** Delegator's signature over the edge's terms (status excluded — see
   * grantSigningPayload's rationale in persistent-identity.ts). */
  edgeSignature: string;
}

/** Resolved authority for one agent: the intersection of every edge on its
 * delegation path, root officer first. */
export interface EffectiveAuthority {
  /** DID path, root delegator → … → agent. */
  path: string[];
  /** Edge ids along the path, same order. */
  edgeIds: string[];
  /** Tools every hop confers — the intersection. */
  scope: string[];
  /** Union of every hop's multi-sig obligations: inherited, never shed. */
  multiSigTools: string[];
  /** The weakest clearance on the path bounds the whole path. */
  clearanceLevel: ClearanceLevel;
}

/** Non-repudiable proof of one consequential action under NEXORA/AIP. */
export interface AipEvidencePacket {
  /** UUID v4. */
  id: string;
  /** Monotonic per-agent index, starting at 1. */
  sequenceNumber: number;
  timestampUtc: string;
  agentDid: AgentDidString;
  /** The agent's anchor-chain head hash at execution time: the exact
   * lifecycle state this action ran under. Rewriting history invalidates
   * every packet sealed on top of it. */
  anchorHash: string;
  /** DID path the authority flowed down, root → agent; empty when the
   * action was blocked for lacking any authority. */
  delegationPath: string[];
  /** The terminal edge the agent acted under ("" when blocked with none). */
  edgeId: string;
  modelDigest: string;
  rawPrompt: string;
  toolExecuted: {
    name: string;
    inputParams: Record<string, unknown>;
    status: "SUCCESS" | "FAILED" | "BLOCKED_BY_POLICY";
    supervisorCoSignature?: string;
    error?: string;
  };
  /** SHA-256 of pre-action state. */
  preStateHash: string;
  /** SHA-256 of post-action state; equals preStateHash when nothing ran. */
  postStateHash: string;
  /** packetHash of the previous packet; genesis constant for the first. */
  previousPacketHash: string;
  /** SHA-256(previousPacketHash + canonical payload). */
  packetHash: string;
}
