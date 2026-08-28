/**
 * The AIP authority delegation graph: who delegated what to whom, with
 * scope attenuating at every hop.
 *
 * # The attenuation invariant
 *
 * Authority only narrows down the tree. A sub-agent's tools are a subset of
 * its delegator's effective tools, its clearance never exceeds the weakest
 * clearance above it, and multi-sig obligations are inherited — a child can
 * gain new obligations, never shed one. This is checked at delegation time
 * *and* recomputed at resolution time, because an edge edited in storage
 * after issue must not widen anything (its signature breaks first, and the
 * resolver re-intersects regardless).
 *
 * # Graph and history are one system
 *
 * Every delegation is anchored as a SUPERVISOR_DELEGATION milestone in the
 * child's lifecycle chain, and every edge revocation as a non-terminal
 * AUTHORITY_REVOCATION — so the graph's evolution is itself verifiable
 * history, not a mutable side table.
 */

import { canonicalJson, hmacSignHex, hmacVerifyHex, importHmacKey } from "../crypto";
import { CLEARANCE_RANK, type ClearanceLevel } from "../agent-identity/agent-profile";
import type { AgentDidString } from "../agent-identity/persistent-identity";
import type { AipDelegationEdge, EffectiveAuthority } from "./types";
import type { NexoraStore } from "./nexora-store";
import type { NexoraAnchorChain } from "./anchor-chain";

/** Sub-agent trees deeper than this are refused: a delegation chain nobody
 * can read is a delegation chain nobody actually reviews. */
export const MAX_DELEGATION_DEPTH = 16;

function isOfficerDid(did: string): boolean {
  return did.startsWith("did:syntriass:officer:");
}

/** The bytes an edge signature covers: the delegation's terms, excluding
 * the signature and the lifecycle `status` (revocation is flipped by the
 * graph without the delegator's key — same rationale as grant signing). */
export function edgeSigningPayload(
  edge: Omit<AipDelegationEdge, "edgeSignature" | "status">,
): string {
  return canonicalJson({
    edgeId: edge.edgeId,
    parentDid: edge.parentDid,
    childDid: edge.childDid,
    scope: [...edge.scope],
    multiSigTools: [...edge.multiSigTools],
    clearanceLevel: edge.clearanceLevel,
    validFromUtc: edge.validFromUtc,
    expiresAtUtc: edge.expiresAtUtc,
    anchorId: edge.anchorId,
  });
}

/** Signs delegation edges and per-invocation supervisor co-signatures.
 * HMAC for the same reason as the other authorities in this subsystem;
 * this class is the asymmetric upgrade seam. */
export class AipDelegationAuthority {
  private readonly key: Promise<CryptoKey>;

  constructor(signingSecret: string) {
    this.key = importHmacKey(signingSecret);
  }

  async signEdge(
    unsigned: Omit<AipDelegationEdge, "edgeSignature">,
  ): Promise<AipDelegationEdge> {
    const edgeSignature = await hmacSignHex(await this.key, edgeSigningPayload(unsigned));
    return { ...unsigned, edgeSignature };
  }

  async verifyEdge(edge: AipDelegationEdge): Promise<boolean> {
    return hmacVerifyHex(await this.key, edgeSigningPayload(edge), edge.edgeSignature);
  }

  /** Co-signature binds the edge as well as the tool: a ticket dies with
   * its edge and cannot cross tools. */
  private coSignaturePayload(edge: AipDelegationEdge, toolName: string): string {
    return canonicalJson({
      standard: "AIP-dual-key-v1",
      edgeId: edge.edgeId,
      childDid: edge.childDid,
      parentDid: edge.parentDid,
      toolName,
    });
  }

  async issueCoSignature(edge: AipDelegationEdge, toolName: string): Promise<string> {
    return hmacSignHex(await this.key, this.coSignaturePayload(edge, toolName));
  }

  async verifyCoSignature(
    edge: AipDelegationEdge,
    toolName: string,
    signatureHex: string,
  ): Promise<boolean> {
    return hmacVerifyHex(
      await this.key,
      this.coSignaturePayload(edge, toolName),
      signatureHex,
    );
  }
}

export interface DelegationInput {
  parentDid: string;
  childDid: AgentDidString;
  scope: string[];
  multiSigTools?: string[];
  clearanceLevel: ClearanceLevel;
  validForMs: number;
}

export class AipDelegationGraph {
  constructor(
    private readonly store: NexoraStore,
    private readonly anchors: NexoraAnchorChain,
    private readonly authority: AipDelegationAuthority,
    private readonly now: () => string = () => new Date().toISOString(),
  ) {}

  /**
   * Confers authority from parent to child. Root edges (officer parent)
   * define scope freely; sub-agent edges are attenuated against the
   * parent's *effective* authority at issue time. The delegation is
   * anchored in the child's lifecycle chain before the edge is stored, so
   * an edge without its milestone cannot exist.
   */
  async delegate(input: DelegationInput): Promise<AipDelegationEdge> {
    let multiSig = [...(input.multiSigTools ?? [])];
    if (!isOfficerDid(input.parentDid)) {
      const parent = await this.resolveAuthority(input.parentDid);
      if (!parent) {
        throw new Error(
          `${input.parentDid} has no effective authority to delegate from`,
        );
      }
      if (parent.path.includes(input.childDid)) {
        throw new Error(
          `delegation cycle: ${input.childDid} is already on ${input.parentDid}'s path`,
        );
      }
      if (parent.path.length >= MAX_DELEGATION_DEPTH) {
        throw new Error(`delegation depth exceeds ${MAX_DELEGATION_DEPTH}`);
      }
      const escaped = input.scope.filter((t) => !parent.scope.includes(t));
      if (escaped.length > 0) {
        throw new Error(
          `scope attenuation violated: parent does not hold [${escaped.join(", ")}]`,
        );
      }
      if (CLEARANCE_RANK[input.clearanceLevel] > CLEARANCE_RANK[parent.clearanceLevel]) {
        throw new Error(
          `clearance attenuation violated: parent path holds ${parent.clearanceLevel}`,
        );
      }
      // Multi-sig is inherited: any delegated tool the parent path gates
      // stays gated for the child, whatever the child edge declares.
      for (const t of parent.multiSigTools) {
        if (input.scope.includes(t) && !multiSig.includes(t)) multiSig.push(t);
      }
    }

    const anchor = await this.anchors.appendAnchor({
      anchorType: "SUPERVISOR_DELEGATION",
      agentDid: input.childDid,
      actorDid: input.parentDid,
      payload: {
        scope: [...input.scope],
        multiSigTools: [...multiSig],
        clearanceLevel: input.clearanceLevel,
      },
    });

    const nowMs = Date.parse(this.now());
    const edge = await this.authority.signEdge({
      edgeId: crypto.randomUUID(),
      parentDid: input.parentDid,
      childDid: input.childDid,
      scope: [...input.scope],
      multiSigTools: multiSig,
      clearanceLevel: input.clearanceLevel,
      validFromUtc: new Date(nowMs - 1000).toISOString(),
      expiresAtUtc: new Date(nowMs + input.validForMs).toISOString(),
      status: "ACTIVE",
      anchorId: anchor.anchorId,
    });
    await this.store.addEdge(edge);
    return edge;
  }

  /** Revokes one edge (non-terminal: the child's chain stays open), and
   * anchors the revocation as a milestone. Everything downstream of this
   * edge loses authority at the next resolution — cascade by construction,
   * since resolution walks the live graph. */
  async revokeEdge(edgeId: string, actorDid: string, reason: string): Promise<void> {
    const edge = await this.store.getEdge(edgeId);
    if (!edge) throw new Error(`edge ${edgeId} not found`);
    await this.anchors.appendAnchor({
      anchorType: "AUTHORITY_REVOCATION",
      agentDid: edge.childDid,
      actorDid,
      payload: { edgeId, reason, terminal: false },
    });
    await this.store.updateEdge({ ...edge, status: "REVOKED" });
  }

  /**
   * The agent's effective authority right now: walk from the agent up to
   * an officer root, taking at each hop the newest usable edge (ACTIVE, in
   * window, signature valid), and intersect everything on the way down.
   * Returns null when any hop has no usable edge — which is exactly how a
   * mid-tree revocation cascades to the whole subtree.
   */
  async resolveAuthority(agentDid: string): Promise<EffectiveAuthority | null> {
    const nowUtc = this.now();
    const path: string[] = [agentDid];
    const edgeIds: string[] = [];
    let scope: string[] | null = null;
    let multiSigTools: string[] = [];
    let clearanceLevel: ClearanceLevel | null = null;

    let current = agentDid;
    for (let depth = 0; depth < MAX_DELEGATION_DEPTH; depth++) {
      const edge = await this.usableEdgeFor(current, nowUtc);
      if (!edge) return null;
      edgeIds.unshift(edge.edgeId);
      path.unshift(edge.parentDid);

      scope = scope === null ? [...edge.scope] : scope.filter((t) => edge.scope.includes(t));
      for (const t of edge.multiSigTools) {
        if (!multiSigTools.includes(t)) multiSigTools.push(t);
      }
      clearanceLevel =
        clearanceLevel === null ||
        CLEARANCE_RANK[edge.clearanceLevel] < CLEARANCE_RANK[clearanceLevel]
          ? edge.clearanceLevel
          : clearanceLevel;

      if (isOfficerDid(edge.parentDid)) {
        return {
          path,
          edgeIds,
          scope: scope ?? [],
          multiSigTools,
          clearanceLevel: clearanceLevel ?? "UNCLASSIFIED",
        };
      }
      current = edge.parentDid;
    }
    // No officer root within the depth bound: unrooted authority is no
    // authority.
    return null;
  }

  private async usableEdgeFor(
    childDid: string,
    nowUtc: string,
  ): Promise<AipDelegationEdge | null> {
    const now = Date.parse(nowUtc);
    const candidates: AipDelegationEdge[] = [];
    for (const edge of await this.store.listEdgesForChild(childDid)) {
      if (edge.status !== "ACTIVE") continue;
      if (now < Date.parse(edge.validFromUtc) || now >= Date.parse(edge.expiresAtUtc)) {
        continue;
      }
      if (!(await this.authority.verifyEdge(edge))) continue;
      candidates.push(edge);
    }
    if (candidates.length === 0) return null;
    candidates.sort((a, b) => Date.parse(b.validFromUtc) - Date.parse(a.validFromUtc));
    return candidates[0];
  }
}
