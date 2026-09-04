/**
 * Durable storage for the identity/authority/evidence triple, in one
 * IndexedDB database (`orbital_trust_audit_db`) so the console can answer
 * "who is this agent, what may it do right now, and what has it done" after
 * any reload.
 *
 * Three stores, three lifecycles:
 * - `persistent_agent_identities` — write-once identity records. Revocation
 *   never deletes from here: authority dies, identity remains, because the
 *   audit trail must keep naming its actor.
 * - `delegated_authority_grants` — active *and historical* grants. A
 *   revoked grant is updated in place (status + reason), not removed; the
 *   history of what authority existed when is itself audit material.
 * - `agent_evidence_ledger` — append-only EvidencePacket chains.
 *
 * A `MemoryIdentityStore` implements the same interface for runtimes
 * without IndexedDB (tests, SSR) and as the deterministic substrate for the
 * test suite.
 */

import type {
  DelegatedAuthorityGrant,
  EvidencePacket,
  PersistentAgentIdentity,
} from "./persistent-identity";

/** A grant as stored: the signed grant plus lifecycle bookkeeping the
 * delegator's signature deliberately does not cover. */
export type StoredAuthorityGrant = DelegatedAuthorityGrant & {
  revocationReason?: string;
  revokedAtUtc?: string;
};

export interface IdentityStore {
  registerPersistentIdentity(identity: PersistentAgentIdentity): Promise<void>;
  getPersistentIdentity(did: string): Promise<PersistentAgentIdentity | null>;

  issueAuthorityGrant(grant: DelegatedAuthorityGrant): Promise<void>;
  /** Flips the grant's status to REVOKED with the operator's reason. The
   * agent's persistent identity is untouched by design. */
  revokeAuthorityGrant(grantId: string, reason: string): Promise<void>;
  /** The grant the agent is operating under right now: status ACTIVE and
   * the clock inside its validity window. When several qualify, the most
   * recently valid-from wins — the newest delegation supersedes. */
  getActiveGrantForAgent(did: string): Promise<DelegatedAuthorityGrant | null>;
  getGrant(grantId: string): Promise<StoredAuthorityGrant | null>;
  listGrantsForAgent(did: string): Promise<StoredAuthorityGrant[]>;

  appendEvidencePacket(packet: EvidencePacket): Promise<void>;
  /** All packets for one agent, ascending by sequenceNumber. */
  listEvidenceForAgent(did: string): Promise<EvidencePacket[]>;
}

function pickActive(
  grants: StoredAuthorityGrant[],
  nowUtc: string,
): DelegatedAuthorityGrant | null {
  const now = Date.parse(nowUtc);
  const usable = grants.filter(
    (g) =>
      g.status === "ACTIVE" &&
      now >= Date.parse(g.validFromUtc) &&
      now < Date.parse(g.expiresAtUtc),
  );
  if (usable.length === 0) return null;
  usable.sort((a, b) => Date.parse(b.validFromUtc) - Date.parse(a.validFromUtc));
  return usable[0];
}

export class MemoryIdentityStore implements IdentityStore {
  private readonly identities = new Map<string, PersistentAgentIdentity>();
  private readonly grants = new Map<string, StoredAuthorityGrant>();
  private readonly evidence: EvidencePacket[] = [];

  registerPersistentIdentity(identity: PersistentAgentIdentity): Promise<void> {
    if (this.identities.has(identity.did)) {
      return Promise.reject(new Error(`identity ${identity.did} already registered`));
    }
    this.identities.set(identity.did, identity);
    return Promise.resolve();
  }

  getPersistentIdentity(did: string): Promise<PersistentAgentIdentity | null> {
    return Promise.resolve(this.identities.get(did) ?? null);
  }

  issueAuthorityGrant(grant: DelegatedAuthorityGrant): Promise<void> {
    if (this.grants.has(grant.grantId)) {
      return Promise.reject(new Error(`grant ${grant.grantId} already exists`));
    }
    this.grants.set(grant.grantId, { ...grant });
    return Promise.resolve();
  }

  revokeAuthorityGrant(grantId: string, reason: string): Promise<void> {
    const grant = this.grants.get(grantId);
    if (!grant) return Promise.reject(new Error(`grant ${grantId} not found`));
    this.grants.set(grantId, {
      ...grant,
      status: "REVOKED",
      revocationReason: reason,
      revokedAtUtc: new Date().toISOString(),
    });
    return Promise.resolve();
  }

  getActiveGrantForAgent(did: string): Promise<DelegatedAuthorityGrant | null> {
    return Promise.resolve(
      pickActive(
        [...this.grants.values()].filter((g) => g.agentDid === did),
        new Date().toISOString(),
      ),
    );
  }

  getGrant(grantId: string): Promise<StoredAuthorityGrant | null> {
    return Promise.resolve(this.grants.get(grantId) ?? null);
  }

  listGrantsForAgent(did: string): Promise<StoredAuthorityGrant[]> {
    return Promise.resolve(
      [...this.grants.values()].filter((g) => g.agentDid === did),
    );
  }

  appendEvidencePacket(packet: EvidencePacket): Promise<void> {
    this.evidence.push(packet);
    return Promise.resolve();
  }

  listEvidenceForAgent(did: string): Promise<EvidencePacket[]> {
    return Promise.resolve(
      this.evidence
        .filter((p) => p.agentDid === did)
        .sort((a, b) => a.sequenceNumber - b.sequenceNumber),
    );
  }
}

const DB_NAME = "orbital_trust_audit_db";
const IDENTITIES = "persistent_agent_identities";
const GRANTS = "delegated_authority_grants";
const LEDGER = "agent_evidence_ledger";

export class IndexedDbIdentityStore implements IdentityStore {
  private readonly db: Promise<IDBDatabase>;

  constructor() {
    this.db = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        db.createObjectStore(IDENTITIES, { keyPath: "did" });
        const grants = db.createObjectStore(GRANTS, { keyPath: "grantId" });
        grants.createIndex("byAgent", "agentDid");
        const ledger = db.createObjectStore(LEDGER, { keyPath: "id" });
        ledger.createIndex("byAgent", ["agentDid", "sequenceNumber"], {
          unique: true,
        });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () =>
        reject(req.error ?? new Error("orbital_trust_audit_db failed to open"));
    });
  }

  private async write(store: string, op: (s: IDBObjectStore) => void): Promise<void> {
    const db = await this.db;
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(store, "readwrite");
      op(tx.objectStore(store));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error(`${store} write failed`));
    });
  }

  private async read<T>(store: string, op: (s: IDBObjectStore) => IDBRequest): Promise<T> {
    const db = await this.db;
    return new Promise<T>((resolve, reject) => {
      const req = op(db.transaction(store, "readonly").objectStore(store));
      req.onsuccess = () => resolve(req.result as T);
      req.onerror = () => reject(req.error ?? new Error(`${store} read failed`));
    });
  }

  async registerPersistentIdentity(identity: PersistentAgentIdentity): Promise<void> {
    // `add` refuses overwrites: an identity is write-once, and silently
    // replacing one under the same DID would rewrite who the history names.
    await this.write(IDENTITIES, (s) => s.add(identity));
  }

  async getPersistentIdentity(did: string): Promise<PersistentAgentIdentity | null> {
    return (
      (await this.read<PersistentAgentIdentity | undefined>(IDENTITIES, (s) =>
        s.get(did),
      )) ?? null
    );
  }

  async issueAuthorityGrant(grant: DelegatedAuthorityGrant): Promise<void> {
    await this.write(GRANTS, (s) => s.add({ ...grant }));
  }

  async revokeAuthorityGrant(grantId: string, reason: string): Promise<void> {
    const grant = await this.getGrant(grantId);
    if (!grant) throw new Error(`grant ${grantId} not found`);
    const revoked: StoredAuthorityGrant = {
      ...grant,
      status: "REVOKED",
      revocationReason: reason,
      revokedAtUtc: new Date().toISOString(),
    };
    await this.write(GRANTS, (s) => s.put(revoked));
  }

  async getActiveGrantForAgent(did: string): Promise<DelegatedAuthorityGrant | null> {
    return pickActive(await this.listGrantsForAgent(did), new Date().toISOString());
  }

  async getGrant(grantId: string): Promise<StoredAuthorityGrant | null> {
    return (
      (await this.read<StoredAuthorityGrant | undefined>(GRANTS, (s) =>
        s.get(grantId),
      )) ?? null
    );
  }

  async listGrantsForAgent(did: string): Promise<StoredAuthorityGrant[]> {
    return this.read<StoredAuthorityGrant[]>(GRANTS, (s) =>
      s.index("byAgent").getAll(did),
    );
  }

  async appendEvidencePacket(packet: EvidencePacket): Promise<void> {
    // `add` + the unique (agentDid, sequenceNumber) index make the ledger
    // append-only at the storage layer: an overwrite or a forked sequence
    // is a constraint violation, not a silent edit.
    await this.write(LEDGER, (s) => s.add(packet));
  }

  async listEvidenceForAgent(did: string): Promise<EvidencePacket[]> {
    const range = IDBKeyRange.bound([did, 0], [did, Infinity]);
    return this.read<EvidencePacket[]>(LEDGER, (s) =>
      s.index("byAgent").getAll(range),
    );
  }
}

/** Best available store for this runtime. */
export function createIdentityStore(): IdentityStore {
  return typeof indexedDB === "undefined"
    ? new MemoryIdentityStore()
    : new IndexedDbIdentityStore();
}
