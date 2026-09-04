/**
 * Durable storage for the NEXORA tiers, in one IndexedDB database
 * (`nexora_lifecycle_db`): lifecycle anchors, delegation edges, and the AIP
 * evidence ledger. Anchors and packets are append-only at the storage layer
 * — unique (agentDid, sequenceNumber) indexes turn a forked or overwritten
 * sequence into a constraint violation rather than a silent edit. Edges are
 * the one mutable kind, and only their lifecycle status mutates: revocation
 * updates in place, never deletes, because "what authority existed when"
 * is itself audit material.
 *
 * `MemoryNexoraStore` implements the same interface for runtimes without
 * IndexedDB and as the deterministic substrate for the test suite.
 */

import type {
  AipDelegationEdge,
  AipEvidencePacket,
  NexoraLifecycleAnchor,
} from "./types";

export interface NexoraStore {
  appendAnchor(anchor: NexoraLifecycleAnchor): Promise<void>;
  /** All anchors for one agent, ascending by sequenceNumber. */
  listAnchorsForAgent(agentDid: string): Promise<NexoraLifecycleAnchor[]>;

  addEdge(edge: AipDelegationEdge): Promise<void>;
  /** Status flips only — an edge's signed terms never change in place. */
  updateEdge(edge: AipDelegationEdge): Promise<void>;
  getEdge(edgeId: string): Promise<AipDelegationEdge | null>;
  listEdgesForChild(childDid: string): Promise<AipDelegationEdge[]>;

  appendPacket(packet: AipEvidencePacket): Promise<void>;
  /** All packets for one agent, ascending by sequenceNumber. */
  listPacketsForAgent(agentDid: string): Promise<AipEvidencePacket[]>;
}

export class MemoryNexoraStore implements NexoraStore {
  private readonly anchors: NexoraLifecycleAnchor[] = [];
  private readonly edges = new Map<string, AipDelegationEdge>();
  private readonly packets: AipEvidencePacket[] = [];

  appendAnchor(anchor: NexoraLifecycleAnchor): Promise<void> {
    this.anchors.push(anchor);
    return Promise.resolve();
  }

  listAnchorsForAgent(agentDid: string): Promise<NexoraLifecycleAnchor[]> {
    return Promise.resolve(
      this.anchors
        .filter((a) => a.agentDid === agentDid)
        .sort((a, b) => a.sequenceNumber - b.sequenceNumber),
    );
  }

  addEdge(edge: AipDelegationEdge): Promise<void> {
    if (this.edges.has(edge.edgeId)) {
      return Promise.reject(new Error(`edge ${edge.edgeId} already exists`));
    }
    this.edges.set(edge.edgeId, { ...edge });
    return Promise.resolve();
  }

  updateEdge(edge: AipDelegationEdge): Promise<void> {
    if (!this.edges.has(edge.edgeId)) {
      return Promise.reject(new Error(`edge ${edge.edgeId} not found`));
    }
    this.edges.set(edge.edgeId, { ...edge });
    return Promise.resolve();
  }

  getEdge(edgeId: string): Promise<AipDelegationEdge | null> {
    return Promise.resolve(this.edges.get(edgeId) ?? null);
  }

  listEdgesForChild(childDid: string): Promise<AipDelegationEdge[]> {
    return Promise.resolve(
      [...this.edges.values()].filter((e) => e.childDid === childDid),
    );
  }

  appendPacket(packet: AipEvidencePacket): Promise<void> {
    this.packets.push(packet);
    return Promise.resolve();
  }

  listPacketsForAgent(agentDid: string): Promise<AipEvidencePacket[]> {
    return Promise.resolve(
      this.packets
        .filter((p) => p.agentDid === agentDid)
        .sort((a, b) => a.sequenceNumber - b.sequenceNumber),
    );
  }
}

const DB_NAME = "nexora_lifecycle_db";
const ANCHORS = "lifecycle_anchors";
const EDGES = "delegation_edges";
const LEDGER = "aip_evidence_ledger";

export class IndexedDbNexoraStore implements NexoraStore {
  private readonly db: Promise<IDBDatabase>;

  constructor() {
    this.db = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        const anchors = db.createObjectStore(ANCHORS, { keyPath: "anchorId" });
        anchors.createIndex("byAgent", ["agentDid", "sequenceNumber"], {
          unique: true,
        });
        const edges = db.createObjectStore(EDGES, { keyPath: "edgeId" });
        edges.createIndex("byChild", "childDid");
        const ledger = db.createObjectStore(LEDGER, { keyPath: "id" });
        ledger.createIndex("byAgent", ["agentDid", "sequenceNumber"], {
          unique: true,
        });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () =>
        reject(req.error ?? new Error("nexora_lifecycle_db failed to open"));
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

  async appendAnchor(anchor: NexoraLifecycleAnchor): Promise<void> {
    await this.write(ANCHORS, (s) => s.add(anchor));
  }

  async listAnchorsForAgent(agentDid: string): Promise<NexoraLifecycleAnchor[]> {
    const range = IDBKeyRange.bound([agentDid, 0], [agentDid, Infinity]);
    return this.read<NexoraLifecycleAnchor[]>(ANCHORS, (s) =>
      s.index("byAgent").getAll(range),
    );
  }

  async addEdge(edge: AipDelegationEdge): Promise<void> {
    await this.write(EDGES, (s) => s.add({ ...edge }));
  }

  async updateEdge(edge: AipDelegationEdge): Promise<void> {
    await this.write(EDGES, (s) => s.put({ ...edge }));
  }

  async getEdge(edgeId: string): Promise<AipDelegationEdge | null> {
    return (
      (await this.read<AipDelegationEdge | undefined>(EDGES, (s) => s.get(edgeId))) ??
      null
    );
  }

  async listEdgesForChild(childDid: string): Promise<AipDelegationEdge[]> {
    return this.read<AipDelegationEdge[]>(EDGES, (s) =>
      s.index("byChild").getAll(childDid),
    );
  }

  async appendPacket(packet: AipEvidencePacket): Promise<void> {
    await this.write(LEDGER, (s) => s.add(packet));
  }

  async listPacketsForAgent(agentDid: string): Promise<AipEvidencePacket[]> {
    const range = IDBKeyRange.bound([agentDid, 0], [agentDid, Infinity]);
    return this.read<AipEvidencePacket[]>(LEDGER, (s) =>
      s.index("byAgent").getAll(range),
    );
  }
}

/** Best available store for this runtime. */
export function createNexoraStore(): NexoraStore {
  return typeof indexedDB === "undefined"
    ? new MemoryNexoraStore()
    : new IndexedDbNexoraStore();
}
