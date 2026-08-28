/**
 * Ledger persistence: IndexedDB when the runtime has it, an in-memory store
 * where it does not (tests, SSR, private-mode browsers with IndexedDB
 * disabled).
 *
 * Storage is append-only by interface: there is deliberately no update or
 * delete method, because the entire point of the ledger is that entries do
 * not change after they are written. (Nothing can stop a hostile actor with
 * devtools from editing IndexedDB rows directly — that is exactly the case
 * the hash chain exists to *detect*, not prevent.)
 */

import type { AgentActionLog } from "./types";

export interface LedgerStorage {
  append(entry: AgentActionLog): Promise<void>;
  /** All entries for one agent, ordered by ascending sequenceNumber. */
  listByAgent(agentId: string): Promise<AgentActionLog[]>;
  /** Every entry, ordered by agent then sequence — the export feed. */
  listAll(): Promise<AgentActionLog[]>;
}

/** In-memory store. Also the deterministic substrate for the test suite. */
export class MemoryLedgerStorage implements LedgerStorage {
  private readonly entries: AgentActionLog[] = [];

  append(entry: AgentActionLog): Promise<void> {
    this.entries.push(entry);
    return Promise.resolve();
  }

  listByAgent(agentId: string): Promise<AgentActionLog[]> {
    return Promise.resolve(
      this.entries
        .filter((e) => e.agentId === agentId)
        .sort((a, b) => a.sequenceNumber - b.sequenceNumber),
    );
  }

  listAll(): Promise<AgentActionLog[]> {
    return Promise.resolve(
      [...this.entries].sort(
        (a, b) =>
          a.agentId.localeCompare(b.agentId) || a.sequenceNumber - b.sequenceNumber,
      ),
    );
  }
}

const DB_NAME = "ot_agent_employee_ledger";
const STORE = "actions";

export class IndexedDbLedgerStorage implements LedgerStorage {
  private readonly db: Promise<IDBDatabase>;

  constructor() {
    this.db = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const store = req.result.createObjectStore(STORE, { keyPath: "eventId" });
        store.createIndex("byAgent", ["agentId", "sequenceNumber"], {
          unique: true,
        });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () =>
        reject(req.error ?? new Error("ot_agent_employee_ledger failed to open"));
    });
  }

  async append(entry: AgentActionLog): Promise<void> {
    const db = await this.db;
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      // `add`, not `put`: overwriting an existing eventId would be an edit,
      // and the storage layer refuses edits by construction.
      tx.objectStore(STORE).add(entry);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("ledger append failed"));
    });
  }

  async listByAgent(agentId: string): Promise<AgentActionLog[]> {
    const db = await this.db;
    return new Promise((resolve, reject) => {
      const range = IDBKeyRange.bound([agentId, 0], [agentId, Infinity]);
      const req = db
        .transaction(STORE, "readonly")
        .objectStore(STORE)
        .index("byAgent")
        .getAll(range);
      req.onsuccess = () => resolve(req.result as AgentActionLog[]);
      req.onerror = () => reject(req.error ?? new Error("ledger read failed"));
    });
  }

  async listAll(): Promise<AgentActionLog[]> {
    const db = await this.db;
    return new Promise((resolve, reject) => {
      const req = db
        .transaction(STORE, "readonly")
        .objectStore(STORE)
        .index("byAgent")
        .getAll();
      req.onsuccess = () => resolve(req.result as AgentActionLog[]);
      req.onerror = () => reject(req.error ?? new Error("ledger read failed"));
    });
  }
}

/** Best available storage for this runtime. */
export function createLedgerStorage(): LedgerStorage {
  return typeof indexedDB === "undefined"
    ? new MemoryLedgerStorage()
    : new IndexedDbLedgerStorage();
}
