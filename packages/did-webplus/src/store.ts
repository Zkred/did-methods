import type { WebplusDidDocument } from "./types.js";

/**
 * A verified portion of a DID's microledger, as retained by a Full DID
 * Resolver. `raw` is the canonical JSONL byte content (one JCS line per
 * document, `\n`-terminated); its UTF-8 byte length is the offset used for
 * range-based HTTP GETs of subsequent updates.
 */
export interface StoredMicroledger {
  raw: string;
  docs: WebplusDidDocument[];
}

/**
 * Persistence interface for verified microledgers (spec: "Full DID
 * Resolver"). Implementations may be in-memory, file-backed, or a database;
 * the resolver only ever stores ledgers that passed full verification, so
 * `get` results are trusted and re-verification is not required.
 */
export interface MicroledgerStore {
  get(did: string): Promise<StoredMicroledger | undefined>;
  put(did: string, ledger: StoredMicroledger): Promise<void>;
}

/** Simple Map-backed store; suitable for processes that resolve repeatedly. */
export class InMemoryMicroledgerStore implements MicroledgerStore {
  private readonly ledgers = new Map<string, StoredMicroledger>();

  async get(did: string): Promise<StoredMicroledger | undefined> {
    return this.ledgers.get(did);
  }

  async put(did: string, ledger: StoredMicroledger): Promise<void> {
    this.ledgers.set(did, ledger);
  }

  clear(): void {
    this.ledgers.clear();
  }
}

/**
 * The store used by `resolve` when none is supplied, giving constant-time
 * repeated resolution out of the box. Pass `store: null` to disable
 * persistence, or supply your own `MicroledgerStore` for durable storage.
 */
export const defaultMicroledgerStore = new InMemoryMicroledgerStore();