import { createHash } from "node:crypto";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { MicroledgerStore, StoredMicroledger } from "../store.js";

/**
 * Filesystem-backed `MicroledgerStore` (Node.js only — imported from the
 * `@zkred/did-webplus/node` subpath so bundling the main entry point for a
 * browser never touches `node:fs`).
 *
 * A Full DID Resolver's whole benefit — a range GET that verifies only newly
 * appended documents — requires the verified prefix to survive between
 * resolutions. `InMemoryMicroledgerStore` only does that within one running
 * process; this store persists to one JSON file per DID under `dir`, so a
 * resolver rebuilt from a fresh process (a new CLI invocation, a restarted
 * server) still resolves warm.
 *
 * Each `put` is written to a temporary file and renamed into place, so a
 * process killed mid-write leaves the previous (still-valid, since it was
 * itself the result of a completed verification) file intact rather than a
 * corrupt partial one.
 */
export class FileMicroledgerStore implements MicroledgerStore {
  constructor(private readonly dir: string) {}

  private pathFor(did: string): string {
    // DIDs contain `:`, which is not a legal filename character on Windows;
    // hash rather than sanitize so no two distinct DIDs can collide.
    const digest = createHash("sha256").update(did, "utf8").digest("hex");
    return join(this.dir, `${digest}.json`);
  }

  async get(did: string): Promise<StoredMicroledger | undefined> {
    try {
      const raw = await readFile(this.pathFor(did), "utf8");
      return JSON.parse(raw) as StoredMicroledger;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return undefined;
      }
      throw err;
    }
  }

  async put(did: string, ledger: StoredMicroledger): Promise<void> {
    await mkdir(this.dir, { recursive: true });
    const target = this.pathFor(did);
    const tmp = `${target}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, JSON.stringify(ledger), "utf8");
    try {
      await rename(tmp, target);
    } catch (err) {
      await unlink(tmp).catch(() => {});
      throw err;
    }
  }
}
