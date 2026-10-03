import { bytesToHex } from "@noble/hashes/utils.js";
import { signObject } from "../entries";
import { detachLeaf, leafBytes, logId, type LogLeaf, type SignedLeaf, type TreeHead } from "../leaves";
import { consistencyProof, leafHash, memorySource, rootHash } from "../merkle";
import type { LogSource } from "../monitor";
import { generateKeyPair, publicKeyOf } from "../signing";

type Unstamped<T> = T extends unknown ? Omit<T, "timestamp"> : never;

/**
 * A log in memory, for tests and scripts: it appends leaves, signs a tree head after each,
 * and answers like a node's log API, as a `LogSource` or as `fetch`. Logs made from one
 * secret key share an ID, so two of them can stand for a log that forked.
 */
export class MemoryLog {
  readonly publicKey;
  readonly id: string;
  readonly leaves: LogLeaf[] = [];
  /** Each entry as signed, which a node keeps beside its leaf. */
  readonly signed: object[] = [];
  /** The tree head the log signed for each size, from size 1. */
  readonly heads: TreeHead[] = [];
  /** The time the next append is stamped with; each append moves it on a second. */
  clock = new Date("2026-10-03T12:00:00.000Z");

  constructor(readonly secretKey: Uint8Array = generateKeyPair().secretKey) {
    this.publicKey = publicKeyOf(secretKey);
    this.id = logId(this.publicKey);
  }

  /** Appends a leaf, with its entry as signed, and signs the new tree head. Returns its index. */
  async append(unstamped: Unstamped<SignedLeaf>): Promise<number> {
    const timestamp = this.clock.toISOString();
    this.clock = new Date(this.clock.getTime() + 1000);
    this.leaves.push(detachLeaf({ ...unstamped, timestamp } as SignedLeaf));
    this.signed.push(unstamped.entry);
    const size = this.leaves.length;
    this.heads.push(
      signObject(
        { type: "tree_head" as const, log: this.id, size, root: bytesToHex(await rootHash(this.tree(), size)), timestamp },
        this.secretKey,
      ),
    );
    return size - 1;
  }

  get size(): number {
    return this.leaves.length;
  }

  head(): TreeHead | null {
    return this.heads.at(-1) ?? null;
  }

  /** The log API's answers, each through JSON as a node sends them. Overrides replace answers. */
  source(overrides: Partial<LogSource> = {}): LogSource {
    const json = (value: unknown) => JSON.parse(JSON.stringify(value)) as unknown;
    return {
      log: async () => json({ log: this.id, public_key: this.publicKey, tree_head: this.head() }),
      entries: async (start, end) =>
        json({
          entries: this.leaves.slice(start, end).map((leaf, i) => ({
            index: start + i,
            leaf,
            leaf_hash: bytesToHex(leafHash(leafBytes(leaf))),
          })),
        }),
      signedEntry: async (index) => {
        if (!(index < this.size)) throw new Error(`No entry ${index}`);
        return json({ index, entry: this.signed[index] });
      },
      consistencyProof: async (first, second) => {
        if (!(first <= second && second <= this.size)) throw new Error(`No proof from ${first} to ${second}`);
        return json({ first, second, proof: (await consistencyProof(this.tree(), first, second)).map(bytesToHex) });
      },
      ...overrides,
    };
  }

  /** Answers GET requests for the log API at any origin, the way a node's routes do. */
  fetch(overrides: Partial<LogSource> = {}): typeof fetch {
    const source = this.source(overrides);
    return async (input) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const number = (name: string) => Number(url.searchParams.get(name));
      const signed = url.pathname.match(/^\/api\/v1\/log\/entries\/(\d+)\/signed$/);
      try {
        const body =
          url.pathname === "/api/v1/log"
            ? await source.log()
            : url.pathname === "/api/v1/log/entries"
              ? await source.entries(number("start"), number("end"))
              : url.pathname === "/api/v1/log/proofs/consistency"
                ? await source.consistencyProof(number("first"), number("second"))
                : signed
                  ? await source.signedEntry(Number(signed[1]))
                  : null;
        return body === null ? Response.json({ error: "Not found" }, { status: 404 }) : Response.json(body);
      } catch (error) {
        return Response.json({ error: (error as Error).message }, { status: 400 });
      }
    };
  }

  private tree() {
    return memorySource(this.leaves.map((leaf) => leafHash(leafBytes(leaf))));
  }
}
