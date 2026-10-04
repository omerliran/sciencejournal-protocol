import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { signObject } from "../entries";
import { detachLeaf, leafBytes, logId, type LogLeaf, type SignedLeaf, type TreeHead } from "../leaves";
import { consistencyProof, inclusionProof, leafHash, memorySource, rootHash } from "../merkle";
import type { LogSource } from "../monitor";
import { checkpointOrigin, checkpointText, NOTE_SIGNATURE_TYPES, noteVerifier, signNote, verifierKey, type CheckpointKeys } from "../notes";
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
  /** Its checkpoints' origin, and the Ed25519 seed of the key that signs them. */
  readonly origin: string;
  readonly checkpointSeed: Uint8Array;
  /** Witnesses' cosignature lines, by the size of the checkpoint each cosigned. */
  readonly cosignatures = new Map<number, string[]>();
  /** Where other logs hold each entry, by index, as a receipt's `copies` says. */
  readonly copies = new Map<number, { log: string; index: number }[]>();
  private keys: CheckpointKeys | null = null;

  constructor(readonly secretKey: Uint8Array = generateKeyPair().secretKey) {
    this.publicKey = publicKeyOf(secretKey);
    this.id = logId(this.publicKey);
    this.origin = checkpointOrigin(this.id);
    this.checkpointSeed = sha512(concatBytes(utf8ToBytes("checkpoint key:"), secretKey)).subarray(0, 32);
  }

  /** Its checkpoint key, as a vkey. */
  get checkpointKey(): string {
    return verifierKey(noteVerifier(this.origin, NOTE_SIGNATURE_TYPES.ed25519, ed25519.getPublicKey(this.checkpointSeed)));
  }

  /** Its checkpoint keys, signed by the log's key, as GET /api/v1/log serves them. Signed once, as hybrid signing is randomized. */
  checkpointKeys(): CheckpointKeys {
    this.keys ??= signObject({ type: "checkpoint_keys" as const, log: this.id, origin: this.origin, keys: [this.checkpointKey] }, this.secretKey);
    return this.keys;
  }

  /** The checkpoint of size `size`, signed, with any cosignatures for it; by default the newest cosigned, else the newest. */
  checkpoint(size?: number): string | null {
    const witnessed = [...this.cosignatures.keys()].filter((at) => at <= this.size);
    const at = size ?? (witnessed.length > 0 ? Math.max(...witnessed) : this.size);
    const head = this.heads[at - 1];
    if (!head) return null;
    const text = checkpointText(this.origin, head.size, head.root);
    return `${text}\n${signNote(text, this.origin, this.checkpointSeed)}${(this.cosignatures.get(at) ?? []).join("")}`;
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
      log: async () => json({ log: this.id, public_key: this.publicKey, tree_head: this.head(), checkpoint_keys: this.checkpointKeys() }),
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
      checkpoint: async (size) => this.checkpoint(size),
      receipt: async (index) => {
        const head = this.head();
        if (!head || !(index < this.size)) throw new Error(`No entry ${index}`);
        const proof = (await inclusionProof(this.tree(), index, head.size)).map(bytesToHex);
        const leaf = this.leaves[index];
        return json({ log: this.id, index, leaf, leaf_hash: bytesToHex(leafHash(leafBytes(leaf))), tree_head: head, inclusion_proof: proof, copies: this.copies.get(index) ?? [] });
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
      const receipt = url.pathname.match(/^\/api\/v1\/log\/entries\/(\d+)$/);
      try {
        if (url.pathname === "/api/v1/log/checkpoint") {
          const text = await source.checkpoint!(url.searchParams.has("size") ? number("size") : undefined);
          return text === null ? Response.json({ error: "Not found" }, { status: 404 }) : new Response(text, { headers: { "content-type": "text/plain; charset=utf-8" } });
        }
        const body =
          url.pathname === "/api/v1/log"
            ? await source.log()
            : url.pathname === "/api/v1/log/entries"
              ? await source.entries(number("start"), number("end"))
              : url.pathname === "/api/v1/log/proofs/consistency"
                ? await source.consistencyProof(number("first"), number("second"))
                : signed
                  ? await source.signedEntry(Number(signed[1]))
                  : receipt
                    ? await source.receipt!(Number(receipt[1]))
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
