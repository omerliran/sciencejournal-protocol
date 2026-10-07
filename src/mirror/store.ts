import { open, mkdir, readdir, readFile, rename, rm, stat, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { DigestSchema, type Digest } from "../hash";
import { JsonError, parseJson } from "../json";
import { TreeHeadSchema } from "../leaves";
import { MonitorError, MonitorStateSchema } from "../monitor";
import { ServedFilesSchema, type ServedFiles } from "../mirror";

// How a mirror keeps its copy in a directory, so any process can read it while another syncs:
//
//   mirror.json         what it holds: the pinned log and its audit, the tree head it serves
//                       with its checkpoints, the bundles withdrawn, and the files it skipped
//   log/<n>.jsonl       entries [n * 1000, (n + 1) * 1000), one a line: the leaf, its hash, the
//                       entry as signed, and the files the node served for it
//   log/leaf-hashes     every leaf's hash, 32 bytes each, for proofs
//   files/<hex>         each file, named by its SHA-256, so any web server can serve the folder
//
// Entries and files are written first and mirror.json last, each by renaming a finished file
// into place, so a crash leaves the copy as the last saved state says, plus files it can use.

/** Entries a log file holds. */
export const SEGMENT = 1000;
const HASH_BYTES = 32;

/** One entry as a mirror keeps it. */
export const StoredEntrySchema = z.strictObject({
  index: z.number().int().nonnegative(),
  leaf: z.record(z.string(), z.unknown()),
  leaf_hash: z.string().regex(/^[0-9a-f]{64}$/),
  signed: z.record(z.string(), z.unknown()),
  /** The files the node served for the entry when the mirror copied it. */
  files: ServedFilesSchema.optional(),
});
export type StoredEntry = z.infer<typeof StoredEntrySchema>;

/** A file the mirror didn't fetch: too large for its limit (with its size), or not served when asked (null). */
const SkippedSchema = z.record(DigestSchema, z.number().int().nonnegative().nullable());

export const MirrorStateSchema = z.strictObject({
  /** The node it last copied from. */
  node: z.string(),
  /** The pinned log, its last verified head, and the audit, which reaches as far as the entries held. */
  monitor: MonitorStateSchema,
  /**
   * The newest tree head it holds every entry of, which it serves, with the log's checkpoint
   * keys as the node served them and the checkpoints the monitor checked beside it: the one for
   * that head, and the node's newest witnessed one, when no larger than the head.
   */
  served: z
    .strictObject({
      head: TreeHeadSchema,
      checkpoint_keys: z.unknown().optional(),
      checkpoint: z.string().nullable(),
      witnessed: z.string().nullable(),
    })
    .nullable(),
  /** The bundles withdrawn on the log: nothing of theirs is kept or served. */
  withdrawn: z.array(DigestSchema),
  skipped: SkippedSchema,
  synced_at: z.iso.datetime(),
});
export type MirrorState = z.infer<typeof MirrorStateSchema>;

/** A file's place in the folder: its SHA-256 in hex. */
export function fileName(digest: Digest): string {
  return digest.slice("sha256:".length);
}

export class MirrorStore {
  constructor(readonly dir: string) {}

  get statePath(): string {
    return join(this.dir, "mirror.json");
  }

  private segmentPath(segment: number): string {
    return join(this.dir, "log", `${String(segment).padStart(6, "0")}.jsonl`);
  }

  private get hashesPath(): string {
    return join(this.dir, "log", "leaf-hashes");
  }

  filePath(digest: Digest): string {
    return join(this.dir, "files", fileName(digest));
  }

  /** The saved state, or null for a folder that holds no mirror yet. */
  async state(): Promise<MirrorState | null> {
    let text: string;
    try {
      text = await readFile(this.statePath, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw new MonitorError(`Can't read ${this.statePath}: ${(error as Error).message}`);
    }
    let value: unknown;
    try {
      value = parseJson(text);
    } catch (error) {
      if (!(error instanceof JsonError)) throw error;
      throw new MonitorError(`${this.statePath} isn't JSON: ${error.message}`);
    }
    const state = MirrorStateSchema.safeParse(value);
    if (!state.success) {
      const issue = state.error.issues[0];
      throw new MonitorError(`${this.statePath} isn't a mirror's state (${issue.path.join(".") || "/"}: ${issue.message})`);
    }
    return state.data;
  }

  async save(state: MirrorState): Promise<void> {
    await this.writeWhole(this.statePath, `${JSON.stringify(state, null, 2)}\n`);
  }

  /** How many entries the saved state says are held. */
  static held(state: MirrorState | null): number {
    return state?.monitor.audit.size ?? 0;
  }

  /**
   * Stores entries that follow the `held` already stored, in order. Anything a crashed run left
   * past `held` is dropped first.
   */
  async append(held: number, entries: readonly StoredEntry[]): Promise<void> {
    if (entries.length === 0) return;
    entries.forEach((entry, i) => {
      if (entry.index !== held + i) throw new Error(`Entry ${entry.index} doesn't follow the ${held} held`);
    });
    await mkdir(join(this.dir, "log"), { recursive: true });
    for (let start = 0; start < entries.length; ) {
      const segment = Math.floor((held + start) / SEGMENT);
      const kept = (held + start) % SEGMENT;
      const count = Math.min(SEGMENT - kept, entries.length - start);
      const before = kept === 0 ? [] : (await this.lines(segment)).slice(0, kept);
      if (before.length !== kept) throw new MonitorError(`${this.segmentPath(segment)} holds fewer entries than the state says`);
      const added = entries.slice(start, start + count).map((entry) => JSON.stringify(entry));
      await this.writeWhole(this.segmentPath(segment), `${[...before, ...added].join("\n")}\n`);
      start += count;
    }
    const handle = await open(this.hashesPath, "a+");
    try {
      await handle.truncate(held * HASH_BYTES);
      await handle.write(Buffer.concat(entries.map((entry) => Buffer.from(entry.leaf_hash, "hex"))), 0, entries.length * HASH_BYTES, held * HASH_BYTES);
    } finally {
      await handle.close();
    }
  }

  /** The stored lines of a log file, as text. */
  private async lines(segment: number): Promise<string[]> {
    try {
      return (await readFile(this.segmentPath(segment), "utf8")).split("\n").filter((line) => line.length > 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }

  /** The stored entries of one log file. */
  async segment(segment: number): Promise<StoredEntry[]> {
    return (await this.lines(segment)).map((line) => StoredEntrySchema.parse(JSON.parse(line)));
  }

  /** Each stored entry in [from, to), in order. */
  async *entries(from: number, to: number): AsyncGenerator<StoredEntry> {
    for (let segment = Math.floor(from / SEGMENT); segment * SEGMENT < to; segment++) {
      for (const entry of await this.segment(segment)) {
        if (entry.index >= from && entry.index < to) yield entry;
      }
    }
  }

  /** The hashes of leaves [0, size), for proofs. */
  async leafHashes(size: number): Promise<Uint8Array[]> {
    if (size === 0) return [];
    const bytes = await readFile(this.hashesPath);
    if (bytes.length < size * HASH_BYTES) throw new MonitorError(`${this.hashesPath} holds fewer leaves than the state says`);
    return Array.from({ length: size }, (_, i) => new Uint8Array(bytes.subarray(i * HASH_BYTES, (i + 1) * HASH_BYTES)));
  }

  /** Whether the folder holds a file. */
  async has(digest: Digest): Promise<boolean> {
    try {
      return (await stat(this.filePath(digest))).isFile();
    } catch {
      return false;
    }
  }

  /** Where to write a file before it is checked and moved into place. */
  async partialPath(digest: Digest): Promise<string> {
    await mkdir(join(this.dir, "files"), { recursive: true });
    return join(this.dir, "files", `.${fileName(digest)}.${process.pid}.partial`);
  }

  /** Moves a checked file into place. */
  async keep(partial: string, digest: Digest): Promise<void> {
    await rename(partial, this.filePath(digest));
  }

  /**
   * The digests the stored entries [0, held) name whose bundles weren't withdrawn: everything the
   * mirror should hold.
   */
  async wanted(held: number, withdrawn: ReadonlySet<string>): Promise<Set<Digest>> {
    const digests = new Set<Digest>();
    for await (const entry of this.entries(0, held)) {
      const served = entry.files;
      if (!served || (served.bundle && withdrawn.has(served.bundle))) continue;
      for (const digest of servedDigests(served)) digests.add(digest);
    }
    return digests;
  }

  /**
   * Deletes every file the folder holds that isn't wanted, such as those of a withdrawn bundle
   * and anything a crashed run left half written. Returns how many it deleted.
   */
  async sweep(wanted: ReadonlySet<Digest>): Promise<number> {
    let names: string[];
    try {
      names = await readdir(join(this.dir, "files"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return 0;
      throw error;
    }
    let deleted = 0;
    for (const name of names) {
      if (wanted.has(`sha256:${name}` as Digest)) continue;
      await rm(join(this.dir, "files", name), { force: true });
      if (!name.startsWith(".")) deleted++;
    }
    return deleted;
  }

  /**
   * Takes the folder for one sync at a time. A lock whose process has ended is taken over.
   * Returns a function that gives it back.
   */
  async lock(): Promise<() => Promise<void>> {
    await mkdir(this.dir, { recursive: true });
    const path = join(this.dir, "sync.lock");
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        await writeFile(path, `${process.pid}\n`, { flag: "wx" });
        return () => unlink(path).catch(() => undefined);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const pid = Number((await readFile(path, "utf8").catch(() => "")).trim());
        if (Number.isSafeInteger(pid) && pid > 0 && running(pid)) {
          throw new MonitorError(`Another sync (process ${pid}) is copying into ${this.dir}; wait for it to finish`);
        }
        await rm(path, { force: true });
      }
    }
    throw new MonitorError(`Can't take ${path}`);
  }

  /** Writes a file whole, so a reader never sees half of one. */
  private async writeWhole(path: string, text: string): Promise<void> {
    const partial = `${path}.${process.pid}.partial`;
    await writeFile(partial, text);
    await rename(partial, path);
  }
}

/** The digests of the files an entry's served list names. */
export function servedDigests(served: ServedFiles): Digest[] {
  return [...new Set("files" in served ? Object.values(served.files) : served.digests)];
}

function running(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}
