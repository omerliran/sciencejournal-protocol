import { createHash } from "node:crypto";
import { open, rm } from "node:fs/promises";
import { Readable } from "node:stream";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import type { Digest } from "../hash";
import { JsonError, parseJson } from "../json";
import type { TreeHead } from "../leaves";
import { FILES_PER_PAGE, ServedFilesPageSchema, servedFilesProblem, withdrawnBundle, type ServedFiles } from "../mirror";
import { MonitorError, monitorLog, type LogSource, type ProblemCheck } from "../monitor";
import { parseCheckpointNote } from "../notes";
import { getText, httpSource, nodeUrl, type HttpOptions } from "../monitor/http";
import { MirrorStore, servedDigests, type MirrorState, type StoredEntry } from "./store";

// One sync of a mirror: it copies what a node added to its log since the last sync, a step of
// entries at a time, and every file those entries name that the node serves. Each step runs a
// monitor's audit of the node first, through a source that records what the audit read, so the
// mirror keeps exactly the entries the audit checked; a log that misbehaved stops the sync
// before anything of it is kept. Then each entry's files are checked against the digest its
// signed entry names, and each file against its own digest as it arrives. A withdrawal entry
// deletes its bundle's files and the evidence about it, as the node stops serving them.

export interface SyncOptions {
  /** The most new entries to copy this run; all of them by default. */
  maxEntries?: number;
  /** Files larger than this many bytes aren't fetched; they are listed as skipped and fetched once the limit allows. */
  maxFileBytes?: number;
  /** Entries audited and stored at a time, so a long first sync keeps what it has copied if it stops. */
  step?: number;
  /** Files fetched at once. */
  concurrency?: number;
  fetch?: typeof fetch;
  /** The time now, in milliseconds since the epoch. */
  now?: () => number;
  /** How many times to try a request that may pass on another try, and how long to wait before the second. */
  attempts?: number;
  retryMs?: number;
}

/** A way the node misbehaved: one of a monitor's checks, or `files`, when what it served doesn't match the log. */
export interface MirrorProblem {
  check: ProblemCheck | "files";
  index?: number;
  reason: string;
  evidence?: unknown;
}

export interface SyncReport {
  node: string;
  dir: string;
  /** The log copied, once known. */
  log: string | null;
  /** Whether this run pinned the log, as a new mirror's first run does. */
  pinned: boolean;
  /** The tree head the mirror serves after this run. */
  head: TreeHead | null;
  /** The entries copied this run, [from, to). */
  copied: { from: number; to: number };
  /** Files fetched this run, and their bytes. */
  fetched: { files: number; bytes: number };
  /** Files not held: larger than the limit (with their size), or listed but not served when asked (null). */
  skipped: { digest: Digest; bytes: number | null }[];
  /** Bundles withdrawn on the log in the entries copied this run. */
  withdrawn: Digest[];
  /** Files deleted this run, as their bundles were withdrawn. */
  deleted: number;
  /** Entries whose files the node lists by digest alone, which were checked only against their own digests. */
  unpathed: number[];
  problems: MirrorProblem[];
  unchecked: string[];
  error: string | null;
}

/** 0 when every check passed, 1 when the node misbehaved, 2 when the sync couldn't finish. */
export function syncStatus(report: { problems: readonly unknown[]; error: string | null }): 0 | 1 | 2 {
  return report.problems.length > 0 ? 1 : report.error !== null ? 2 : 0;
}

/** Copies what `node` added to its log, and the files its entries name, into the mirror in `dir`. */
export async function syncMirror(dir: string, node: string, options: SyncOptions = {}): Promise<SyncReport> {
  const base = nodeUrl(node);
  const store = new MirrorStore(dir);
  const report: SyncReport = {
    node: base,
    dir,
    log: null,
    pinned: false,
    head: null,
    copied: { from: 0, to: 0 },
    fetched: { files: 0, bytes: 0 },
    skipped: [],
    withdrawn: [],
    deleted: 0,
    unpathed: [],
    problems: [],
    unchecked: [],
    error: null,
  };
  let unlock: (() => Promise<void>) | undefined;
  try {
    unlock = await store.lock();
    await copy(store, base, options, report);
  } catch (error) {
    report.error = error instanceof Error ? error.message : String(error);
  } finally {
    await unlock?.();
  }
  return report;
}

async function copy(store: MirrorStore, base: string, options: SyncOptions, report: SyncReport): Promise<void> {
  const http: HttpOptions = { fetch: options.fetch, attempts: options.attempts ?? 5, retryMs: options.retryMs ?? 2000 };
  const now = options.now ?? Date.now;
  const limit = options.maxEntries ?? Infinity;
  const unchecked = new Set<string>();
  let state = await store.state();
  report.log = state?.monitor.log ?? null;
  report.head = state?.served?.head ?? null;
  report.copied = { from: MirrorStore.held(state), to: MirrorStore.held(state) };

  for (;;) {
    const held = MirrorStore.held(state);
    const recorder = recording(httpSource(base, http));
    // A node this mirror hasn't copied from may lag behind the one it has, which proves it.
    const moved = state !== null && state.node !== base;
    const run = await monitorLog(recorder.source, state?.monitor ?? null, {
      maxEntries: Math.min(options.step ?? 1000, limit - (report.copied.to - report.copied.from)),
      ...(moved && { servedBefore: 0, ahead: httpSource(state!.node, http) }),
    });
    report.log = run.report.log;
    report.pinned ||= run.report.pinned;
    report.problems.push(...run.report.problems);
    for (const note of run.report.unchecked) unchecked.add(note);
    report.unchecked = [...unchecked];
    if (run.report.error !== null) report.error = run.report.error;
    if (!run.state) return;

    const monitored = run.state;
    const to = monitored.audit.size;
    const entries = recorder.entries(held, to);
    const served = await servedFiles(base, held, to, http);
    for (const files of served.values()) {
      const problem = servedFilesProblem(files, entries[files.index - held].signed);
      if (problem) report.problems.push({ check: "files", index: files.index, reason: problem, evidence: files });
      if (!("files" in files)) report.unpathed.push(files.index);
    }
    if (report.problems.length > 0) return;

    const withdrawn = new Set<string>(state?.withdrawn ?? []);
    const newly = entries.map((entry) => withdrawnBundle(entry.signed)).filter((bundle) => bundle !== null);
    for (const bundle of newly) withdrawn.add(bundle);
    const skipped = { ...state?.skipped };
    const wanted = new Set<Digest>();
    for (const files of served.values()) {
      if (files.bundle && withdrawn.has(files.bundle)) continue;
      for (const digest of servedDigests(files)) wanted.add(digest);
    }
    await fetchFiles(store, base, [...wanted], skipped, options, http, report);
    if (report.problems.length > 0) return;

    await store.append(
      held,
      entries.map((entry) => ({ ...entry, ...(served.has(entry.index) && { files: served.get(entry.index) }) })),
    );
    if (newly.length > 0) {
      const kept = await store.wanted(to, withdrawn);
      report.deleted += await store.sweep(kept);
      for (const digest of Object.keys(skipped) as Digest[]) if (!kept.has(digest)) delete skipped[digest];
      report.withdrawn.push(...newly);
    }

    const head = monitored.head;
    const next: MirrorState = {
      node: base,
      monitor: monitored,
      served: head && to === head.size ? servedHead(head, recorder) : (state?.served ?? null),
      withdrawn: [...withdrawn] as Digest[],
      skipped,
      synced_at: new Date(now()).toISOString(),
    };
    await store.save(next);
    state = next;
    report.head = next.served?.head ?? null;
    report.copied.to = to;
    if (to === held || to >= (head?.size ?? 0) || report.copied.to - report.copied.from >= limit) break;
  }

  // Files skipped before, which the limit may allow now or the node may serve now.
  const retry = Object.entries(state?.skipped ?? {})
    .filter(([, bytes]) => bytes === null || options.maxFileBytes === undefined || bytes <= options.maxFileBytes)
    .map(([digest]) => digest as Digest);
  if (state && retry.length > 0) {
    const skipped = { ...state.skipped };
    for (const digest of retry) delete skipped[digest];
    await fetchFiles(store, base, retry, skipped, options, http, report);
    if (report.problems.length > 0) return;
    state = { ...state, skipped };
    await store.save(state);
  }
  report.skipped = Object.entries(state?.skipped ?? {}).map(([digest, bytes]) => ({ digest: digest as Digest, bytes }));
}

/** What the mirror serves as its head: the head, with the checkpoint keys and checkpoints the audit checked beside it. */
function servedHead(head: TreeHead, recorder: Recorder): MirrorState["served"] {
  const info = recorder.info() as { checkpoint_keys?: unknown } | undefined;
  const checkpoint = recorder.checkpoint(String(head.size));
  const witnessed = recorder.checkpoint("newest");
  // A witnessed checkpoint newer than the head would need a proof from a tree the mirror doesn't hold.
  const usable = witnessed !== null && parseCheckpointNote(witnessed).size <= head.size;
  return {
    head,
    ...(info?.checkpoint_keys !== undefined && { checkpoint_keys: info.checkpoint_keys }),
    checkpoint,
    witnessed: usable ? witnessed : null,
  };
}

/** The files the node serves for entries [from, to), by index, a page at a time. */
async function servedFiles(base: string, from: number, to: number, http: HttpOptions): Promise<Map<number, ServedFiles>> {
  const served = new Map<number, ServedFiles>();
  for (let start = from; start < to; start += FILES_PER_PAGE) {
    const end = Math.min(to, start + FILES_PER_PAGE);
    const url = `${base}/api/v1/files?start=${start}&end=${end}`;
    let page;
    try {
      page = ServedFilesPageSchema.safeParse(parseJson((await getText(url, "application/json", http))!));
    } catch (error) {
      if (!(error instanceof JsonError)) throw error;
      throw new MonitorError(`GET ${url} answered with something other than I-JSON: ${error.message}`);
    }
    if (!page.success) throw new MonitorError(`GET ${url} answered with something other than a list of entries' files: ${page.error.issues[0].message}`);
    let last = start - 1;
    for (const files of page.data.entries) {
      if (files.index <= last || files.index >= end) throw new MonitorError(`GET ${url} listed entry ${files.index}, out of order or out of range`);
      last = files.index;
      served.set(files.index, files);
    }
  }
  return served;
}

/** Fetches the files the mirror doesn't hold yet, checking each against its digest. */
async function fetchFiles(
  store: MirrorStore,
  base: string,
  digests: readonly Digest[],
  skipped: Record<string, number | null>,
  options: SyncOptions,
  http: HttpOptions,
  report: SyncReport,
): Promise<void> {
  const missing: Digest[] = [];
  for (const digest of digests) if (!(await store.has(digest))) missing.push(digest);
  await inParallel(missing, options.concurrency ?? 4, async (digest) => {
    const got = await download(store, `${base}/api/v1/files/${digest}`, digest, options.maxFileBytes, http);
    if ("bytes" in got) {
      report.fetched.files++;
      report.fetched.bytes += got.bytes;
    } else if ("tooLarge" in got) {
      skipped[digest] = got.tooLarge;
    } else if ("missing" in got) {
      skipped[digest] = null;
    } else {
      report.problems.push({ check: "files", reason: `The node served bytes that hash to ${got.wrong} for the file ${digest}`, evidence: { digest, served: got.wrong } });
    }
  });
}

type Download = { bytes: number } | { tooLarge: number } | { missing: true } | { wrong: Digest };

/** Downloads one file into place, if it is what its digest says and no larger than `max`. */
async function download(store: MirrorStore, url: string, digest: Digest, max: number | undefined, http: HttpOptions): Promise<Download> {
  const { fetch: get = fetch, attempts = 5, retryMs = 2000 } = http;
  for (let attempt = 1; ; attempt++) {
    const retry = attempt < attempts;
    let response: Response;
    try {
      // A large file redirects to storage, which fetch follows.
      response = await get(url, { signal: AbortSignal.timeout(30 * 60_000) });
    } catch (error) {
      if (retry) {
        await pause(retryMs * attempt);
        continue;
      }
      throw new MonitorError(`GET ${url} failed: ${(error as Error).message}`);
    }
    if (response.status === 404) {
      await response.body?.cancel();
      return { missing: true };
    }
    if (!response.ok) {
      await response.body?.cancel();
      if (retry && (response.status === 429 || response.status >= 500)) {
        await pause(retryMs * attempt);
        continue;
      }
      throw new MonitorError(`GET ${url} answered ${response.status}`);
    }
    const declared = Number(response.headers.get("content-length"));
    if (max !== undefined && Number.isFinite(declared) && declared > max) {
      await response.body?.cancel();
      return { tooLarge: declared };
    }
    const partial = await store.partialPath(digest);
    const hash = createHash("sha256");
    const handle = await open(partial, "w");
    let bytes = 0;
    try {
      const body: AsyncIterable<Uint8Array> = Readable.fromWeb((response.body ?? new ReadableStream()) as WebReadableStream<Uint8Array>);
      for await (const chunk of body) {
        bytes += chunk.length;
        if (max !== undefined && bytes > max) {
          await handle.close();
          await rm(partial, { force: true });
          return { tooLarge: bytes };
        }
        hash.update(chunk);
        await handle.write(chunk);
      }
    } catch (error) {
      await handle.close().catch(() => undefined);
      await rm(partial, { force: true });
      if (retry) {
        await pause(retryMs * attempt);
        continue;
      }
      throw new MonitorError(`GET ${url} stopped partway: ${(error as Error).message}`);
    }
    await handle.close();
    const served = `sha256:${hash.digest("hex")}` as Digest;
    if (served !== digest) {
      await rm(partial, { force: true });
      return { wrong: served };
    }
    await store.keep(partial, digest);
    return { bytes };
  }
}

interface Recorder {
  source: LogSource;
  /** What GET /api/v1/log answered. */
  info(): unknown;
  /** The entries [from, to) the audit read, each with its entry as signed. */
  entries(from: number, to: number): Omit<StoredEntry, "files">[];
  /** A checkpoint the audit read: by its size, or "newest" for the one the node serves by default. */
  checkpoint(size: string): string | null;
}

/** A log source that keeps what it answered, so the mirror stores what the audit read. */
function recording(source: LogSource): Recorder {
  let info: unknown;
  const leaves = new Map<number, { leaf: Record<string, unknown>; leaf_hash: string }>();
  const signed = new Map<number, Record<string, unknown>>();
  const checkpoints = new Map<string, string | null>();
  return {
    source: {
      ...source,
      log: async () => (info = await source.log()),
      entries: async (start, end) => {
        const answer = await source.entries(start, end);
        for (const entry of (answer as { entries?: { index: number; leaf: Record<string, unknown>; leaf_hash: string }[] }).entries ?? []) {
          leaves.set(entry.index, { leaf: entry.leaf, leaf_hash: entry.leaf_hash });
        }
        return answer;
      },
      signedEntry: async (index) => {
        const answer = await source.signedEntry(index);
        signed.set(index, (answer as { entry: Record<string, unknown> }).entry);
        return answer;
      },
      ...(source.checkpoint && {
        checkpoint: async (size?: number) => {
          const text = await source.checkpoint!(size);
          checkpoints.set(size === undefined ? "newest" : String(size), text);
          return text;
        },
      }),
    },
    info: () => info,
    entries(from, to) {
      return Array.from({ length: to - from }, (_, i) => {
        const index = from + i;
        const leaf = leaves.get(index);
        const entry = signed.get(index);
        if (!leaf || !entry) throw new MonitorError(`The audit checked entry ${index}, but the mirror didn't keep what it read`);
        return { index, leaf: leaf.leaf, leaf_hash: leaf.leaf_hash, signed: entry };
      });
    },
    checkpoint: (size) => checkpoints.get(size) ?? null,
  };
}

/** Runs `work` on each item with at most `limit` at once. */
async function inParallel<T>(items: readonly T[], limit: number, work: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) await work(items[next++]);
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
