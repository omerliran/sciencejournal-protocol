import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { Readable } from "node:stream";
import { bytesToHex } from "@noble/hashes/utils.js";
import { DigestSchema } from "../hash";
import { ENTRIES_PER_PAGE } from "../monitor";
import { consistencyProof, inclusionProof, nodeHash, type SubtreeSource } from "../merkle";
import { FILES_PER_PAGE, type ServedFiles } from "../mirror";
import { MirrorStore, SEGMENT, type MirrorState, type StoredEntry } from "./store";

// A mirror serves its copy the way a node serves the record: the log's read API, so a monitor
// or a reader checks it as it would the node, and each file by its digest, under the same
// paths. It answers only from what the last sync saved, up to the tree head it holds every
// entry of, and serves nothing of a withdrawn bundle. It takes nothing: every write goes to a
// node.

interface Loaded {
  /** Which save of mirror.json this is: each save replaces the file, so its inode changes. */
  version: string;
  state: MirrorState | null;
  size: number;
  tree: SubtreeSource | null;
  withdrawn: Set<string>;
  segments: Map<number, StoredEntry[]>;
}

/** Answers GET requests for a mirror's copy in `dir`, the way a node's routes answer them. */
export function mirrorHandler(dir: string): (request: Request) => Promise<Response> {
  const store = new MirrorStore(dir);
  let loaded: Loaded | null = null;

  async function current(): Promise<Loaded> {
    const saved = await stat(store.statePath).catch(() => null);
    const version = saved ? `${saved.ino}:${saved.mtimeMs}:${saved.size}` : "none";
    if (loaded?.version === version) return loaded;
    const state = await store.state();
    const size = state?.served?.head.size ?? 0;
    const tree = loaded && loaded.size === size ? loaded.tree : size > 0 ? levelSource(await store.leafHashes(size)) : null;
    loaded = { version, state, size, tree, withdrawn: new Set(state?.withdrawn), segments: new Map() };
    return loaded;
  }

  async function entry(view: Loaded, index: number): Promise<StoredEntry> {
    const segment = Math.floor(index / SEGMENT);
    let entries = view.segments.get(segment);
    if (!entries) {
      entries = await store.segment(segment);
      if (view.segments.size >= 8) view.segments.delete(view.segments.keys().next().value!);
      view.segments.set(segment, entries);
    }
    return entries[index % SEGMENT];
  }

  return async (request) => {
    if (request.method !== "GET" && request.method !== "HEAD") return error(405, "A mirror only serves reads; send writes to a node");
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "");
    try {
      if (path === "/api/health") return Response.json({ status: "ok" });
      const view = await current();
      const { state } = view;
      if (!state) return error(503, "This mirror holds nothing yet");
      const served = state.served;

      if (path === "/api/v1/log") {
        return Response.json({
          log: state.monitor.log,
          public_key: state.monitor.public_key,
          tree_head: served?.head ?? null,
          ...(served?.checkpoint_keys !== undefined && { checkpoint_keys: served.checkpoint_keys }),
          mirror: { of: state.node, synced_at: state.synced_at },
        });
      }
      if (path === "/api/v1/log/entries") {
        const [start, end] = [int(url, "start"), url.searchParams.has("end") ? int(url, "end") : int(url, "start") + ENTRIES_PER_PAGE];
        if (end < start || end - start > ENTRIES_PER_PAGE) return error(400, `Request between 0 and ${ENTRIES_PER_PAGE} entries, with end >= start`);
        const entries = [];
        for (let index = start; index < Math.min(end, view.size); index++) {
          const { leaf, leaf_hash } = await entry(view, index);
          entries.push({ index, leaf, leaf_hash });
        }
        return Response.json({ entries });
      }
      const signed = path.match(/^\/api\/v1\/log\/entries\/(0|[1-9][0-9]*)\/signed$/);
      if (signed) {
        const index = Number(signed[1]);
        if (index >= view.size) return error(404, "No entry at that index");
        return Response.json({ index, entry: (await entry(view, index)).signed });
      }
      const receipt = path.match(/^\/api\/v1\/log\/entries\/(0|[1-9][0-9]*)$/);
      if (receipt) {
        const index = Number(receipt[1]);
        if (index >= view.size || !served) return error(404, "No entry at that index");
        const { leaf, leaf_hash } = await entry(view, index);
        const proof = await inclusionProof(view.tree!, index, view.size);
        return Response.json({ log: state.monitor.log, index, leaf, leaf_hash, tree_head: served.head, inclusion_proof: proof.map(bytesToHex) });
      }
      if (path === "/api/v1/log/proofs/inclusion") {
        const [index, size] = [int(url, "index"), int(url, "size")];
        if (index >= size || size > view.size) return error(400, "Need index < size <= the log's current size");
        return Response.json({ index, size, proof: (await inclusionProof(view.tree!, index, size)).map(bytesToHex) });
      }
      if (path === "/api/v1/log/proofs/consistency") {
        const [first, second] = [int(url, "first"), int(url, "second")];
        if (first > second || second > view.size) return error(400, "Need first <= second <= the log's current size");
        const proof = second === 0 ? [] : await consistencyProof(view.tree!, first, second);
        return Response.json({ first, second, proof: proof.map(bytesToHex) });
      }
      if (path === "/api/v1/log/checkpoint") {
        const size = url.searchParams.has("size") ? int(url, "size") : undefined;
        const text = size === undefined ? (served?.witnessed ?? served?.checkpoint) : size === served?.head.size ? served.checkpoint : null;
        if (!text) return error(404, size === undefined ? "This mirror holds no checkpoint" : "This mirror holds no checkpoint of that size");
        return new Response(text, { headers: { "content-type": "text/plain; charset=utf-8" } });
      }
      if (path === "/api/v1/files") {
        const [start, end] = [int(url, "start"), int(url, "end")];
        if (end < start || end - start > FILES_PER_PAGE) return error(400, `Request between 0 and ${FILES_PER_PAGE} entries, with end >= start`);
        const entries: ServedFiles[] = [];
        for (let index = start; index < Math.min(end, view.size); index++) {
          const { files } = await entry(view, index);
          if (files && !(files.bundle && view.withdrawn.has(files.bundle))) entries.push(files);
        }
        return Response.json({ entries });
      }
      const file = path.match(/^\/api\/v1\/files\/([^/]+)$/);
      if (file) {
        const given = decodeURIComponent(file[1]);
        const digest = DigestSchema.safeParse(given.startsWith("sha256:") ? given : `sha256:${given}`);
        if (!digest.success) return error(400, "Name a file by its SHA-256 digest");
        const found = await stat(store.filePath(digest.data)).catch(() => null);
        if (!found?.isFile()) return error(404, "No file with that digest");
        const body = request.method === "HEAD" ? null : (Readable.toWeb(createReadStream(store.filePath(digest.data))) as ReadableStream<Uint8Array>);
        return new Response(body, {
          headers: {
            "content-type": "application/octet-stream",
            "content-length": String(found.size),
            "cache-control": "public, max-age=31536000, immutable",
          },
        });
      }
      return error(404, "A mirror serves the log's read API and files by digest; this isn't one of them");
    } catch (thrown) {
      if (thrown instanceof BadRequest) return error(400, thrown.message);
      throw thrown;
    }
  };
}

class BadRequest extends Error {}

/** A whole-number query parameter. */
function int(url: URL, name: string): number {
  const value = url.searchParams.get(name);
  if (value === null || !/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value))) {
    throw new BadRequest(`${name} must be a non-negative integer`);
  }
  return Number(value);
}

function error(status: number, message: string): Response {
  return Response.json({ error: message }, { status });
}

/**
 * Every perfect subtree's hash over a list of leaf hashes, computed once, so each proof reads
 * only the hashes it needs.
 */
function levelSource(leaves: Uint8Array[]): SubtreeSource {
  const levels: Uint8Array[][] = [leaves];
  for (let below = leaves; below.length > 1; ) {
    const above: Uint8Array[] = [];
    for (let i = 0; i + 1 < below.length; i += 2) above.push(nodeHash(below[i], below[i + 1]));
    levels.push(above);
    below = above;
  }
  return {
    node: async (level, index) => {
      const hash = levels[level]?.[index];
      if (!hash) throw new RangeError(`No subtree ${index} at level ${level}`);
      return hash;
    },
  };
}
