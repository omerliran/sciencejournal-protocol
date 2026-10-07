import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { digestBundle, digestEvidence } from "../bundle";
import { operatorId, signObject } from "../entries";
import { sha256Digest, type Digest } from "../hash";
import { monitorLog } from "../monitor";
import { MemoryLog } from "../monitor/memory-log";
import { httpSource } from "../monitor/http";
import type { ServedFiles } from "../mirror";
import { verifyReceipt, type Receipt } from "../receipts";
import { generateKeyPair } from "../signing";
import { main, type Io } from "./cli";
import { mirrorHandler } from "./serve";
import { syncMirror } from "./sync";

// The reference mirror against a node made of an in-memory log and the files its entries name:
// it copies both, checks each against the log, follows withdrawals, and serves the copy so a
// monitor checks it as it checks the node.

const alice = generateKeyPair(); // publishes
const bob = generateKeyPair(); // verifies
const [aliceId, bobId] = [alice, bob].map((keys) => operatorId(keys.publicKey));
const CLAIM = `claim:${"c".repeat(64)}` as const;
const NODE = "https://node.test";
const text = (words: string) => new TextEncoder().encode(words);

type Files = Map<string, Uint8Array>;

/** A node: its log, the files it serves for each entry, and their bytes. */
class TestNode {
  readonly log = new MemoryLog();
  readonly served = new Map<number, ServedFiles>();
  readonly blobs = new Map<string, Uint8Array>();
  /** Requests it answered, by path. */
  readonly requests: string[] = [];
  /** Replaces the bytes served for a digest, as a node that misbehaves might. */
  readonly tampered = new Map<string, Uint8Array>();

  async setUp() {
    await this.log.append({ operator: aliceId, entry: signObject({ type: "key" as const, key: alice.publicKey, name: "Publisher", model_families: ["family-a"] }, alice.secretKey) });
    await this.log.append({ operator: aliceId, entry: signObject({ type: "identity" as const, kind: "invited" as const, operator: aliceId }, this.log.secretKey), organization: aliceId });
    await this.log.append({ operator: bobId, entry: signObject({ type: "key" as const, key: bob.publicKey, name: "Verifier", model_families: ["family-b"] }, bob.secretKey) });
    await this.log.append({
      operator: bobId,
      entry: signObject({ type: "identity" as const, kind: "domain" as const, operator: bobId, domain: "lab.example.org" }, bob.secretKey),
      organization: "example.org",
    });
  }

  /** Publishes a bundle of `files` and serves them. Returns its hash. */
  async bundle(files: Files): Promise<Digest> {
    const { bundle, files: digests } = digestBundle(files);
    const index = await this.log.append({
      operator: aliceId,
      entry: signObject({ type: "bundle" as const, bundle }, alice.secretKey),
      claims: [CLAIM],
      fields: ["mathematics"],
    });
    this.serve(index, { index, bundle, files: digests }, files);
    return bundle;
  }

  /** Logs bob's attestation on `bundle` with `evidence`, and serves it, path by path or (as entries logged before nodes kept paths) by digest alone. */
  async attest(bundle: Digest, evidence: Files, paths = true): Promise<number> {
    const { evidence: digest, files: digests } = digestEvidence(evidence);
    const entry = signObject(
      {
        type: "attestation" as const,
        job: "reproduction" as const,
        verifier: bobId,
        bundle,
        claims: { [CLAIM]: "reproduced" as const },
        evidence: digest,
        model_family: "family-b",
        harness: "test harness",
        hazard: "none" as const,
      },
      bob.secretKey,
    );
    const index = await this.log.append({ operator: bobId, entry });
    this.serve(index, paths ? { index, bundle, files: digests } : { index, bundle, digests: Object.values(digests) }, evidence);
    return index;
  }

  /** Withdraws a bundle, as a person at the node does on a notice: nothing of it or about it is served after. */
  async withdraw(bundle: Digest): Promise<number> {
    for (const [index, files] of this.served) if (files.bundle === bundle) this.served.delete(index);
    return this.log.append({ entry: signObject({ type: "withdrawal" as const, bundle, reason: "copyright" as const }, this.log.secretKey) });
  }

  private serve(index: number, files: ServedFiles, bytes: Files) {
    this.served.set(index, files);
    for (const content of bytes.values()) this.blobs.set(sha256Digest(content), content);
  }

  /** Answers GET requests the way a node's routes do. */
  fetch(): typeof fetch {
    const logFetch = this.log.fetch();
    return async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      this.requests.push(url.pathname);
      if (url.pathname === "/api/v1/files") {
        const [start, end] = [Number(url.searchParams.get("start")), Number(url.searchParams.get("end"))];
        return Response.json({ entries: [...this.served.values()].filter((files) => files.index >= start && files.index < end).sort((a, b) => a.index - b.index) });
      }
      const file = url.pathname.match(/^\/api\/v1\/files\/(.+)$/);
      if (file) {
        const digest = decodeURIComponent(file[1]);
        const listed = [...this.served.values()].some((files) => ("files" in files ? Object.values(files.files) : files.digests).includes(digest as Digest));
        const bytes = this.tampered.get(digest) ?? this.blobs.get(digest);
        if (!listed || !bytes) return Response.json({ error: "No file with that digest" }, { status: 404 });
        return new Response(bytes as Uint8Array<ArrayBuffer>, { headers: { "content-type": "application/octet-stream", "content-length": String(bytes.length) } });
      }
      return logFetch(input, init);
    };
  }
}

const paper = (title: string): Files =>
  new Map([
    ["paper.md", text(`# ${title}\n\nIt holds.\n`)],
    ["claims.json", text('[{"local_id": "C1"}]\n')],
    ["signature", text(`signature of ${title}`)],
  ]);
const report = (words: string): Files => new Map([["report.md", text(words)]]);

/** A JSON answer, read as the type it should have. */
const json = async <T = Record<string, unknown>>(answer: Promise<Response>) => (await (await answer).json()) as T;

/** A fetch that asks the mirror's handler. */
const fetchFrom = (dir: string): typeof fetch => {
  const handle = mirrorHandler(dir);
  return (input, init) => handle(new Request(input, init));
};

let node: TestNode;
let dir: string;

beforeEach(async () => {
  node = new TestNode();
  await node.setUp();
  dir = await mkdtemp(join(tmpdir(), "sj-mirror-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const sync = (options: Parameters<typeof syncMirror>[2] = {}) => syncMirror(dir, NODE, { fetch: node.fetch(), retryMs: 0, ...options });
const held = async () => (await readdir(join(dir, "files"))).sort();
const hex = (digest: Digest) => digest.slice("sha256:".length);

describe("syncing a mirror", () => {
  it("copies the log and every file its entries name, and serves a copy a monitor checks as it checks the node", async () => {
    const bundle = await node.bundle(paper("Primes"));
    const attestation = await node.attest(bundle, report("Re-ran it; it holds."));

    const synced = await sync();
    expect(synced).toMatchObject({ problems: [], error: null, pinned: true, copied: { from: 0, to: 6 }, fetched: { files: 4 }, skipped: [] });
    expect(synced.head).toEqual(node.log.head());
    expect(await held()).toEqual([...node.blobs.keys()].map((digest) => hex(digest as Digest)).sort());

    // A monitor reads the mirror as a node, and finds what it finds on the node.
    const mirror = fetchFrom(dir);
    const checked = await monitorLog(httpSource("https://mirror.test", { fetch: mirror }), null);
    expect(checked.report).toMatchObject({ problems: [], error: null, head: node.log.head(), audited: 6 });
    expect(checked.report.witnessing?.keys).toEqual([node.log.checkpointKey]);
    const info = await json(mirror("https://mirror.test/api/v1/log"));
    expect(info).toMatchObject({ log: node.log.id, public_key: node.log.publicKey, mirror: { of: NODE } });

    // A receipt from the mirror verifies against the log's key.
    const receipt = await json<Receipt>(mirror(`https://mirror.test/api/v1/log/entries/${attestation}`));
    expect(verifyReceipt(receipt, node.log.publicKey)).toBe(true);

    // It lists each entry's files as the node does, and serves each file by its digest.
    const listed = await json<{ entries: ServedFiles[] }>(mirror("https://mirror.test/api/v1/files?start=0&end=100"));
    expect(listed.entries).toEqual([...node.served.values()]);
    const paperDigest = sha256Digest(paper("Primes").get("paper.md")!);
    const served = await mirror(`https://mirror.test/api/v1/files/${paperDigest}`);
    expect(served.status).toBe(200);
    expect(await served.text()).toBe("# Primes\n\nIt holds.\n");
    expect((await mirror(`https://mirror.test/api/v1/files/${hex(paperDigest)}`)).status).toBe(200);
    expect((await mirror(`https://mirror.test/api/v1/files/${sha256Digest("nothing")}`)).status).toBe(404);
  });

  it("copies only what is new, and fetches no file twice", async () => {
    const bundle = await node.bundle(paper("Primes"));
    expect((await sync()).copied).toEqual({ from: 0, to: 5 });
    // A second bundle shares its claims file with the first.
    await node.bundle(paper("Primes, again"));
    node.requests.length = 0;
    const again = await sync();
    expect(again).toMatchObject({ problems: [], error: null, pinned: false, copied: { from: 5, to: 6 }, fetched: { files: 2 } });
    expect(node.requests.filter((path) => path.startsWith("/api/v1/files/"))).toHaveLength(2);
    expect((await sync()).copied).toEqual({ from: 6, to: 6 });
    expect(bundle).toMatch(/^sha256:/);
  });

  it("deletes a withdrawn bundle's files and the evidence about it, but keeps a file another bundle holds", async () => {
    const kept = await node.bundle(paper("Primes"));
    const withdrawn = await node.bundle(paper("Primes, again"));
    await node.attest(withdrawn, report("Re-ran the second; it holds."));
    await sync();
    const before = await held();
    expect(before).toHaveLength(6);

    await node.withdraw(withdrawn);
    const after = await sync();
    expect(after).toMatchObject({ problems: [], error: null, withdrawn: [withdrawn], deleted: 3 });
    const shared = hex(sha256Digest(paper("Primes").get("claims.json")!));
    expect(await held()).toEqual([...digestBundleFiles(paper("Primes"))].map(hex).sort());
    expect(await held()).toContain(shared);

    // The mirror serves nothing of it, as the node doesn't.
    const mirror = fetchFrom(dir);
    const listed = await json<{ entries: ServedFiles[] }>(mirror("https://mirror.test/api/v1/files?start=0&end=100"));
    expect(listed.entries.map((files) => files.bundle)).toEqual([kept]);
    const paperDigest = sha256Digest(paper("Primes, again").get("paper.md")!);
    expect((await mirror(`https://mirror.test/api/v1/files/${paperDigest}`)).status).toBe(404);
  });

  it("never fetches the files of a bundle withdrawn before the mirror reached it", async () => {
    const withdrawn = await node.bundle(paper("Primes"));
    // Served while the mirror copies its entry, as a node that hadn't yet taken it down would.
    const files = node.served.get(4)!;
    await node.withdraw(withdrawn);
    node.served.set(4, files);
    const synced = await sync();
    expect(synced).toMatchObject({ problems: [], error: null, fetched: { files: 0 }, withdrawn: [withdrawn] });
  });

  it("refuses files that aren't the ones the entry names, and keeps nothing of that step", async () => {
    const bundle = await node.bundle(paper("Primes"));
    await sync();
    const index = await node.attest(bundle, report("Re-ran it."));
    const listed = node.served.get(index) as Extract<ServedFiles, { files: unknown }>;
    node.served.set(index, { ...listed, files: { ...listed.files, "extra.txt": sha256Digest("extra") } });
    const synced = await sync();
    expect(synced.problems).toEqual([
      expect.objectContaining({ check: "files", index, reason: expect.stringContaining(`hash to`) }),
    ]);
    expect(synced.copied).toEqual({ from: 5, to: 5 });
    expect(await main(["sync", NODE, dir], io(node.fetch()))).toBe(1);
  });

  it("refuses bytes that aren't what their digest says", async () => {
    const files = paper("Primes");
    await node.bundle(files);
    node.tampered.set(sha256Digest(files.get("paper.md")!), text("# Composites\n"));
    const synced = await sync();
    expect(synced.problems).toEqual([expect.objectContaining({ check: "files", reason: expect.stringContaining("hash to") })]);
    expect(synced.copied).toEqual({ from: 0, to: 0 });
    expect((await readdir(join(dir, "files"))).filter((name) => !name.startsWith("."))).toHaveLength(2);
  });

  it("skips files larger than its limit, and fetches them once the limit allows", async () => {
    const files = paper("Primes");
    files.set("data/table.csv", text("x\n".repeat(100)));
    await node.bundle(files);
    const limited = await sync({ maxFileBytes: 100 });
    const table = sha256Digest(files.get("data/table.csv")!);
    expect(limited).toMatchObject({ problems: [], error: null, skipped: [{ digest: table, bytes: 200 }] });
    expect(await held()).not.toContain(hex(table));
    const later = await sync({ maxFileBytes: 1000 });
    expect(later).toMatchObject({ problems: [], skipped: [], fetched: { files: 1, bytes: 200 } });
    expect(await held()).toContain(hex(table));
  });

  it("fetches the files an entry lists by digest alone, and says they weren't checked against the entry", async () => {
    const bundle = await node.bundle(paper("Primes"));
    const index = await node.attest(bundle, report("Re-ran it."), false);
    const synced = await sync();
    expect(synced).toMatchObject({ problems: [], error: null, unpathed: [index] });
    expect(await held()).toContain(hex(sha256Digest("Re-ran it.")));
  });

  it("keeps each step it finished when a sync stops partway, and the next one goes on from there", async () => {
    for (const title of ["One", "Two", "Three"]) await node.bundle(paper(title));
    let requests = 0;
    const flaky: typeof fetch = async (input, init) => {
      if (++requests > 30) throw new TypeError("fetch failed");
      return node.fetch()(input, init);
    };
    const stopped = await syncMirror(dir, NODE, { fetch: flaky, step: 2, attempts: 1, retryMs: 0 });
    expect(stopped.error).toContain("fetch failed");
    expect(stopped.copied.to).toBeGreaterThan(0);
    expect(stopped.copied.to).toBeLessThan(node.log.size);
    const finished = await sync({ step: 2 });
    expect(finished).toMatchObject({ problems: [], error: null, copied: { from: stopped.copied.to, to: node.log.size }, head: node.log.head() });
    const checked = await monitorLog(httpSource("https://mirror.test", { fetch: fetchFrom(dir) }), null);
    expect(checked.report).toMatchObject({ problems: [], error: null, audited: node.log.size });
  });

  it("refuses a node that serves another log", async () => {
    await sync();
    const other = new TestNode();
    await other.setUp();
    const synced = await syncMirror(dir, NODE, { fetch: other.fetch(), retryMs: 0 });
    expect(synced.problems).toEqual([expect.objectContaining({ check: "log_changed" })]);
  });

  it("takes one sync at a time", async () => {
    const [first, second] = await Promise.all([sync(), sync()]);
    expect([first.error, second.error].filter(Boolean)).toEqual([expect.stringContaining("Another sync")]);
  });
});

describe("serving a mirror", () => {
  it("answers 503 before the first sync, and refuses writes", async () => {
    const mirror = fetchFrom(dir);
    expect((await mirror("https://mirror.test/api/v1/log")).status).toBe(503);
    expect((await mirror("https://mirror.test/api/health")).status).toBe(200);
    expect((await mirror("https://mirror.test/api/v1/log/entries", { method: "POST", body: "{}" })).status).toBe(405);
  });

  it("serves only what the head it holds covers, and turns away bad requests", async () => {
    await node.bundle(paper("Primes"));
    await sync();
    const mirror = fetchFrom(dir);
    expect((await mirror("https://mirror.test/api/v1/log/entries/5/signed")).status).toBe(404);
    expect((await mirror("https://mirror.test/api/v1/log/entries/4/signed")).status).toBe(200);
    expect((await mirror("https://mirror.test/api/v1/log/entries?start=0&end=500")).status).toBe(400);
    expect((await mirror("https://mirror.test/api/v1/log/proofs/consistency?first=2&second=9")).status).toBe(400);
    expect((await mirror("https://mirror.test/api/v1/log/checkpoint?size=3")).status).toBe(404);
    expect(await (await mirror("https://mirror.test/api/v1/log/checkpoint?size=5")).text()).toBe(node.log.checkpoint(5));
    expect((await mirror("https://mirror.test/api/v1/files/not-a-digest")).status).toBe(400);
    expect((await mirror("https://mirror.test/api/v1/claims")).status).toBe(404);
  });

  it("picks up what a later sync copied", async () => {
    await sync();
    const mirror = fetchFrom(dir);
    const size = async () => (await json<{ tree_head: { size: number } }>(mirror("https://mirror.test/api/v1/log"))).tree_head.size;
    expect(await size()).toBe(4);
    await node.bundle(paper("Primes"));
    await sync();
    expect(await size()).toBe(5);
  });
});

describe("the mirror's command line", () => {
  it("syncs and says what it did", async () => {
    await node.bundle(paper("Primes"));
    const out: string[] = [];
    expect(await main(["sync", NODE, dir], { ...io(node.fetch()), out: (line) => out.push(line) })).toBe(0);
    expect(out.join("")).toContain(`${node.log.id} at ${NODE}, copied into ${dir}`);
    expect(out.join("")).toContain("Entries: 0 to 4 copied this run; 5 held.");
    expect(out.join("")).toContain("OK:");
    const json: string[] = [];
    expect(await main(["sync", NODE, dir, "--json"], { ...io(node.fetch()), out: (line) => json.push(line) })).toBe(0);
    expect(JSON.parse(json.join(""))).toMatchObject({ result: "ok", copied: { from: 5, to: 5 } });
  });

  it("refuses options that don't fit the command", async () => {
    const err: string[] = [];
    const quiet = { ...io(node.fetch()), err: (line: string) => err.push(line) };
    expect(await main(["sync", NODE, dir, "--port", "80"], quiet)).toBe(2);
    expect(await main(["sync", NODE, dir, "--max-file-bytes", "lots"], quiet)).toBe(2);
    expect(await main(["serve", dir, "--json"], quiet)).toBe(2);
    expect(await main(["sync", "not a url", dir], quiet)).toBe(2);
    expect(await main([], quiet)).toBe(2);
    expect(err.join("")).toContain("--port is for serve");
  });
});

function io(fetch: typeof globalThis.fetch): Io {
  return { fetch, out: () => {}, err: () => {}, now: () => Date.parse("2026-10-07T12:00:00Z") };
}

function digestBundleFiles(files: Files): Set<Digest> {
  return new Set(Object.values(digestBundle(files).files));
}
