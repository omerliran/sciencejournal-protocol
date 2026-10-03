import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { operatorId, signObject } from "../entries";
import { generateKeyPair } from "../signing";
import { main, type Io } from "./cli";
import { httpSource, nodeUrl } from "./http";
import { MemoryLog } from "./memory-log";

const NODE = "https://node.example";
const MIRROR = "https://mirror.example";
// Signed once: hybrid signing is randomized, so signing again would make a different entry.
const keyEntries = [generateKeyPair(), generateKeyPair(), generateKeyPair()].map((keys, i) =>
  signObject({ type: "key" as const, key: keys.publicKey, name: `Agent ${i}`, model_families: ["family-a"] }, keys.secretKey),
);
const keyEntry = (i: number) => keyEntries[i];

/** A log whose first entries are the key entries of operators `ids`, in order. */
async function logOf(ids: number[], log = new MemoryLog()): Promise<MemoryLog> {
  for (const i of ids) await log.append({ operator: operatorId(keyEntry(i).key), entry: keyEntry(i) });
  return log;
}

let home: string;
let out: string;
let err: string;

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "monitor-"));
  out = "";
  err = "";
});

/** The monitor run with nodes served from memory, by origin. */
function run(args: string[], nodes: Record<string, MemoryLog | typeof fetch>): Promise<number> {
  const io: Io = {
    fetch: async (input, init) => {
      const origin = new URL(String(input)).origin;
      const node = nodes[origin];
      if (!node) throw new TypeError("fetch failed", { cause: new Error(`getaddrinfo ENOTFOUND ${new URL(origin).host}`) });
      return node instanceof MemoryLog ? node.fetch()(input, init) : node(input, init);
    },
    out: (text) => (out += text),
    err: (text) => (err += text),
    env: {},
    home,
  };
  return main(args, io);
}

const directory = () => join(home, ".config", "sciencejournal", "monitor");
const stateFile = (log: MemoryLog) => join(directory(), `${log.id.replace(":", "_")}.json`);
const readJson = async (path: string) => JSON.parse(await readFile(path, "utf8"));

describe("monitor check", () => {
  it("pins a log, keeps its state in a file per log, and checks the log as it grows", async () => {
    const log = await logOf([0, 1]);
    expect(await run(["check", `${NODE}/`], { [NODE]: log })).toBe(0);
    expect(out).toContain(`${log.id} at ${NODE}\n  Pinned on this run`);
    expect(out).toContain("Entries: 0 to 1 audited this run (key 2); 2 of 2 audited in all.");
    expect(out).toMatch(/OK: every check passed\. State saved in .*\.json\.\n$/);
    expect(await readJson(stateFile(log))).toMatchObject({ log: log.id, nodes: { [NODE]: 2 }, head: log.head(), audit: { size: 2 } });

    await logOf([2], log);
    out = "";
    expect(await run(["check", NODE], { [NODE]: log })).toBe(0);
    expect(out).toContain("History: consistent with the head verified before, 2 entries");
    expect(out).toContain("Entries: 2 to 2 audited this run (key 1); 3 of 3 audited in all.");
    expect(await readdir(directory())).toEqual([`${log.id.replace(":", "_")}.json`]);
  });

  it("exits 1 when the log misbehaves, leaving the state as it was", async () => {
    const honest = await logOf([0, 1]);
    const forked = await logOf([0, 2], new MemoryLog(honest.secretKey));
    expect(await run(["check", NODE], { [NODE]: honest })).toBe(0);
    const before = await readFile(stateFile(honest), "utf8");
    out = "";
    expect(await run(["check", NODE], { [NODE]: forked })).toBe(1);
    expect(out).toContain("Problem (fork): The log signed two trees of 2 entries with different roots");
    expect(out).toContain("MISBEHAVED: 1 problem with the log. The state file was left as it was");
    expect(await readFile(stateFile(honest), "utf8")).toBe(before);
  });

  it("refuses a node that serves another log until told to pin again", async () => {
    const first = await logOf([0]);
    const second = await logOf([0]);
    expect(await run(["check", NODE], { [NODE]: first })).toBe(0);
    expect(await run(["check", NODE, "--json"], { [NODE]: second })).toBe(1);
    const refused = JSON.parse(out.slice(out.indexOf("{")));
    expect(refused).toMatchObject({ result: "misbehaved", state_file: null, problems: [{ check: "log_changed" }] });

    out = "";
    expect(await run(["check", NODE, "--pin"], { [NODE]: second })).toBe(0);
    expect(out).toContain("Pinned on this run");
    expect(await readJson(stateFile(second))).toMatchObject({ log: second.id, nodes: { [NODE]: 1 } });
    // The first log's file stays, as a record, but no longer speaks for the node.
    expect((await readJson(stateFile(first))).nodes).toEqual({});
    expect(await run(["check", NODE], { [NODE]: second })).toBe(0);
  });

  it("checks two nodes that serve one log against each other, letting one lag but never shrink", async () => {
    const log = await logOf([0, 1, 2]);
    const split = await logOf([0, 2], new MemoryLog(log.secretKey));
    const lagging = await logOf([0, 1], new MemoryLog(log.secretKey));
    const shrunk = await logOf([0], new MemoryLog(log.secretKey));
    expect(await run(["check", NODE], { [NODE]: log })).toBe(0);
    // The node that served the newer head proves what a lagging one serves is a prefix of it.
    expect(await run(["check", MIRROR], { [MIRROR]: split, [NODE]: log })).toBe(1);
    expect(out).toContain("Problem (consistency)");

    out = "";
    expect(await run(["check", MIRROR], { [MIRROR]: lagging, [NODE]: log })).toBe(0);
    expect(out).toContain("History: behind the head verified before, 3 entries");
    expect(await readJson(stateFile(log))).toMatchObject({ nodes: { [NODE]: 3, [MIRROR]: 2 }, head: { size: 3 } });

    out = "";
    expect(await run(["check", MIRROR], { [MIRROR]: shrunk })).toBe(1);
    expect(out).toContain("Problem (shrank): This node served a tree of 2 entries, and now one of 1");
    expect(await run(["check", MIRROR], { [MIRROR]: log })).toBe(0);
    expect(await readJson(stateFile(log))).toMatchObject({ nodes: { [NODE]: 3, [MIRROR]: 3 } });
  });

  it("exits 2 when it can't finish: an unreachable node, an unreadable state file, or a bad command", async () => {
    expect(await run(["check", NODE], {})).toBe(2);
    expect(out).toContain(
      "FAILED, so the state file was left as it was: GET https://node.example/api/v1/log failed: fetch failed (getaddrinfo ENOTFOUND node.example)",
    );

    const log = await logOf([0]);
    const state = join(home, "state.json");
    await writeFile(state, "{not json");
    expect(await run(["check", NODE, "--state", state], { [NODE]: log })).toBe(2);
    expect(err).toMatch(/^FAILED: The state file .*state\.json isn't JSON/);

    expect(await run(["check", "ftp://node.example"], {})).toBe(2);
    expect(await run(["check", NODE, "--max-entries", "-1"], {})).toBe(2);
    expect(await run(["check", NODE, "--node", NODE], {})).toBe(2);
    expect(await run(["check"], {})).toBe(2);
    expect(await run(["watch", NODE], {})).toBe(2);
    expect(await run(["check", NODE, "--frequency", "1"], {})).toBe(2);
    expect(await run(["--help"], {})).toBe(0);
  });

  it("treats a node error as a failure to finish, after retrying it", async () => {
    let calls = 0;
    const flaky: typeof fetch = async () => {
      calls += 1;
      return Response.json({ error: "Internal error" }, { status: 500 });
    };
    const source = httpSource(NODE, { fetch: flaky, retryMs: 0 });
    await expect(source.log()).rejects.toThrow("GET https://node.example/api/v1/log answered 500: Internal error");
    expect(calls).toBe(3);

    // A dropped connection is tried again; an answer that isn't strict JSON is not.
    let dropped = 0;
    const recovering = httpSource(NODE, {
      retryMs: 0,
      fetch: async () => (dropped++ === 0 ? Promise.reject(new TypeError("fetch failed")) : Response.json({ ok: true })),
    });
    expect(await recovering.log()).toEqual({ ok: true });
    const duplicated = httpSource(NODE, { retryMs: 0, fetch: async () => new Response('{"log": "a", "log": "b"}') });
    await expect(duplicated.log()).rejects.toThrow('answered with something other than I-JSON: Duplicate property name "log"');
    expect(() => nodeUrl("https://node.example/path/?q=1")).toThrow(/query or fragment/);
    expect(nodeUrl("https://node.example/base//")).toBe("https://node.example/base");
  });

  it("writes a checkpoint after a run that passes, to a file or alone on stdout", async () => {
    const log = await logOf([0, 1]);
    const path = join(home, "checkpoint.json");
    expect(await run(["check", NODE, "--checkpoint", path], { [NODE]: log })).toBe(0);
    expect(await readJson(path)).toEqual({ log: log.id, public_key: log.publicKey, tree_head: log.head(), node: NODE });

    out = "";
    err = "";
    expect(await run(["check", NODE, "--checkpoint", "-", "--max-entries", "0"], { [NODE]: log })).toBe(0);
    expect(JSON.parse(out)).toEqual({ log: log.id, public_key: log.publicKey, tree_head: log.head(), node: NODE });
    expect(err).toContain("OK: every check passed");
  });
});

describe("monitor compare", () => {
  async function checkpoints(log: MemoryLog, sizes: number[]) {
    const paths: string[] = [];
    for (const size of sizes) {
      const path = join(home, `checkpoint-${log.id.slice(4, 12)}-${size}.json`);
      await writeFile(path, JSON.stringify({ log: log.id, public_key: log.publicKey, tree_head: log.heads[size - 1], node: NODE }));
      paths.push(path);
    }
    return paths;
  }

  it("finds checkpoints of one history consistent", async () => {
    const log = await logOf([0, 1, 2]);
    const [small, large] = await checkpoints(log, [1, 3]);
    expect(await run(["compare", large, small], { [NODE]: log })).toBe(0);
    expect(out).toContain("OK: the heads are consistent, so both readers saw one history.");
  });

  it("catches a log that showed two readers different histories", async () => {
    const log = await logOf([0, 1, 2]);
    const forked = await logOf([0, 2, 1], new MemoryLog(log.secretKey));
    const [mine] = await checkpoints(log, [2]);
    const [theirs] = await checkpoints(forked, [3]);
    expect(await run(["compare", mine, theirs, "--json"], { [NODE]: forked })).toBe(1);
    expect(JSON.parse(out)).toMatchObject({ result: "misbehaved", problems: [{ check: "consistency" }] });
  });

  it("can't compare what isn't a checkpoint, or checkpoints of different logs", async () => {
    const one = await logOf([0]);
    const other = await logOf([0]);
    const [a] = await checkpoints(one, [1]);
    const b = join(home, "other.json");
    await writeFile(b, JSON.stringify({ log: other.id, public_key: other.publicKey, tree_head: other.head() }));
    expect(await run(["compare", a, b], {})).toBe(2);
    expect(out).toContain(`FAILED: The checkpoints are of different logs, ${one.id} and ${other.id}`);
    expect(await run(["compare", a, join(home, "missing.json")], {})).toBe(2);
    expect(await run(["compare", a, b, "--pin"], {})).toBe(2);
  });
});
