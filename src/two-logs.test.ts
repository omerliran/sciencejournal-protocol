import { describe, expect, it } from "vitest";
import { operatorId, signObject } from "./entries";
import { sha256Digest } from "./hash";
import { MemoryLog } from "./monitor/memory-log";
import { generateKeyPair } from "./signing";
import { compareLogs, comparisonStatus, MERGE_WINDOW_MS, type ComparisonState } from "./two-logs";

// Two logs keep one record: the first copies each entry to the second, and anyone may submit to
// the second directly. Comparing them matches entries by the digest of the entry as signed.

const keys = [generateKeyPair(), generateKeyPair(), generateKeyPair(), generateKeyPair()];
const agent = (i: number) =>
  signObject({ type: "key" as const, key: keys[i].publicKey, name: `Agent ${i}`, model_families: ["family-a"] }, keys[i].secretKey);
const agents = keys.map((_, i) => agent(i));
const ids = keys.map((k) => operatorId(k.publicKey));
const bundle = signObject({ type: "bundle" as const, bundle: sha256Digest("a bundle") }, keys[0].secretKey);

const LOGGED = Date.parse("2026-10-03T12:00:00.000Z");
const soon = LOGGED + 60 * 60 * 1000;
const later = LOGGED + MERGE_WINDOW_MS + 60 * 60 * 1000;

/** Each log holding the key entries of agents `which`, in order. */
async function logs(first: number[], second: number[]) {
  const a = new MemoryLog();
  const b = new MemoryLog();
  for (const i of first) await a.append({ operator: ids[i], entry: agents[i] });
  for (const i of second) await b.append({ operator: ids[i], entry: agents[i] });
  return { a, b };
}

describe("comparing two logs", () => {
  it("matches every entry the second copied, and reads only what's new on the next run", async () => {
    const { a, b } = await logs([0, 1], [0, 1]);
    const run = await compareLogs(a.source(), b.source(), null, { now: soon });
    expect(run.report).toMatchObject({ logs: [a.id, b.id], matched: 2, waiting: [0, 0], problems: [], error: null });
    expect(comparisonStatus(run.report)).toBe(0);

    // The first logs a third entry and the second hasn't copied it yet: it waits, within the window.
    await a.append({ operator: ids[2], entry: agents[2] });
    const next = await compareLogs(a.source(), b.source(), run.state, { now: soon });
    expect(next.report).toMatchObject({ read: [{ from: 2, to: 3 }, { from: 2, to: 2 }], matched: 0, waiting: [1, 0], problems: [] });

    // Once the second copies it, the two match again.
    await b.append({ operator: ids[2], entry: agents[2] });
    const caught = await compareLogs(a.source(), b.source(), next.state, { now: later });
    expect(caught.report).toMatchObject({ matched: 1, waiting: [0, 0], problems: [] });
  });

  it("reports an entry missing from either log a day after it was logged, the second's as possible censorship", async () => {
    const { a, b } = await logs([0, 1], [0, 2]);
    const early = await compareLogs(a.source(), b.source(), null, { now: soon });
    expect(early.report).toMatchObject({ matched: 1, waiting: [1, 1], problems: [] });
    const late = await compareLogs(a.source(), b.source(), early.state, { now: later });
    expect(late.report.problems).toMatchObject([
      { check: "not_on_second", log: a.id, index: 1 },
      { check: "not_on_first", log: b.id, index: 1, reason: expect.stringMatching(/logged there/) },
    ]);
    expect(comparisonStatus(late.report)).toBe(1);
    // Reading both logs found nothing wrong with either, so the state moves on, and the entries keep waiting.
    expect(late.state?.waiting.map((side) => Object.keys(side).length)).toEqual([1, 1]);
  });

  it("waits to report entries missing from a log until it is read to its head", async () => {
    const { a, b } = await logs([0, 1, 2], [3, 0, 1, 2]);
    const partial = await compareLogs(a.source(), b.source(), null, { now: later, maxEntries: 2 });
    expect(partial.report.problems).toEqual([]);
    expect(partial.report.unchecked).toContain("A log wasn't read to its head this run, so entries missing from it weren't reported yet.");
  });

  it("reports the same signed entry in leaves that differ, on every run after", async () => {
    const a = new MemoryLog();
    const b = new MemoryLog();
    await a.append({ operator: ids[0], entry: agents[0] });
    await a.append({ operator: ids[0], entry: bundle, claims: [`claim:${"c".repeat(64)}`], fields: ["physics"] });
    await b.append({ operator: ids[0], entry: agents[0] });
    // The second attributes the bundle to someone else: a field both leaves state, differing.
    await b.append({ operator: ids[1], entry: bundle } as never);
    const run = await compareLogs(a.source(), b.source(), null, { now: soon });
    expect(run.report.problems).toMatchObject([{ check: "copies_differ", log: a.id, index: 1, reason: expect.stringMatching(/differ in operator$/) }]);
    const again = await compareLogs(a.source(), b.source(), run.state, { now: soon });
    expect(again.report.problems.map((p) => p.check)).toEqual(["copies_differ"]);
  });

  it("compares a revealed entry's salt, not where its commitment sits on each log", async () => {
    const reveal = (index: number, salt: string) => ({ operator: ids[0], entry: bundle, sealed: { index, salt } }) as never;
    const { a, b } = await logs([0], [0]);
    await a.append(reveal(0, "ab".repeat(32)));
    await b.append({ operator: ids[1], entry: agents[1] });
    await b.append(reveal(1, "ab".repeat(32)));
    expect((await compareLogs(a.source(), b.source(), null, { now: soon })).report.problems).toEqual([]);
    const other = await logs([0], [0]);
    await other.a.append(reveal(0, "ab".repeat(32)));
    await other.b.append(reveal(0, "cd".repeat(32)));
    const run = await compareLogs(other.a.source(), other.b.source(), null, { now: soon });
    expect(run.report.problems).toMatchObject([{ check: "copies_differ", reason: expect.stringMatching(/differ in sealed$/) }]);
  });

  it("checks the copies the first log names for its bundles, and for entries the second doesn't hold", async () => {
    const a = new MemoryLog();
    const b = new MemoryLog();
    await a.append({ operator: ids[0], entry: agents[0] });
    await a.append({ operator: ids[0], entry: bundle, claims: [], fields: ["physics"] });
    await a.append({ operator: ids[1], entry: agents[1] });
    await b.append({ operator: ids[0], entry: agents[0] });
    await b.append({ operator: ids[0], entry: bundle } as never);
    // The first says the second holds the bundle at 0, where its key entry is, and entry 2 at 7.
    const copies: Record<number, number> = { 1: 0, 2: 7 };
    const first = a.source({ receipt: async (index) => ({ copies: index in copies ? [{ log: b.id, index: copies[index] }] : [] }) });
    const run = await compareLogs(first, b.source(), null, { now: later });
    expect(run.report.problems).toMatchObject([
      { check: "false_copy", index: 1, reason: expect.stringMatching(/at 0, but the second holds it at 1/) },
      { check: "not_on_second", index: 2 },
      { check: "false_copy", index: 2, reason: expect.stringMatching(/at 7, but the second holds no such entry/) },
    ]);
  });

  it("stops at a log that misbehaves, keeping the state from before", async () => {
    const { a, b } = await logs([0, 1], [0, 1]);
    const run = await compareLogs(a.source(), b.source(), null, { now: soon });
    // The second log, by its own key, now serves a different history of the same size.
    const forked = new MemoryLog(b.secretKey);
    await forked.append({ operator: ids[1], entry: agents[1] });
    await forked.append({ operator: ids[0], entry: agents[0] });
    const after = await compareLogs(a.source(), forked.source(), run.state as ComparisonState, { now: soon });
    expect(after.report.problems).toMatchObject([{ check: "fork", log: b.id }]);
    expect(after.state).toBeNull();
    // And two nodes serving one log aren't two logs.
    const same = await compareLogs(a.source(), a.source(), null, { now: soon });
    expect(same.report.error).toMatch(/compare two different logs/);
  });
});
