import { mkdir, mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ExternalFile } from "../external";
import { sha256Digest } from "../hash";
import type { Deps } from "./context";
import { describePointers, fetchPointed, placePointed, readPointers } from "./pointers";

const table = "year,deaths\n2025,24400\n";
const pointer = (overrides: Partial<ExternalFile> = {}): ExternalFile => ({
  path: "data/eurostat/deaths.csv",
  url: "https://data.example/deaths.csv",
  sha256: sha256Digest(table),
  bytes: table.length,
  license: "CC-BY-4.0",
  ...overrides,
});

/** A data host: each URL's answer, and every URL asked for, with how each request was made. */
function host(answers: Record<string, () => Response>) {
  const asked: { url: string; redirect?: RequestInit["redirect"] }[] = [];
  const fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    asked.push({ url, redirect: init?.redirect });
    const answer = answers[url];
    if (!answer) return new Response("not here", { status: 404 });
    return answer();
  }) as typeof globalThis.fetch;
  const deps: Deps = { fetch, now: () => new Date(), print: () => {}, env: {}, home: tmpdir(), invocation: "sj-harness", findEngine: async () => null };
  return { deps, asked };
}

const moved = (location: string, status = 302) => () => new Response(null, { status, headers: { location } });

describe("the public files a bundle points at", () => {
  it("are fetched once, checked, kept by digest, and put where their paths say", async () => {
    const store = await mkdtemp(join(tmpdir(), "sj-pointers-"));
    const { deps, asked } = host({ "https://data.example/deaths.csv": () => new Response(table) });
    expect(await fetchPointed([pointer()], store, deps)).toEqual([
      { path: "data/eurostat/deaths.csv", url: "https://data.example/deaths.csv", sha256: sha256Digest(table), bytes: table.length, fetched: true },
    ]);
    // The harness follows redirects itself, so none can take it anywhere but https.
    expect(asked).toEqual([{ url: "https://data.example/deaths.csv", redirect: "manual" }]);
    expect(await readdir(store)).toEqual([sha256Digest(table).slice("sha256:".length)]);

    // A second run uses what the first kept, once it checks again.
    expect((await fetchPointed([pointer()], store, deps))[0].fetched).toBe(false);
    expect(asked).toHaveLength(1);

    const workspace = await mkdtemp(join(tmpdir(), "sj-workspace-"));
    await placePointed([pointer()], store, workspace);
    expect(await readFile(join(workspace, "data", "eurostat", "deaths.csv"), "utf8")).toBe(table);
  });

  it("follow redirects to other https URLs, and say where the bytes came from", async () => {
    const store = await mkdtemp(join(tmpdir(), "sj-pointers-"));
    const { deps } = host({
      "https://data.example/deaths.csv": moved("/files/deaths.csv", 301),
      "https://data.example/files/deaths.csv": moved("https://mirror.example/a/deaths.csv", 307),
      "https://mirror.example/a/deaths.csv": () => new Response(table),
    });
    const [fetched] = await fetchPointed([pointer()], store, deps);
    expect(fetched).toMatchObject({ fetched: true, from: "https://mirror.example/a/deaths.csv" });
  });

  it("aren't kept when they can't be had or aren't what the bundle says, and the error names the file", async () => {
    const store = await mkdtemp(join(tmpdir(), "sj-pointers-"));
    const cases: [Record<string, () => Response>, RegExp][] = [
      [{ "https://data.example/deaths.csv": moved("http://data.example/deaths.csv") }, /sends it to http:\/\/data\.example\/deaths\.csv, which isn't https/],
      [{ "https://data.example/deaths.csv": () => new Response(null, { status: 302 }) }, /without saying where to go/],
      [{ "https://data.example/deaths.csv": () => new Response("gone", { status: 410 }) }, /answered 410/],
      [{ "https://data.example/deaths.csv": () => new Response(table.replace("24400", "24401")) }, /isn't what data\/external\.json names/],
      [{ "https://data.example/deaths.csv": () => new Response(`${table}${table}`) }, new RegExp(`larger than the ${table.length} bytes data/external\\.json names`)],
      [{ "https://data.example/deaths.csv": moved("https://data.example/deaths.csv") }, /redirects more than 10 times/],
    ];
    for (const [answers, problem] of cases) {
      const { deps } = host(answers);
      await expect(fetchPointed([pointer()], store, deps)).rejects.toThrow(problem);
      await expect(fetchPointed([pointer()], store, deps)).rejects.toThrow(/Couldn't fetch data\/eurostat\/deaths\.csv, which data\/external\.json points at/);
    }
    expect(await readdir(store)).toEqual([]);

    // A file kept from before that no longer checks is fetched again.
    await writeFile(join(store, sha256Digest(table).slice("sha256:".length)), "tampered");
    const { deps } = host({ "https://data.example/deaths.csv": () => new Response(table) });
    expect((await fetchPointed([pointer()], store, deps))[0].fetched).toBe(true);
  });

  it("are read from data/external.json against the bundle's own paths, and described in a line", async () => {
    const bundle = await mkdtemp(join(tmpdir(), "sj-bundle-"));
    expect(await readPointers(bundle, ["paper.md"])).toEqual([]);
    await mkdir(join(bundle, "data"), { recursive: true });
    await writeFile(join(bundle, "data", "external.json"), JSON.stringify([pointer()]));
    expect(await readPointers(bundle, ["paper.md", "data/external.json"])).toEqual([pointer()]);
    await expect(readPointers(bundle, ["paper.md", "data/external.json", "data/eurostat/deaths.csv"])).rejects.toThrow(
      `data/external.json can't be used: /0/path "data/eurostat/deaths.csv" is both in the bundle and pointed at`,
    );
    await writeFile(join(bundle, "data", "external.json"), '[{"path": "data/a", "path": "data/b"}]');
    await expect(readPointers(bundle, ["data/external.json"])).rejects.toThrow(/isn't valid JSON/);

    expect(describePointers([])).toBeNull();
    expect(describePointers([pointer(), pointer({ path: "data/b.csv", url: "https://other.example/b.csv", bytes: 2048 })])).toBe(
      "2 public files (2.0 KB) from data.example, other.example",
    );
  });
});
