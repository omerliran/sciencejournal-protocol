import { chmod, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { sha256Digest } from "../hash";
import { generateKeyPair, keyDigest, publicKeyOf } from "../signing";
import { main } from "./cli";
import type { Deps } from "./context";
import { HARNESS_DIGEST_PATH, HARNESS_PATH, requireCurrent } from "./update";

const NODE = "https://node.test";
const OLD = new TextEncoder().encode("#!/usr/bin/env node\n// the harness as it was\n");
const NEW = new TextEncoder().encode("#!/usr/bin/env node\n// the harness the node serves now\n");

/** A node serving `harness`, and saying `said` of it; every request it gets, by path. */
function node(harness: Uint8Array | null, said: { digest: string; bytes: number } | null = harness && { digest: sha256Digest(harness), bytes: harness.length }) {
  const asked: string[] = [];
  const fetch: Deps["fetch"] = async (input) => {
    const path = new URL(String(input)).pathname;
    asked.push(path);
    if (path === HARNESS_DIGEST_PATH && said) return Response.json(said);
    if (path === HARNESS_PATH && harness) return new Response(harness.slice().buffer);
    return Response.json({ error: "Not found" }, { status: 404 });
  };
  return { fetch, asked };
}

/** Deps for a harness running from `self`, the one file it was built into. */
async function harnessAt(contents: Uint8Array | null, fetch: Deps["fetch"]) {
  const lines: string[] = [];
  const self = contents && join(await mkdtemp(join(tmpdir(), "sj-update-")), "sj-harness.mjs");
  if (self) await writeFile(self, contents!, { mode: 0o755 });
  const deps: Deps = {
    fetch,
    now: () => new Date(),
    print: (line) => lines.push(line),
    env: { SJ_NODE: NODE },
    home: tmpdir(),
    invocation: "node sj-harness.mjs",
    findEngine: async () => null,
    ...(self && { self }),
  };
  return { deps, lines, self: self! };
}

describe("keeping the harness current", () => {
  it("takes no job while the node serves a newer harness, and says how to update", async () => {
    const served = node(NEW);
    const { deps } = await harnessAt(OLD, served.fetch);
    await expect(main(["job", "--model-family", "claude", "--model", "claude-opus-5-5"], deps)).rejects.toThrow(
      `This sj-harness is out of date: ${NODE} serves a newer one, which knows every job it may hand you. Run node sj-harness.mjs update, then ask for a job again.`,
    );
    expect(served.asked).toEqual([HARNESS_DIGEST_PATH]);
  });

  it("counts as current when it is the harness the node serves, runs from its source, or the node serves none", async () => {
    await expect(requireCurrent(undefined, (await harnessAt(NEW, node(NEW).fetch)).deps)).resolves.toBeUndefined();
    await expect(requireCurrent(undefined, (await harnessAt(null, node(NEW).fetch)).deps)).resolves.toBeUndefined();
    await expect(requireCurrent(undefined, (await harnessAt(OLD, node(null).fetch)).deps)).resolves.toBeUndefined();
    const unreachable: Deps["fetch"] = async () => {
      throw new TypeError("fetch failed");
    };
    await expect(requireCurrent(undefined, (await harnessAt(OLD, unreachable)).deps)).resolves.toBeUndefined();
  });

  it("updates to the harness the node serves, keeping the file's mode, and then is current", async () => {
    const served = node(NEW);
    const { deps, lines, self } = await harnessAt(OLD, served.fetch);
    await chmod(self, 0o750);
    expect(await main(["update"], deps)).toBe(0);
    expect(new Uint8Array(await readFile(self))).toEqual(NEW);
    expect((await stat(self)).mode & 0o777).toBe(0o750);
    expect(lines.at(-1)).toBe(`Updated sj-harness to the one ${NODE} serves. Run node sj-harness.mjs version to see which it is.`);
    expect(await main(["update"], deps)).toBe(0);
    expect(lines.at(-1)).toBe("sj-harness is up to date.");
    await expect(requireCurrent(undefined, deps)).resolves.toBeUndefined();
  });

  it("keeps its file when what the node sends doesn't match the digest it gives", async () => {
    // As while a node deploys: the digest from a new server, the file from an old one.
    const { deps, self } = await harnessAt(OLD, node(OLD, { digest: sha256Digest(NEW), bytes: NEW.length }).fetch);
    await expect(main(["update"], deps)).rejects.toThrow(`The harness ${NODE} sent doesn't match the digest it gives for it. Try again in a few minutes.`);
    expect(new Uint8Array(await readFile(self))).toEqual(OLD);
  });

  it("can't update from its source, or from a node that serves no harness", async () => {
    await expect(main(["update"], (await harnessAt(null, node(NEW).fetch)).deps)).rejects.toThrow("This harness runs from its source");
    await expect(main(["update"], (await harnessAt(OLD, node(null).fetch)).deps)).rejects.toThrow(`${NODE} doesn't say which harness it serves.`);
    await expect(main(["update", "now"], (await harnessAt(OLD, node(NEW).fetch)).deps)).rejects.toThrow("update takes no arguments");
  });

  it("says to update when the node hands it a kind of job it doesn't know", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sj-update-key-"));
    const key = join(dir, "operator.key");
    const { secretKey } = generateKeyPair();
    await writeFile(key, Buffer.from(secretKey).toString("hex"), { mode: 0o600 });
    const fetch: Deps["fetch"] = async (input) => {
      const path = new URL(String(input)).pathname;
      if (path.startsWith("/api/v1/operators/")) return Response.json({ key_digest: keyDigest(publicKeyOf(secretKey)) });
      if (path === "/api/v1/jobs") return Response.json({ job: "job:1", kind: "a_kind_from_later", deadline: new Date().toISOString() });
      return Response.json({ error: "Not found" }, { status: 404 });
    };
    // A harness run from its source compares nothing first, so only the job's kind can tell it.
    const { deps } = await harnessAt(null, fetch);
    await expect(main(["job", "--key", key, "--dir", dir, "--model-family", "claude", "--model", "claude-opus-5-5"], deps)).rejects.toThrow(
      "The node handed you a job of a kind this harness doesn't know, a_kind_from_later. Run node sj-harness.mjs update, then ask for a job again: the node hands you the same one.",
    );
  });
});
