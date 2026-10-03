import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../signing";
import { main } from "./cli";
import { loadSecretKey, NodeClient } from "./client";
import type { Deps } from "./context";
import { HARNESS } from "./version";

function deps(fetch: Deps["fetch"] = async () => Response.json({})): Deps & { lines: string[] } {
  const lines: string[] = [];
  return { fetch, now: () => new Date(), print: (line) => lines.push(line), env: {}, home: tmpdir(), invocation: "sj-harness", lines };
}

describe("the command line", () => {
  it("says its version and how to use it", async () => {
    const out = deps();
    expect(await main(["version"], out)).toBe(0);
    expect(await main(["--help"], out)).toBe(0);
    expect(await main(["job", "--help"], out)).toBe(0);
    expect(await main([], out)).toBe(2);
    expect(out.lines[0]).toBe(HARNESS);
    expect(out.lines[1]).toContain("reproduce <bundle dir>");
  });

  it.each([
    [["bogus"], /There is no bogus command/],
    [["run"], /run needs a directory/],
    [["run", "a", "b"], /takes one directory/],
    [["run", "job", "--hazard", "none"], /--hazard doesn't apply to run/],
    [["attest", "job", "--image", "x"], /--image doesn't apply to attest/],
    [["job", "--nonsense"], /Unknown option/],
    [["job", "--minutes", "soon"], /--minutes takes a positive number/],
  ])("refuses %j", async (argv, message) => {
    await expect(main(argv, deps())).rejects.toThrow(message);
  });

  it("needs an operator to act as, and never shows the key", async () => {
    await expect(main(["job"], deps())).rejects.toThrow(/--operator op:<n>/);
  });
});

describe("the secret key file", () => {
  it("loads the hex of the two seeds, from a file only its owner can read", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sj-key-"));
    const path = join(dir, "operator.key");
    const { secretKey } = generateKeyPair();
    await writeFile(path, `${Buffer.from(secretKey).toString("hex")}\n`, { mode: 0o600 });
    expect(await loadSecretKey(path)).toEqual(secretKey);
    await chmod(path, 0o644);
    await expect(loadSecretKey(path)).rejects.toThrow(/chmod 600/);
    await writeFile(path, "not a key", { mode: 0o600 });
    await chmod(path, 0o600);
    const refusal = await loadSecretKey(path).catch((error: Error) => error.message);
    expect(refusal).toMatch(/doesn't hold a secret key/);
    expect(refusal).not.toContain("not a key");
    await expect(loadSecretKey(join(dir, "missing.key"))).rejects.toThrow(/--key/);
  });
});

describe("downloads", () => {
  const body = new TextEncoder().encode("a large data file");
  const digest = `sha256:${createHash("sha256").update(body).digest("hex")}`;
  const serve = (bytes: Uint8Array) => async () => new Response(bytes as Uint8Array<ArrayBuffer>);

  it("keep a file only when its size and SHA-256 are what the job names", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sj-download-"));
    const target = join(dir, "big.csv");
    const client = new NodeClient("https://node.test", deps(serve(body)));
    await client.download({ url: "/api/v1/transfers/t" }, target, { digest, bytes: body.length });
    expect(await readFile(target, "utf8")).toBe("a large data file");

    const tampered = new NodeClient("https://node.test", deps(serve(new TextEncoder().encode("a large data filE"))));
    await expect(tampered.download({ url: "/x" }, join(dir, "bad.csv"), { digest, bytes: body.length })).rejects.toThrow(/isn't what its job names/);
    await expect(stat(join(dir, "bad.csv"))).rejects.toThrow();
    await expect(stat(join(dir, "bad.csv.part"))).rejects.toThrow();
    await expect(tampered.download({ url: "/x" }, join(dir, "short.csv"), { digest, bytes: 4 })).rejects.toThrow(/larger than the 4 bytes/);
  });

  it("resolve a link on the node or anywhere else", () => {
    const client = new NodeClient("https://node.test/", deps());
    expect(client.resolve("/api/v1/transfers/t")).toBe("https://node.test/api/v1/transfers/t");
    expect(client.resolve("https://bucket.s3.example/key?sig=1")).toBe("https://bucket.s3.example/key?sig=1");
  });
});
