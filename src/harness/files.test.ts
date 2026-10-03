import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { cloneTree, listOutputs, LogTail, readOutput, sha256Output } from "./files";

const scratch = () => mkdtemp(join(tmpdir(), "sj-files-"));

describe("LogTail", () => {
  it("keeps a short log whole", () => {
    const log = new LogTail(16, 16);
    log.write("hello\n");
    log.write(Buffer.from("world\n"));
    expect(log.bytes().toString()).toBe("hello\nworld\n");
    expect(log.total).toBe(12);
  });

  it("keeps the start and the end of a long one, from a whole line, and says how much is left out", () => {
    const log = new LogTail(10, 20);
    for (let i = 0; i < 100; i++) log.write(`line ${String(i).padStart(3, "0")}\n`);
    const text = log.bytes().toString();
    expect(text.startsWith("line 000\nl")).toBe(true);
    expect(text).toMatch(/\n\[\.\.\. \d+ bytes left out \.\.\.\]\nline 098\nline 099\n$/);
    const left = Number(/\[\.\.\. (\d+) bytes/.exec(text)![1]);
    expect(10 + left + "line 098\nline 099\n".length).toBe(log.total);
    expect(log.lastLines(1)).toEqual(["line 099"]);
  });
});

describe("reading what a run wrote", () => {
  it("lists and reads regular files only, never following a link out of the workspace", async () => {
    const root = await scratch();
    const secret = join(root, "operator.key");
    await writeFile(secret, "the operator's secret key");
    const results = join(root, "workspace", "results");
    await mkdir(join(results, "plots"), { recursive: true });
    await writeFile(join(results, "R1.json"), '{"x": 1}');
    await writeFile(join(results, "plots", "fig.svg"), "<svg/>");
    await symlink(secret, join(results, "R2.json"));
    await symlink(root, join(results, "escape"));
    execFileSync("mkfifo", [join(results, "R3.json")]);

    expect(await listOutputs(results)).toEqual({ files: ["R1.json", "plots/fig.svg"], others: ["R2.json", "R3.json", "escape"] });
    const workspace = join(root, "workspace");
    expect(new TextDecoder().decode(await readOutput(workspace, "results/R1.json", 100))).toBe('{"x": 1}');
    await expect(readOutput(workspace, "results/R2.json", 100)).rejects.toThrow(/link/);
    await expect(readOutput(workspace, "results/escape/operator.key", 100)).rejects.toThrow(/link/);
    await expect(readOutput(workspace, "results/R3.json", 100)).rejects.toThrow(/isn't a regular file/);
    await expect(readOutput(workspace, "results/R1.json", 3)).rejects.toThrow(/larger than/);
    await expect(readOutput(workspace, "results/R9.json", 100)).rejects.toThrow(/there is no results\/R9.json/);
    await expect(sha256Output(workspace, "results/R2.json")).rejects.toThrow(/link/);
    expect(await sha256Output(workspace, "results/R1.json")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses a results directory the run replaced with a link", async () => {
    const root = await scratch();
    await mkdir(join(root, "elsewhere"));
    await writeFile(join(root, "elsewhere", "R1.json"), "{}");
    await mkdir(join(root, "workspace"));
    await symlink(join(root, "elsewhere"), join(root, "workspace", "results"));
    expect(await listOutputs(join(root, "workspace", "results"))).toEqual({ files: [], others: ["."] });
    await expect(readOutput(join(root, "workspace"), "results/R1.json", 100)).rejects.toThrow(/link/);
  });
});

describe("cloneTree", () => {
  it("copies every file, so changing a copy leaves the original alone", async () => {
    const root = await scratch();
    await mkdir(join(root, "from", "data", "raw"), { recursive: true });
    await writeFile(join(root, "from", "data", "raw", "rows.csv"), "a,b\n1,2\n", { mode: 0o444 });
    await cloneTree(join(root, "from"), join(root, "to"));
    const copy = join(root, "to", "data", "raw", "rows.csv");
    await writeFile(copy, "changed");
    expect(await readFile(join(root, "from", "data", "raw", "rows.csv"), "utf8")).toBe("a,b\n1,2\n");
  });
});
