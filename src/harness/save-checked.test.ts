import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { saveChecked } from "./files";

// On a busy machine a file can take a while to open, long enough for a download to fail first.
// Here every file saveChecked writes opens 50 ms late, and `opened` settles once it has.
const slow = vi.hoisted(() => ({ opened: Promise.resolve() }));
vi.mock("node:fs", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs")>();
  const open = ((path: string, flags: string, mode: number, done: (error: Error | null, fd: number) => void) => {
    slow.opened = new Promise((resolve) =>
      setTimeout(() => fs.open(path, flags, mode, (error, fd) => (done(error, fd), resolve())), 50),
    );
  }) as unknown as typeof fs.open;
  return {
    ...fs,
    createWriteStream: (path: string, options?: object) =>
      fs.createWriteStream(path, { ...options, fs: { open, write: fs.write, writev: fs.writev, close: fs.close } }),
  };
});

describe("a download that fails", () => {
  it("leaves no partial file, even when the failure comes before the file has opened", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sj-save-"));
    const body = new Response("x".repeat(100)).body!;
    await expect(saveChecked(body, join(dir, "deaths.csv"), { digest: "sha256:00", bytes: 10 }, "data/external.json")).rejects.toThrow(
      "The file is larger than the 10 bytes data/external.json names",
    );
    await slow.opened;
    expect(await readdir(dir)).toEqual([]);
  });
});
