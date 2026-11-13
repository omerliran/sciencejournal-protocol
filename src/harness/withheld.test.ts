import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { sha256Digest } from "../hash";
import { checkWithheldOpening, WithheldOpeningSchema } from "../withheld";
import { main } from "./cli";
import type { Deps } from "./context";
import { describeWithheld, readWithheld } from "./withheld";

function deps(): Deps & { lines: string[] } {
  const lines: string[] = [];
  return { fetch: async () => Response.json({}), now: () => new Date(), print: (line) => lines.push(line), env: {}, home: tmpdir(), invocation: "sj-harness", findEngine: async () => null, lines };
}

/** A folder of scans on the author's machine, outside any bundle. */
async function scans() {
  const dir = await mkdtemp(join(tmpdir(), "sj-withheld-"));
  const data = join(dir, "scans");
  await mkdir(join(data, "sub-01", "func"), { recursive: true });
  await writeFile(join(data, "sub-01", "func", "bold.nii.gz"), "voxels over time");
  await writeFile(join(data, "participants.tsv"), "id\tage\nsub-01\t34\n");
  return { dir, data };
}

/** The set `withhold` printed for data/withheld.json, with the words an author adds. */
const printed = (lines: string[]) => ({
  ...(JSON.parse(lines.find((line) => line.startsWith("{"))!) as { name: string; files: number; bytes: number; commitment: `sha256:${string}` }),
  description: "Scans of one adult.",
  reason: "consent",
  why: "They didn't agree to public release.",
  access: "No one outside the study.",
});

describe("withhold", () => {
  it("commits to every file in a folder, keeps the opening beside it, and prints only counts and the commitment", async () => {
    const { dir, data } = await scans();
    const out = deps();
    expect(await main(["withhold", data, "--name", "scans"], out)).toBe(0);
    const opening = WithheldOpeningSchema.parse(JSON.parse(await readFile(join(dir, "scans.opening.json"), "utf8")));
    expect(opening.files).toEqual([
      { path: "participants.tsv", sha256: sha256Digest("id\tage\nsub-01\t34\n"), bytes: 17 },
      { path: "sub-01/func/bold.nii.gz", sha256: sha256Digest("voxels over time"), bytes: 16 },
    ]);
    expect(opening.nonce).toMatch(/^[0-9a-f]{32}$/);
    // Only its holder reads the opening.
    expect((await stat(join(dir, "scans.opening.json"))).mode & 0o077).toBe(0);
    const set = printed(out.lines);
    expect(set).toMatchObject({ name: "scans", files: 2, bytes: 33 });
    expect(checkWithheldOpening(set, opening)).toEqual([]);
    // Nothing a file holds, and no file's own digest, is printed.
    expect(out.lines.join("\n")).not.toMatch(/sub-01|participants|voxels/);
    expect(out.lines.join("\n")).not.toContain(opening.files[0].sha256);
  });

  it("makes a new commitment each time, and never writes over an opening", async () => {
    const { dir, data } = await scans();
    const first = deps();
    await main(["withhold", data, "--name", "scans"], first);
    await expect(main(["withhold", data, "--name", "scans"], deps())).rejects.toThrow(/An opening can't be made again/);
    const second = deps();
    await main(["withhold", data, "--name", "scans", "--out", join(dir, "again.json")], second);
    expect(printed(second.lines).commitment).not.toBe(printed(first.lines).commitment);
  });

  it("needs a name code can use, and an opening outside the folder it commits to", async () => {
    const { data } = await scans();
    await expect(main(["withhold", data], deps())).rejects.toThrow(/Name the set with --name/);
    await expect(main(["withhold", data, "--name", "Raw Scans"], deps())).rejects.toThrow(/Name the set with --name/);
    await expect(main(["withhold", data, "--name", "scans", "--out", join(data, "opening.json")], deps())).rejects.toThrow(/can't go inside the folder/);
    await expect(main(["withhold", join(data, "nowhere"), "--name", "scans"], deps())).rejects.toThrow(/isn't a directory/);
  });
});

describe("check-withheld", () => {
  it("checks a folder against an opening, and the opening against the study that committed to it", async () => {
    const { dir, data } = await scans();
    const made = deps();
    await main(["withhold", data, "--name", "scans"], made);
    const bundle = join(dir, "bundle");
    await mkdir(join(bundle, "data"), { recursive: true });
    await writeFile(join(bundle, "data", "withheld.json"), JSON.stringify([printed(made.lines)]));
    const opening = join(dir, "scans.opening.json");

    const out = deps();
    expect(await main(["check-withheld", data, "--opening", opening, "--bundle", bundle], out)).toBe(0);
    expect(out.lines).toContain('The opening is the one the bundle\'s set "scans" commits to: 2 files, 33 bytes.');
    expect(out.lines).toContain("Every file the opening lists is here with the size and SHA-256 it says: 2 files, 33 bytes.");
    expect(await readWithheld(bundle, ["data/withheld.json"])).toHaveLength(1);
    expect(describeWithheld(await readWithheld(bundle, ["data/withheld.json"]))).toBe("2 files (33 bytes) in 1 set");

    // A file changed since, even at the same size, doesn't check; one added is said, and changes nothing.
    await writeFile(join(data, "sub-01", "func", "bold.nii.gz"), "voxels over tim3");
    await writeFile(join(data, ".DS_Store"), "finder");
    const changed = deps();
    expect(await main(["check-withheld", data, "--opening", opening], changed)).toBe(1);
    expect(changed.lines).toContain("  sub-01/func/bold.nii.gz has other bytes than the opening says");
    expect(changed.lines.join("\n")).toContain("The folder also holds 1 file the opening doesn't list");

    // Another study's commitment isn't opened by it.
    await writeFile(join(bundle, "data", "withheld.json"), JSON.stringify([{ ...printed(made.lines), commitment: sha256Digest("another") }]));
    const other = deps();
    expect(await main(["check-withheld", data, "--opening", opening, "--bundle", bundle], other)).toBe(1);
    expect(other.lines[0]).toContain("No set in the bundle's data/withheld.json commits to this opening");
  });

  it("needs an opening it can read", async () => {
    const { dir, data } = await scans();
    await expect(main(["check-withheld", data], deps())).rejects.toThrow(/Give the opening with --opening/);
    await writeFile(join(dir, "not.json"), '{"nonce": "short"}');
    await expect(main(["check-withheld", data, "--opening", join(dir, "not.json")], deps())).rejects.toThrow(/isn't an opening/);
  });
});
