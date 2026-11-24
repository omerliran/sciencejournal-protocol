import { describe, expect, it } from "vitest";
import { BundleLayoutError } from "./bundle";
import { canonicalDigest, sha256Digest } from "./hash";
import { digestPlanFolder, planCheck } from "./plan-folder";
import { planDigest } from "./preregistration";

const bytes = (text: string) => new TextEncoder().encode(text);
const folder = (files: Record<string, string>) => new Map(Object.entries(files).map(([path, text]) => [path, bytes(text)]));

describe("plan folders", () => {
  it("digests the whole folder for the version, and plan/ alone as registering it does", () => {
    const files = folder({ "plan/plan.md": "# Plan\n", "plan/analysis.py": "print(1)\n", "data/stripped.csv": "id,arm\n1,a\n" });
    const digests = digestPlanFolder(files);
    const each = Object.fromEntries([...files].map(([path, data]) => [path, sha256Digest(data)]));
    expect(digests.files).toEqual(each);
    expect(digests.folder).toBe(canonicalDigest(each));
    expect(digests.plan).toBe(planDigest(each));
    // What sits beside plan/ changes the version, never the plan.
    const more = digestPlanFolder(folder({ "plan/plan.md": "# Plan\n", "plan/analysis.py": "print(1)\n", "data/stripped.csv": "id,arm\n1,a\n2,b\n" }));
    expect(more.plan).toBe(digests.plan);
    expect(more.folder).not.toBe(digests.folder);
    // Uploaded files count by digest, as a bundle's do.
    const uploaded = new Map([["data/large.csv", sha256Digest("x")]]);
    expect(digestPlanFolder(files, uploaded).folder).toBe(canonicalDigest({ ...each, "data/large.csv": sha256Digest("x") }));
  });

  it("refuses a folder with nothing under plan/, a file at its top, or one outside a bundle's directories", () => {
    for (const files of [
      folder({ "code/run.py": "x" }),
      folder({ "plan/plan.md": "x", "README.md": "x" }),
      folder({ "plan/plan.md": "x", "manifest.json": "{}" }),
      folder({ "plan/plan.md": "x", "notes/a.md": "x" }),
      folder({ "plan/plan.md": "x", "data/withheld/scans/a.nii": "x" }),
    ]) {
      expect(() => digestPlanFolder(files)).toThrow(BundleLayoutError);
    }
  });

  it("says a prose plan can't be run, allowing that it may be fine", () => {
    const check = planCheck(folder({ "plan/plan.md": "# Plan\nWe will count deaths.\n" }));
    expect(check.code).toEqual([]);
    expect(check.notes[0]).toMatch(/holds no code/);
    expect(check.notes.join(" ")).toMatch(/fine for data not collected yet/);
  });

  it("says what pins the environment, which data the plan names and holds, and whether tests are there", () => {
    const data = "id,arm\n1,placebo\n";
    const named = sha256Digest("the full data, kept by its author");
    const files = folder({
      "plan/plan.md": `# Plan\nData: ${sha256Digest(data)} and ${named}.\n`,
      "plan/analysis.R": "fit()\n",
      "plan/Dockerfile": "FROM rocker/r-ver:4.4\nRUN true\n",
      "data/stripped.csv": data,
    });
    const check = planCheck(files);
    expect(check.code).toEqual(["plan/analysis.R"]);
    expect(check.environment).toEqual({ pinned: [], unpinned: ["plan/Dockerfile"] });
    expect(check.data).toEqual({ named: 2, held: 1, missing: [named] });
    expect(check.tests).toEqual([]);
    expect(check.beside).toBe(1);
    const notes = check.notes.join(" ");
    expect(notes).toMatch(/Nothing pins the environment/);
    expect(notes).toMatch(/names an image by tag/);
    expect(notes).toMatch(/doesn't hold/);
    expect(notes).toMatch(/No tests/);
  });

  it("finds nothing to say of a plan a helper can run whole", () => {
    const data = "id,arm\n1,placebo\n";
    const check = planCheck(
      folder({
        "plan/plan.md": `Data: ${sha256Digest(data)}\n`,
        "plan/analysis.py": "run()\n",
        "plan/tests/test_null.py": "assert True\n",
        "plan/Dockerfile": `FROM python:3.13@sha256:${"a".repeat(64)} AS build\nFROM build\n`,
        "plan/requirements.txt": "numpy==2.3.1\nscipy==1.16.0  # pinned\n",
        "data/stripped.csv": data,
        "results/null-sims.json": "{}",
      }),
    );
    expect(check.environment.pinned).toEqual(["plan/Dockerfile", "plan/requirements.txt"]);
    expect(check.tests).toEqual(["plan/tests/test_null.py", "results/null-sims.json"]);
    expect(check.notes).toEqual(["Helpers can run this plan: its code, the environment it runs in, its data, and its tests are all here."]);
  });
});
