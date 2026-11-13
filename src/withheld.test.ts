import { describe, expect, it } from "vitest";
import { BundleLayoutError, digestBundle } from "./bundle";
import { sha256Digest } from "./hash";
import {
  checkWithheldOpening,
  readWithheldData,
  withheldBytes,
  withheldCommitment,
  WITHHELD_REASON_MEANINGS,
  WITHHELD_REASONS,
  type WithheldOpening,
  type WithheldSet,
} from "./withheld";

const opening: WithheldOpening = {
  nonce: "000102030405060708090a0b0c0d0e0f",
  files: [
    { path: "sub-01/anat/T1w.nii.gz", sha256: sha256Digest("anatomy"), bytes: 9_000_000 },
    { path: "sub-01/func/task-rest_bold.nii.gz", sha256: sha256Digest("rest"), bytes: 120_000_000 },
  ],
};

const set = (overrides: Partial<WithheldSet> = {}): WithheldSet => ({
  name: "scans",
  description: "Structural and resting-state scans of 48 adults, one folder per participant.",
  reason: "consent",
  why: "Participants agreed to their scans being shared with researchers under an agreement, not to their public release.",
  access: "Researchers at an institution may ask the authors' data access committee, which shares them under a data use agreement.",
  files: 2,
  bytes: 129_000_000,
  commitment: withheldCommitment(opening),
  ...overrides,
});

describe("data/withheld.json", () => {
  it("says what each set holds, why it is withheld, who could be given it, its size, and its commitment", () => {
    const sets = [set(), set({ name: "clinical-notes", reason: "law" })];
    expect(readWithheldData(sets)).toEqual({ sets, issues: null });
    expect(withheldBytes(sets)).toBe(258_000_000);
    expect(Object.keys(WITHHELD_REASON_MEANINGS)).toEqual([...WITHHELD_REASONS]);
  });

  it("turns away a set with no reason, no way to ask, a name code couldn't use, or anything it doesn't know", () => {
    const unexplained: Partial<WithheldSet> = set();
    delete unexplained.why;
    const closed: Partial<WithheldSet> = set();
    delete closed.access;
    for (const entry of [unexplained, closed, set({ name: "Raw Scans" }), set({ reason: "embargo" as never }), set({ files: 0 }), { ...set(), url: "https://example.org" }]) {
      expect(readWithheldData([entry]).issues).not.toBeNull();
    }
    expect(readWithheldData([]).issues).not.toBeNull();
    expect(readWithheldData([set(), set()]).issues).toEqual([{ path: "/1/name", message: 'Two sets are named "scans"' }]);
  });
});

describe("a withheld set's commitment", () => {
  it("is the digest of the opening's canonical JSON, so the same files and nonce always commit alike", () => {
    // Worked out apart from this library, with Python's hashlib over json.dumps(sort_keys=True, separators=(",", ":")).
    expect(withheldCommitment(opening)).toBe("sha256:b7f8fa4a84e0c78638669f2e1ee139399e084fd0e974dd75f5303fd8f6f18bac");
  });

  it("tells nothing without the nonce: another nonce over the same files commits differently", () => {
    expect(withheldCommitment({ ...opening, nonce: "ff0102030405060708090a0b0c0d0e0f" })).not.toBe(withheldCommitment(opening));
  });

  it("opens only with the files it committed to, in order, as many and as large as the set says", () => {
    expect(checkWithheldOpening(set(), opening)).toEqual([]);
    const changed = { ...opening, files: [opening.files[0], { ...opening.files[1], sha256: sha256Digest("edited") }] };
    expect(checkWithheldOpening(set(), changed)).toEqual([{ path: "", message: "The opening doesn't digest to the set's commitment" }]);
    expect(checkWithheldOpening(set({ files: 3, bytes: 1 }), opening).map((issue) => issue.path)).toEqual(["/files", "/files"]);
    const reversed = { ...opening, files: [...opening.files].reverse() };
    expect(checkWithheldOpening(set(), reversed)).toEqual([
      { path: "/files/1/path", message: '"sub-01/anat/T1w.nii.gz" is out of order: files go in order of path' },
    ]);
    const twice = { ...opening, files: [opening.files[0], opening.files[0]] };
    expect(checkWithheldOpening(set(), twice)[0].path).toBe("/files");
    const escaping = { ...opening, files: [{ ...opening.files[0], path: "../elsewhere.nii.gz" }] };
    expect(checkWithheldOpening(set(), escaping)[0]).toMatchObject({ path: "/files", message: expect.stringContaining("not a normalized relative path") });
    expect(checkWithheldOpening(set(), { nonce: "short", files: [] }).length).toBeGreaterThan(0);
  });
});

describe("data/withheld/", () => {
  const bytes = new TextEncoder().encode("x");
  const bundle = (path: string) => new Map([["manifest.json", bytes], [path, bytes]]);

  it("is where the work's code reads withheld data, so no bundle carries a file there, sent or uploaded", () => {
    expect(() => digestBundle(bundle("data/withheld/scans/sub-01/anat/T1w.nii.gz"))).toThrow(BundleLayoutError);
    expect(() => digestBundle(bundle("data/Withheld/scans/T1w.nii.gz"))).toThrow(/where withheld data is read from/);
    expect(() => digestBundle(new Map([["manifest.json", bytes]]), new Map([["data/withheld/scans/bold.nii.gz", sha256Digest("bold")]]))).toThrow(BundleLayoutError);
    expect(() => digestBundle(bundle("data/withheld.json"))).not.toThrow();
    expect(() => digestBundle(bundle("data/withheld-notes.csv"))).not.toThrow();
  });
});
