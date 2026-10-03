import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { BundleLayoutError, digestBundle } from "./bundle";

const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");

function bundle(files: Record<string, string>): Map<string, Uint8Array> {
  const encoder = new TextEncoder();
  return new Map(Object.entries(files).map(([path, text]) => [path, encoder.encode(text)]));
}

const base = {
  "manifest.json": "{}",
  "paper.md": "# Summary",
  "claims.json": "[]",
  "code/eval.py": "print(1)",
  "results/R3.json": '{"loss_delta":-0.03}',
  signature: "ed25519:00",
};

describe("digestBundle", () => {
  it("hashes each file, and the bundle as canonical JSON of path to file digest", () => {
    const digests = digestBundle(bundle({ "paper.md": "hi", "code/a.py": "x", signature: "s" }));

    expect(digests.files["paper.md"]).toBe(`sha256:${sha256("hi")}`);
    expect(digests.bundle).toBe(
      `sha256:${sha256(`{"code/a.py":"sha256:${sha256("x")}","paper.md":"sha256:${sha256("hi")}"}`)}`,
    );
    expect(digests.verificationInputs).toBe(
      `sha256:${sha256(`{"code/a.py":"sha256:${sha256("x")}"}`)}`,
    );
  });

  it("leaves the signature out of the bundle hash", () => {
    const signed = digestBundle(bundle(base));
    const resigned = digestBundle(bundle({ ...base, signature: "ed25519:ff" }));
    expect(resigned.bundle).toBe(signed.bundle);
    expect(resigned.files.signature).not.toBe(signed.files.signature);
  });

  it.each(["code/eval.py", "env/lock.txt", "data/rows.csv", "results/R3.json", "proofs/t.lean"])(
    "changes the verification inputs when %s changes",
    (path) => {
      const before = digestBundle(bundle(base));
      const after = digestBundle(bundle({ ...base, [path]: "changed" }));
      expect(after.verificationInputs).not.toBe(before.verificationInputs);
      expect(after.bundle).not.toBe(before.bundle);
    },
  );

  it("keeps the verification inputs when only prose or metadata changes", () => {
    const before = digestBundle(bundle(base));
    const after = digestBundle(bundle({ ...base, "paper.md": "# Summary, revised" }));
    expect(after.verificationInputs).toBe(before.verificationInputs);
    expect(after.bundle).not.toBe(before.bundle);
  });

  it.each([
    ["an empty path", [""]],
    ["an absolute path", ["/paper.md"]],
    ["an empty segment", ["code//a.py"]],
    ["a trailing slash", ["code/"]],
    ["a dot segment", ["code/./a.py"]],
    ["a parent segment", ["code/../paper.md"]],
    ["a backslash", ["code\\a.py"]],
    ["a control character", [`code/a${String.fromCharCode(7)}.py`]],
    ["a non-NFC path", [`code/e${String.fromCodePoint(0x301)}.py`]],
    ["an unknown top-level file", ["notes.txt"]],
    ["an unknown directory", ["src/a.py"]],
    ["a directory name used as a file", ["code"]],
    ["paths differing only in case", ["code/A.py", "code/a.py"]],
    ["a path that is both file and directory", ["code/a", "code/a/b.py"]],
    ["a file and directory differing only in case", ["code/A", "code/a/b.py"]],
  ])("rejects %s", (_, paths) => {
    const files = new Map(paths.map((path) => [path, new Uint8Array()]));
    expect(() => digestBundle(files)).toThrow(BundleLayoutError);
  });

  it("accepts nested paths and Unicode NFC names", () => {
    expect(() =>
      digestBundle(bundle({ ...base, "data/raw/séance.csv": "a,b", "proofs/Main.lean": "" })),
    ).not.toThrow();
  });
});
