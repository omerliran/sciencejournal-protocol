import { describe, expect, it } from "vitest";
import { diffLines, unifiedDiff, type DiffLine } from "./diff";

/** The two texts a diff's lines rebuild. */
const sides = (lines: readonly DiffLine[]) => ({
  before: lines.filter((line) => line.kind !== "+").map((line) => line.text),
  after: lines.filter((line) => line.kind !== "-").map((line) => line.text),
});

describe("line diffs", () => {
  it("find the fewest lines to change, and rebuild both texts from them", () => {
    const before = ["a", "b", "c", "a", "b", "b", "a"];
    const after = ["c", "b", "a", "b", "a", "c"];
    const lines = diffLines(before, after)!;
    expect(sides(lines)).toEqual({ before, after });
    // Myers's own example: five lines change, no fewer.
    expect(lines.filter((line) => line.kind !== " ")).toHaveLength(5);
    expect(diffLines([], ["x"])).toEqual([{ kind: "+", text: "x" }]);
    expect(diffLines(["x"], [])).toEqual([{ kind: "-", text: "x" }]);
    expect(diffLines(["same"], ["same"])).toEqual([{ kind: " ", text: "same" }]);
  });

  it("rebuild both sides of texts that differ at random", () => {
    let seed = 7;
    const random = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
    for (let round = 0; round < 50; round++) {
      const text = () => Array.from({ length: Math.floor(random() * 30) }, () => "abcd"[Math.floor(random() * 4)]);
      const before = text();
      const after = text();
      expect(sides(diffLines(before, after)!)).toEqual({ before, after });
    }
  });

  it("give hunks with context, numbered as unified diffs are", () => {
    const before = Array.from({ length: 20 }, (_, i) => `line ${i + 1}`).join("\n") + "\n";
    const after = before.replace("line 10\n", "line ten\n").replace("line 19\n", "");
    const diff = unifiedDiff(before, after, { context: 2 });
    expect(diff).toEqual({
      changed: 3,
      hunks: ["@@ -8,5 +8,5 @@", " line 8", " line 9", "-line 10", "+line ten", " line 11", " line 12", "@@ -17,4 +17,3 @@", " line 17", " line 18", "-line 19", " line 20"].join(
        "\n",
      ),
    });
    expect(unifiedDiff("same\n", "same\n")).toEqual({ hunks: "", changed: 0 });
  });

  it("say only how much changed past the most lines worth showing", () => {
    const before = Array.from({ length: 50 }, (_, i) => `old ${i}`).join("\n");
    const after = Array.from({ length: 40 }, (_, i) => `new ${i}`).join("\n");
    expect(unifiedDiff(before, after, { maxChanged: 30 })).toEqual({ rewritten: true, changed: 90, lines: 50 });
  });
});
