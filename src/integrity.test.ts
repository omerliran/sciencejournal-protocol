import { describe, expect, it } from "vitest";
import { BENFORD, integrityFlags, orphanNumbers, parseDelimited, tableFlags } from "./integrity";

const numbers = (markdown: string) => orphanNumbers(markdown).map((found) => found.number);

describe("no orphan numbers", () => {
  it("flags numbers typed into the sections that state results, and not those bound to results", () => {
    const paper = [
      "# Summary",
      "",
      "Method X lowers loss by {{R1.loss_delta}} across {{R1.seeds}} seeds, a 12.5% gain.",
      "",
      "# Methods",
      "",
      "We train for 30 epochs at a learning rate of 0.001.",
      "",
      "# Results",
      "",
      "| Model | Loss |",
      "| --- | --- |",
      "| X | 0.412 |",
      "",
      "Accuracy rose to −3e-2 below baseline, and 1,204 runs finished.",
    ].join("\n");
    expect(orphanNumbers(paper)).toEqual([
      expect.objectContaining({ section: "Summary", line: 3, number: "12.5", excerpt: expect.stringContaining("12.5% gain") }),
      expect.objectContaining({ section: "Results", line: 13, number: "0.412" }),
      expect.objectContaining({ section: "Results", line: 15, number: "−3e-2" }),
      expect.objectContaining({ section: "Results", line: 15, number: "1,204" }),
    ]);
    const [first] = orphanNumbers(paper);
    expect(paper.split("\n")[first.line - 1].slice(first.column - 1)).toMatch(/^12\.5/);
  });

  it("skips code, math, links, headings, names, and years", () => {
    const paper = [
      "# Claims",
      "",
      "## Claim 2 holds",
      "",
      "C1 and R3 extend GPT-4 and ResNet-50, as in 2024; see `seed=42`, $x^2 = 4$, and [the code](code/run2.py).",
      "",
      "```",
      "loss = 0.5",
      "```",
      "",
      "$$",
      "y = 3x",
      "$$",
      "",
      "Data at https://example.org/v2/run7 and www.example.org/9.",
    ].join("\n");
    expect(numbers(paper)).toEqual([]);
  });

  it("reads a paper's sections at its top heading level, and nothing before the first", () => {
    expect(numbers("Preamble with 7 numbers.\n\n## Summary\n\nIt rose 4 points.\n\n### Detail\n\nBy 9.\n\n## Methods\n\nBatch 64.")).toEqual([
      "4",
      "9",
    ]);
    expect(numbers("No headings at all: 5.")).toEqual([]);
  });

  it("counts positions in code points, and shows hidden characters in excerpts", () => {
    const [found] = orphanNumbers("# Results\n\n🐝 rose by 3​ points.");
    expect(found).toMatchObject({ line: 3, column: 11, number: "3" });
    expect(found.excerpt).toContain("<U+200B>");
  });
});

describe("tables", () => {
  it("parse as RFC 4180 does: quoted delimiters, line breaks, and doubled quotes", () => {
    expect(parseDelimited('a,b\r\n"1,5","say ""hi""\nthere"\n\n3,4\n', ",")).toEqual([
      ["a", "b"],
      ["1,5", 'say "hi"\nthere'],
      ["3", "4"],
    ]);
    expect(parseDelimited("﻿x\ty\n1\t2", "\t")).toEqual([
      ["x", "y"],
      ["1", "2"],
    ]);
  });

  it("flag exact duplicate rows, naming the rows", () => {
    const rows = parseDelimited("site,count\na,1\nb,2\na,1\nc,3\na,1\n", ",");
    expect(tableFlags("data/counts.csv", rows)).toEqual([
      {
        kind: "duplicate_rows",
        path: "data/counts.csv",
        rows: 5,
        duplicates: 2,
        examples: [
          { row: 4, repeats: 2 },
          { row: 6, repeats: 2 },
        ],
      },
    ]);
  });

  it("flag a numeric column whose first digits stray from Benford's law", () => {
    // Numbers spread evenly over 1 to 1,000,000 by their logarithm follow Benford's law.
    const natural = Array.from({ length: 2000 }, (_, i) => (10 ** ((6 * (i + 0.5)) / 2000)).toFixed(3));
    // Invented numbers spread evenly over the digits don't.
    const invented = Array.from({ length: 2000 }, (_, i) => String(((i % 9) + 1) * 10 ** (i % 4)));
    const table = [["natural", "invented", "label"], ...natural.map((n, i) => [n, invented[i], `row ${i}`])];
    const flags = tableFlags("data/values.csv", table);
    expect(flags).toEqual([
      expect.objectContaining({ kind: "benford", path: "data/values.csv", column: "invented", values: 2000 }),
    ]);
    const [flag] = flags;
    if (flag.kind !== "benford") throw new Error("expected a Benford flag");
    expect(flag.mad).toBeGreaterThan(0.015);
    expect(flag.observed.reduce((a, b) => a + b, 0)).toBeCloseTo(1, 3);
    expect(BENFORD[0]).toBeCloseTo(0.301, 3);
  });

  it("leave Benford's law out for small columns and narrow ranges", () => {
    const few = [["x"], ...Array.from({ length: 100 }, () => ["5"])];
    const narrow = [["x"], ...Array.from({ length: 1000 }, (_, i) => [String(50 + (i % 40))])];
    expect(tableFlags("data/few.csv", few)).toEqual([expect.objectContaining({ kind: "duplicate_rows" })]);
    expect(tableFlags("data/narrow.csv", narrow).filter((flag) => flag.kind === "benford")).toEqual([]);
  });
});

describe("a bundle's integrity flags", () => {
  const encode = (text: string) => new TextEncoder().encode(text);

  it("check paper.md and the tables under data/, and skip what they can't read", () => {
    const flags = integrityFlags([
      ["paper.md", encode("# Summary\n\nLoss fell by 0.03.\n")],
      ["data/a.csv", encode("x,y\n1,2\n1,2\n")],
      ["data/notes.md", encode("# Results\n\nNot the paper: 99.\n")],
      ["results/R1.csv", encode("x\n1\n1\n")],
      ["data/binary.csv", new Uint8Array([0xff, 0xfe, 0x00])],
    ]);
    expect(flags.orphan_numbers.map((found) => found.number)).toEqual(["0.03"]);
    expect(flags.data).toEqual([expect.objectContaining({ kind: "duplicate_rows", path: "data/a.csv" })]);
    expect(flags.skipped).toEqual([]);
  });

  it("skip tables too large to check, and say so", () => {
    const large = new Uint8Array(8 * 1024 * 1024 + 1).fill(0x31);
    expect(integrityFlags([["data/big.tsv", large]]).skipped).toEqual([{ path: "data/big.tsv", bytes: large.length }]);
  });
});
