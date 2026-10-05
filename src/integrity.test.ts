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

  it("reads the sections below a title, whatever depth the paper starts at", () => {
    const titled = "# Method X lowers loss\n\nBy 3 points.\n\n## Summary\n\nIt rose 4 points.\n\n## Methods\n\nBatch 64.\n\n## Results\n\nUp 5.";
    expect(numbers(titled)).toEqual(["4", "5"]);
    // A heading shallower than the sections ends the one before it.
    expect(numbers("## Results\n\nUp 5.\n\n# Appendix\n\nTable 6.")).toEqual(["5"]);
  });

  it("flags numbers spelled out in words, though prose may count to nine in words", () => {
    const paper = [
      "# Summary",
      "",
      "Two methods give {{R1.n_records}} records, covering the first ten million integers.",
      "",
      "# Methods",
      "",
      "We search the first ten million integers with one hundred threads.",
      "",
      "# Results",
      "",
      "Anchors: n equals twenty-seven with delay one hundred eleven; n equals eight hundred thirty-seven thousand seven hundred ninety-nine with delay five hundred twenty-four.",
      "",
      "It rose 4 points, then forty, in three of the runs, or two thirds of them.",
    ].join("\n");
    expect(numbers(paper)).toEqual([
      "ten million",
      "twenty-seven",
      "one hundred eleven",
      "eight hundred thirty-seven thousand seven hundred ninety-nine",
      "five hundred twenty-four",
      "4",
      "forty",
      "two thirds",
    ]);
    const found = orphanNumbers(paper).find((orphan) => orphan.number === "twenty-seven")!;
    expect(found).toMatchObject({ section: "Results", line: 11 });
    expect(paper.split("\n")[found.line - 1].slice(found.column - 1)).toMatch(/^twenty-seven with delay/);
  });

  it("leaves spelled-out numbers alone in placeholders, code, math, and headings", () => {
    const paper = "# Results\n\n## Twenty-one runs\n\n{{R1.twenty_one}} and `ninety` and $\\text{forty}$.";
    expect(numbers(paper)).toEqual([]);
  });

  it("leaves a table's number alone in its caption, and flags values in the caption and cells", () => {
    const table = ["| Test | Rejected |", "| --- | --- |", "| Wald | {{R1.wald}} |"];
    expect(numbers(["# Results", "", "**Table 1.** Rejection probabilities.", "", ...table].join("\n"))).toEqual([]);
    expect(numbers(["# Results", "", "**Table 1:** Rejection probabilities.", ...table].join("\n"))).toEqual([]);
    const values = ["# Results", "", "**Table 2.** Rejection at level 0.05.", "", ...table, "| Score | 0.93 |"].join("\n");
    expect(numbers(values)).toEqual(["0.05", "0.93"]);
  });

  it("leaves the paper's tables, figures, and equations alone where the text names them by their labels", () => {
    const paper = [
      "# Methods",
      "",
      "$$",
      "p = \\Pr(T > t) \\tag{3}",
      "$$",
      "",
      "**Table 1.** Rejection probabilities.",
      "",
      "| Test | Rejected |",
      "| --- | --- |",
      "| Wald | {{R1.wald}} |",
      "",
      "# Results",
      "",
      "Table 1 and Figure 2a show it (see Extended Data Fig. 4), as Eq. (3) predicts and Table",
      "1 confirms.",
      "",
      "![Figure 2. Rejection by sample size.](results/fig2.png)",
      "",
      "![Extended Data Fig. 4: Power.](results/fig4.png)",
    ].join("\n");
    expect(numbers(paper)).toEqual([]);
    // Only the labels the paper gives: other numbers beside the same words are flagged.
    const others = "Table 5, Table 12, DataTable 1, Figure 2.5, and (3 runs) stand out.";
    expect(numbers(`${paper}\n\n${others}`)).toEqual(["5", "12", "1", "2.5", "3"]);
    // An equation displayed from one line, $$ and all, is tagged the same way.
    expect(numbers("# Methods\n\nWe use $$p = \\Pr(T > t) \\tag{4}$$ below.\n\n# Results\n\nEq. (4) holds.")).toEqual([]);
  });

  it("reads a label only from a caption that opens with one", () => {
    const table = ["", "| Test | Rejected |", "| --- | --- |", "| Wald | {{R1.wald}} |"];
    expect(numbers(["# Results", "", "**Loss over 3 runs.**", ...table, "", "Loss over 3 runs."].join("\n"))).toEqual(["3", "3"]);
    expect(numbers(["# Results", "", "**The best of four tables 7.**", ...table].join("\n"))).toEqual(["7"]);
    expect(numbers(["# Results", "", "![Loss after 3 epochs.](results/loss.png)", "", "Loss after 3 epochs."].join("\n"))).toEqual(["3"]);
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

  it("flag the files the claims call for that the bundle lacks", () => {
    const measurement = { result: "R1.mp", measured: "data/dsc.csv" };
    const claim = (type: string, evidence: unknown[], dependsOn: string[] = []) => ({
      local_id: "C1",
      type,
      core: true,
      statement: "A statement.",
      evidence,
      depends_on: dependsOn,
      confidence: 0.5,
    });
    const flagged = (claims: unknown[], others: [string, string][] = [], paths?: string[]) =>
      integrityFlags([["claims.json", encode(JSON.stringify(claims))], ...others.map(([path, text]) => [path, encode(text)] as const)], paths)
        .missing_files;

    expect(flagged([claim("empirical", [measurement])])).toEqual(["materials.json"]);
    expect(flagged([claim("empirical", [measurement])], [], ["claims.json", "materials.json"])).toEqual([]);
    expect(flagged([claim("empirical", [{ result: "R1.x", produced_by: "code/a.py" }])])).toEqual([]);
    const original = `claim:${"a".repeat(64)}`;
    expect(flagged([claim("replication", [measurement], [original])], [], ["claims.json", "materials.json"])).toEqual(["deviations.json"]);
    const prereg = `prereg:${"b".repeat(64)}`;
    expect(flagged([claim("theoretical", [])], [["references.json", JSON.stringify([{ id: prereg }])]])).toEqual(["deviations.json"]);
    // A claims file that doesn't parse is the bundle check's to reject, not a flag's.
    expect(integrityFlags([["claims.json", encode("[{")]]).missing_files).toEqual([]);
  });

  it("flag sources references.json lists that the paper never cites, and citations it doesn't list", () => {
    const claim = `claim:${"a".repeat(64)}`;
    const paper = [
      "# Methods",
      "",
      "We follow [Leavens and Vermeulen (1992)](doi:10.1016/0898-1221(92)90034-F) and <" + claim + ">,",
      "and extend [an earlier bound][bound].",
      "",
      "[bound]: arxiv:2401.12345",
      "",
      "See also [the code](code/run.py), [a page](https://example.org), and [a mistyped ID](claim:abc).",
    ].join("\n");
    const references = [
      { id: "doi:10.1016/0898-1221(92)90034-F", title: "3x+1 search programs", authors: ["Leavens, G. T."], year: 1992 },
      { id: claim },
      { id: "pmid:12345", title: "A source", authors: ["A. Author"], year: 2001 },
    ];
    const flags = integrityFlags([
      ["paper.md", encode(paper)],
      ["references.json", encode(JSON.stringify(references))],
    ]);
    expect(flags.uncited_references).toEqual(["pmid:12345"]);
    expect(flags.unlisted_citations).toEqual(["arxiv:2401.12345"]);

    // Without references.json, every citation is unlisted; with one that doesn't parse, the bundle check rejects it first.
    expect(integrityFlags([["paper.md", encode(paper)]]).unlisted_citations).toEqual([
      "doi:10.1016/0898-1221(92)90034-F",
      claim,
      "arxiv:2401.12345",
    ]);
    const broken = integrityFlags([
      ["paper.md", encode(paper)],
      ["references.json", encode("[{")],
    ]);
    expect([broken.uncited_references, broken.unlisted_citations]).toEqual([[], []]);
  });

  it("skip tables too large to check, and say so", () => {
    const large = new Uint8Array(8 * 1024 * 1024 + 1).fill(0x31);
    expect(integrityFlags([["data/big.tsv", large]]).skipped).toEqual([{ path: "data/big.tsv", bytes: large.length }]);
  });
});
