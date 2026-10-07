import { expect, it } from "vitest";
import type { IntegrityFlags } from "../integrity";
import { renderBrief } from "./brief";
import type { JobRecord, ScanRecord } from "./job";

// IDs of the shape operators' and volunteers' first keys make: op: or obs: and 64 hex digits.
const exampleId = (kind: "op" | "obs", n: number) => `${kind}:${n.toString(16).padStart(64, "0")}`;
const op1 = exampleId("op", 1);

const record = (integrity?: IntegrityFlags): JobRecord => ({
  job: "job:abc",
  kind: "screen",
  bundle: `sha256:${"a".repeat(64)}`,
  deadline: "2026-10-04T12:00:00.000Z",
  fields: ["machine-learning"],
  compute: { minutes: 30, gpu: false },
  claims: [],
  credits: 1,
  files: {},
  node: "https://sciencejournal.ai",
  operator: op1,
  received_at: "2026-10-03T12:00:00.000Z",
  harness: "test",
  verification_inputs: `sha256:${"b".repeat(64)}`,
  claim_ids: "match",
  ...(integrity && { integrity }),
});

const scan: ScanRecord = { scanned: [], binary: [], findings: [], omitted: {}, harness: "test", skipped: [] };
const brief = (integrity?: IntegrityFlags) =>
  renderBrief({ record: record(integrity), jobDir: "job-abc", scan, declared: [], invocation: "sj-harness", now: new Date("2026-10-03T12:00:00Z") });

it("lists what the node's integrity checks flagged, as things to look at", () => {
  const text = brief({
    orphan_numbers: [{ section: "Results", line: 9, column: 14, number: "0.412", excerpt: "Loss fell to 0.412." }],
    missing_sections: ["Methods"],
    missing_files: ["materials.json"],
    uncited_references: ["pmid:12345"],
    unlisted_citations: ["arxiv:2401.12345", "doi:10.1/x"],
    data: [
      { kind: "duplicate_rows", path: "data/runs.csv", rows: 40, duplicates: 2, examples: [{ row: 7, repeats: 3 }] },
      { kind: "benford", path: "data/sales.csv", column: "amount", values: 900, mad: 0.031, observed: [] },
    ],
    skipped: [{ path: "data/huge.csv", bytes: 9 * 1024 * 1024 }],
  });
  expect(text).toContain("## Integrity flags");
  expect(text).toContain("`paper.md`, line 9, column 14, in Results: `0.412`");
  expect(text).toContain("2 of 40 data rows repeat an earlier one (row 7 repeats 3)");
  expect(text).toContain("column `amount`: its first digits stray from Benford's law, with a mean absolute deviation of 0.031 over 900 values");
  expect(text).toContain("`data/huge.csv`");
  expect(text).toContain("not a finding");
  expect(text).toContain("The paper has no Methods section");
  expect(text).toContain("The bundle has no `materials.json`, though a claim rests on a measurement");
  expect(text).toContain("`references.json` lists 1 source the paper never cites, so nothing says what it supports: `pmid:12345`.");
  expect(text).toContain("The paper cites 2 sources that `references.json` doesn't list, so no citation check judges them: `arxiv:2401.12345`, `doi:10.1/x`.");
  expect(text).toContain("in digits or in words");
});

it("says when the checks flagged nothing, and leaves the section out for a node that doesn't run them", () => {
  expect(
    brief({ orphan_numbers: [], missing_sections: [], missing_files: [], uncited_references: [], unlisted_citations: [], data: [], skipped: [] }),
  ).toContain("The node's checks flagged nothing");
  // A node from before the paper and file checks doesn't send them.
  expect(brief({ orphan_numbers: [], data: [], skipped: [] } as unknown as IntegrityFlags)).toContain("The node's checks flagged nothing");
  expect(brief()).not.toContain("## Integrity flags");
});

it("shows a review what the work's materials resolve to, and which give no RRID", () => {
  const review: JobRecord = {
    ...record(),
    kind: "methods_review",
    claims: [{ local_id: "M1", claim_id: `claim:${"c".repeat(64)}`, needs_verdict: true }],
  };
  const text = renderBrief({
    record: review,
    jobDir: "job-abc",
    scan,
    declared: [],
    materials: {
      materials: [
        { kind: "cell_line", name: "HEp-2", rrid: "RRID:CVCL_1906" },
        { kind: "antibody", name: "Anti-X", rrid: "RRID:AB_0000001" },
        { kind: "antibody", name: "Anti-Y | rabbit" },
        { kind: "chemical", name: "Water" },
      ],
      lookups: [
        {
          rrid: "RRID:CVCL_1906",
          found: "resolved",
          name: "HEp-2",
          citation: "ATCC Cat# CCL-23, RRID:CVCL_1906",
          problems: ["Problematic cell line: Contaminated. Shown to be a HeLa derivative."],
          notes: ["Discontinued: ATCC; CRL-7923"],
        },
        { rrid: "RRID:AB_0000001", found: "unknown", problems: [], notes: [] },
      ],
      not_looked_up: [],
    },
    invocation: "sj-harness",
    now: new Date("2026-10-03T12:00:00Z"),
  });
  expect(text).toContain("whether someone else could repeat the work from the bundle alone");
  expect(text).toContain("## Materials");
  expect(text).toContain("| `RRID:CVCL_1906` | `HEp-2`, `ATCC Cat# CCL-23, RRID:CVCL_1906` | `Problematic cell line: Contaminated. Shown to be a HeLa derivative.` | `Discontinued: ATCC; CRL-7923` |");
  expect(text).toContain("| `RRID:AB_0000001` | nothing: the resolver has no such RRID |");
  expect(text).toContain("these give none, so nothing pins down which one was used: `Anti-Y \\| rabbit` (antibody).");
});

it("marks a source cited only to compare with, says where the paper cites each, and how to judge a comparison", () => {
  const text = renderBrief({
    record: {
      ...record(),
      kind: "citation_check",
      claims: [{ claim_id: `claim:${"c".repeat(64)}`, local_id: "C1" } as JobRecord["claims"][number]],
      citations: [
        { reference: "doi:10.1/support", claims: [`claim:${"c".repeat(64)}`], cited_at: [{ section: "Results", line: 12 }], title: "A source", authors: ["A. Author"], year: 2020 },
        {
          reference: "doi:10.1/compared",
          claims: [],
          cited_at: [
            { section: "Discussion", line: 40 },
            { section: "Discussion", line: 44 },
          ],
          title: "Another project",
          authors: ["B. Author"],
          year: 2015,
        },
      ],
    },
    jobDir: "job-abc",
    scan,
    declared: [],
    invocation: "sj-harness",
    now: new Date("2026-10-03T12:00:00Z"),
  });
  expect(text).toContain("| `doi:10.1/support` | `C1` | Results, line 12 | `A source` (2020), by `A. Author` |");
  expect(text).toContain("| `doi:10.1/compared` | comparison only | Discussion, line 40; Discussion, line 44 | `Another project` (2015), by `B. Author` |");
  expect(text).toContain("Judge whether the paper describes it fairly where it cites it");
});
