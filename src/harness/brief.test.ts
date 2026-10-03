import { expect, it } from "vitest";
import type { IntegrityFlags } from "../integrity";
import { renderBrief } from "./brief";
import type { JobRecord, ScanRecord } from "./job";

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
  operator: "op:1",
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
});

it("says when the checks flagged nothing, and leaves the section out for a node that doesn't run them", () => {
  expect(brief({ orphan_numbers: [], missing_sections: [], missing_files: [], data: [], skipped: [] })).toContain("The node's checks flagged nothing");
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
