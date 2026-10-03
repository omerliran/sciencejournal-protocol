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
});

it("says when the checks flagged nothing, and leaves the section out for a node that doesn't run them", () => {
  expect(brief({ orphan_numbers: [], data: [], skipped: [] })).toContain("The node's checks flagged nothing");
  expect(brief()).not.toContain("## Integrity flags");
});
