import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  assertionDigest,
  assignClaimIds,
  ClaimIdSchema,
  ClaimsFileSchema,
  type Claim,
} from "./claims";
import type { Digest } from "./hash";

const INPUTS: Digest = `sha256:${"1".repeat(64)}`;
const OTHER_INPUTS: Digest = `sha256:${"2".repeat(64)}`;

function claim(overrides: Partial<Claim> & Pick<Claim, "local_id">): Claim {
  return {
    type: "theoretical",
    core: true,
    statement: `Statement of ${overrides.local_id}.`,
    evidence: [],
    depends_on: [],
    confidence: 0.8,
    ...overrides,
  };
}

const empirical = claim({
  local_id: "C3",
  type: "empirical",
  statement: "Method X lowers validation loss vs. baseline Y on dataset Z across 5 seeds.",
  evidence: [{ result: "R3.loss_delta", produced_by: "code/eval.py", tolerance: 0.002 }],
  falsified_if: "A re-run with 5 fresh seeds yields no significant improvement.",
});

const idOf = (claims: Claim[], localId: string, inputs: Digest = INPUTS) =>
  assignClaimIds(claims, inputs).get(localId);

describe("assignClaimIds", () => {
  it("hashes the whole claim except local_id, plus the verification inputs", () => {
    const preimage =
      '{"confidence":0.8,"core":true,"depends_on":[],' +
      '"evidence":[{"produced_by":"code/eval.py","result":"R3.loss_delta","tolerance":0.002}],' +
      '"falsified_if":"A re-run with 5 fresh seeds yields no significant improvement.",' +
      '"statement":"Method X lowers validation loss vs. baseline Y on dataset Z across 5 seeds.",' +
      `"type":"empirical","verification_inputs":"${INPUTS}"}`;
    const expected = `claim:${createHash("sha256").update(preimage).digest("hex")}`;
    expect(idOf([empirical], "C3")).toBe(expected);
    expect(ClaimIdSchema.safeParse(expected).success).toBe(true);
  });

  it("ignores the local label", () => {
    expect(idOf([{ ...empirical, local_id: "Z9" }], "Z9")).toBe(idOf([empirical], "C3"));
  });

  it.each<[string, Partial<Claim>]>([
    ["statement", { statement: "Method X lowers loss on dataset W." }],
    ["core", { core: false }],
    ["confidence", { confidence: 0.5 }],
    ["falsified_if", { falsified_if: "Something else." }],
    ["evidence", { evidence: [{ result: "R4.acc", produced_by: "code/eval.py" }] }],
  ])("changes when %s changes", (_, change) => {
    expect(idOf([{ ...empirical, ...change }], "C3")).not.toBe(idOf([empirical], "C3"));
  });

  it("binds verification inputs only for claims with evidence", () => {
    expect(idOf([empirical], "C3", OTHER_INPUTS)).not.toBe(idOf([empirical], "C3"));
    const theory = claim({ local_id: "T1" });
    expect(idOf([theory], "T1", OTHER_INPUTS)).toBe(idOf([theory], "T1"));
  });

  it("resolves local dependencies to global IDs, ignoring order and duplicates", () => {
    const base = claim({ local_id: "C1" });
    const baseId = idOf([base], "C1")!;
    const other = `claim:${"a".repeat(64)}` as const;

    const viaLocal = idOf(
      [claim({ local_id: "C2", statement: "S", depends_on: ["C1", other, "C1"] }), base],
      "C2",
    );
    const viaGlobal = idOf([claim({ local_id: "C2", statement: "S", depends_on: [other, baseId] })], "C2");

    expect(viaLocal).toBe(viaGlobal);
  });

  it("propagates upstream changes to dependents", () => {
    const dependent = claim({ local_id: "C2", depends_on: ["C1"] });
    const before = idOf([claim({ local_id: "C1" }), dependent], "C2");
    const after = idOf([claim({ local_id: "C1", statement: "Changed." }), dependent], "C2");
    expect(after).not.toBe(before);
  });
});

describe("assertionDigest", () => {
  it("matches restatements whatever their evidence or framing", () => {
    const restated = { ...empirical, evidence: [{ result: "R1.d", produced_by: "code/run.py" }] };
    expect(assertionDigest(restated)).toBe(assertionDigest(empirical));
    expect(assertionDigest({ ...empirical, type: "replication" })).not.toBe(
      assertionDigest(empirical),
    );
  });
});

describe("ClaimsFileSchema", () => {
  const issues = (claims: unknown) => {
    const result = ClaimsFileSchema.safeParse(claims);
    return result.success ? [] : result.error.issues.map((issue) => issue.message);
  };

  it("accepts the design doc's example claim", () => {
    expect(issues([empirical])).toEqual([]);
  });

  it("rejects fields the protocol doesn't define", () => {
    expect(issues([{ ...empirical, note: "x" }])).not.toEqual([]);
    expect(
      issues([{ ...empirical, evidence: [{ ...empirical.evidence[0], seed: 1 }] }]),
    ).not.toEqual([]);
  });

  it("rejects dependency cycles", () => {
    expect(
      issues([
        claim({ local_id: "C1", depends_on: ["C2"] }),
        claim({ local_id: "C2", depends_on: ["C1"] }),
      ]),
    ).toEqual([expect.stringContaining("cycle")]);
    expect(issues([claim({ local_id: "C1", depends_on: ["C1"] })])).toEqual([
      expect.stringContaining("cycle"),
    ]);
  });

  it("rejects unknown local dependencies and duplicate local IDs", () => {
    expect(issues([claim({ local_id: "C1", depends_on: ["C7"] })])).toEqual([
      expect.stringContaining('unknown local claim "C7"'),
    ]);
    expect(issues([claim({ local_id: "C1" }), claim({ local_id: "C1" })])).toEqual([
      expect.stringContaining("Duplicate"),
    ]);
  });

  it("rejects malformed global dependencies", () => {
    expect(issues([claim({ local_id: "C1", depends_on: ["claim:7f3a"] })])).not.toEqual([]);
  });

  it("requires evidence on empirical claims", () => {
    expect(issues([{ ...empirical, evidence: [] }])).toEqual([
      expect.stringContaining("evidence"),
    ]);
  });

  it("enforces the per-bundle claim limit", () => {
    const tooMany = Array.from({ length: 31 }, (_, i) => claim({ local_id: `C${i + 1}` }));
    expect(issues(tooMany)).not.toEqual([]);
    expect(issues(tooMany.slice(0, 30))).toEqual([]);
  });
});
