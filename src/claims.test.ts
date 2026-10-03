import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  assertionDigest,
  assignClaimIds,
  ClaimIdSchema,
  ClaimsFileSchema,
  needsReproduction,
  resultsNamed,
  type Claim,
} from "./claims";
import { declaredInputs, ResultError, type BundleInputs } from "./results";

const RESULTS = { "R3.loss_delta": -0.0123, "R3.seeds": 5, "R4.acc": 0.91, "R5.melting_point": 151.8 };
const INPUTS = declaredInputs(`sha256:${"1".repeat(64)}`, RESULTS);
const OTHER_INPUTS = declaredInputs(`sha256:${"2".repeat(64)}`, RESULTS);

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

const idOf = (claims: Claim[], localId: string, inputs: BundleInputs = INPUTS) =>
  assignClaimIds(claims, inputs).get(localId);

describe("assignClaimIds", () => {
  it("hashes the whole claim except local_id, plus the verification inputs and the results it names", () => {
    const preimage =
      '{"confidence":0.8,"core":true,"depends_on":[],' +
      '"evidence":[{"produced_by":"code/eval.py","result":"R3.loss_delta","tolerance":0.002}],' +
      '"falsified_if":"A re-run with 5 fresh seeds yields no significant improvement.",' +
      '"results":{"R3.loss_delta":-0.0123},' +
      '"statement":"Method X lowers validation loss vs. baseline Y on dataset Z across 5 seeds.",' +
      `"type":"empirical","verification_inputs":"${INPUTS.verificationInputs}"}`;
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

  it("changes only for the claims that read a corrected result", () => {
    const other = claim({
      local_id: "C4",
      type: "empirical",
      evidence: [{ result: "R4.acc", produced_by: "code/eval.py" }],
    });
    const corrected = declaredInputs(INPUTS.verificationInputs, { ...RESULTS, "R3.loss_delta": -0.0119 });
    expect(idOf([empirical, other], "C3", corrected)).not.toBe(idOf([empirical, other], "C3"));
    expect(idOf([empirical, other], "C4", corrected)).toBe(idOf([empirical, other], "C4"));
  });

  it("binds measured results, and proofs without any results", () => {
    const measured = claim({
      local_id: "M1",
      type: "empirical",
      evidence: [{ result: "R5.melting_point", measured: "data/dsc/run1.csv", tolerance: 0.5 }],
    });
    const corrected = declaredInputs(INPUTS.verificationInputs, { ...RESULTS, "R5.melting_point": 152.4 });
    expect(idOf([measured], "M1", corrected)).not.toBe(idOf([measured], "M1"));

    const proved = claim({
      local_id: "P1",
      evidence: [{ proof: "proofs/Main.lean", theorem: "Main.prime_order_cyclic", checker: "lean4" }],
    });
    const noResults = declaredInputs(INPUTS.verificationInputs, {});
    expect(idOf([proved], "P1", noResults)).toBe(idOf([proved], "P1"));
    expect(idOf([proved], "P1", OTHER_INPUTS)).not.toBe(idOf([proved], "P1"));
  });

  it("throws ResultError for a result the bundle doesn't declare", () => {
    expect(() => idOf([empirical], "C3", declaredInputs(INPUTS.verificationInputs, {}))).toThrow(ResultError);
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

describe("evidence kinds", () => {
  it("re-runs only computations", () => {
    expect(needsReproduction(empirical)).toBe(true);
    expect(
      needsReproduction(claim({ local_id: "M1", evidence: [{ result: "R5.melting_point", measured: "data/a.csv" }] })),
    ).toBe(false);
    expect(
      needsReproduction(claim({ local_id: "P1", evidence: [{ proof: "proofs/A.lean", theorem: "A.t", checker: "lean4" }] })),
    ).toBe(false);
  });

  it("names each result once", () => {
    const twice = claim({
      local_id: "C9",
      evidence: [
        { result: "R1.a", produced_by: "code/a.py" },
        { result: "R1.b", measured: "data/b.csv" },
        { result: "R1.a", produced_by: "code/b.py" },
        { proof: "proofs/A.lean", theorem: "A.t", checker: "rocq" },
      ],
    });
    expect(resultsNamed(twice)).toEqual(["R1.a", "R1.b"]);
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

  it.each<[string, unknown]>([
    ["a computation outside code/", { result: "R1.a", produced_by: "eval.py" }],
    ["a measurement outside data/", { result: "R1.a", measured: "results/R1.json" }],
    ["a proof outside proofs/", { proof: "code/A.lean", theorem: "A.t", checker: "lean4" }],
    ["an unknown proof checker", { proof: "proofs/A.thy", theorem: "A.t", checker: "isabelle" }],
    ["a result name without a key", { result: "R1", produced_by: "code/a.py" }],
    ["an item that is two kinds at once", { result: "R1.a", produced_by: "code/a.py", measured: "data/a.csv" }],
  ])("rejects %s", (_, item) => {
    expect(issues([{ ...empirical, evidence: [item] }])).not.toEqual([]);
  });

  it("accepts any path a bundle may hold under the right directory, line separators included", () => {
    expect(issues([{ ...empirical, evidence: [{ result: "R1.a", produced_by: "code/\u2028x.py" }] }])).toEqual([]);
    expect(issues([{ ...empirical, evidence: [{ result: "R1.a", measured: "data/\u2029" }] }])).toEqual([]);
    expect(issues([{ ...empirical, evidence: [{ result: "R1.a", produced_by: "code/" }] }])).not.toEqual([]);
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
