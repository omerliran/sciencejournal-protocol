import { describe, expect, it } from "vitest";
import { assignClaimIds, claimsFileJsonSchema, type Claim } from "./claims";
import { bundleInputs, declaredInputs } from "./results";
import { checkClaims } from "./validate";

const INPUTS = declaredInputs(`sha256:${"1".repeat(64)}`, { "R1.x": 3 });

const theory: Claim = {
  local_id: "T1",
  type: "theoretical",
  core: true,
  statement: "A theorem.",
  evidence: [],
  depends_on: [],
  confidence: 0.9,
};
const experiment: Claim = {
  local_id: "E1",
  type: "empirical",
  core: true,
  statement: "A measurement.",
  evidence: [{ result: "R1.x", produced_by: "code/run.py" }],
  depends_on: ["T1"],
  confidence: 0.7,
};
const consequence: Claim = { ...theory, local_id: "T2", statement: "Follows.", depends_on: ["E1"] };

describe("checkClaims", () => {
  it("returns the same IDs as assignClaimIds when given the verification inputs", () => {
    const check = checkClaims([theory, experiment, consequence], INPUTS);
    const ids = assignClaimIds([theory, experiment, consequence], INPUTS);
    expect(check.valid && check.claims.map((c) => c.claim_id)).toEqual([
      ids.get("T1"),
      ids.get("E1"),
      ids.get("T2"),
    ]);
  });

  it("leaves IDs null for claims bound to missing verification inputs, directly or upstream", () => {
    const check = checkClaims([theory, experiment, consequence]);
    const ids = assignClaimIds([theory, experiment, consequence], INPUTS);
    expect(check.valid && check.claims.map((c) => [c.local_id, c.claim_id])).toEqual([
      ["T1", ids.get("T1")],
      ["E1", null],
      ["T2", null],
    ]);
  });

  it("reports problems with JSON Pointer paths", () => {
    const check = checkClaims([{ ...experiment, evidence: [] }, { ...theory, confidence: 2 }]);
    expect(check).toEqual({
      valid: false,
      issues: [
        { path: "/0/evidence", message: expect.stringContaining("Empirical claims") },
        { path: "/1/confidence", message: expect.any(String) },
      ],
    });
  });

  it("reports undeclared results and missing evidence files at their evidence items", () => {
    const encoder = new TextEncoder();
    const files = new Map([
      ["results/R1.json", encoder.encode('{"x": 3}')],
      ["data/a.csv", encoder.encode("a\n1\n")],
    ]);
    const check = checkClaims(
      [
        theory,
        {
          ...experiment,
          evidence: [
            { result: "R1.x", produced_by: "code/run.py" },
            { result: "R1.y", measured: "data/a.csv" },
            { result: "R1.y", measured: "data/a.csv" },
          ],
        },
      ],
      bundleInputs(files, INPUTS.verificationInputs),
    );
    expect(check).toEqual({
      valid: false,
      issues: [
        { path: "/1/evidence/1/result", message: "results/R1.json has no value at y" },
        { path: "/1/evidence/0/produced_by", message: "The bundle has no code/run.py" },
      ],
    });
  });

  it("reports graph problems against the whole file", () => {
    const check = checkClaims([{ ...theory, depends_on: ["T9"] }]);
    expect(check).toEqual({
      valid: false,
      issues: [{ path: "", message: expect.stringContaining('unknown local claim "T9"') }],
    });
  });
});

describe("claimsFileJsonSchema", () => {
  it("publishes the claim ID pattern and the claim limit", () => {
    const schema = JSON.stringify(claimsFileJsonSchema());
    expect(schema).toContain("^claim:[0-9a-f]{64}$");
    expect(schema).toContain('"maxItems":30');
  });
});
