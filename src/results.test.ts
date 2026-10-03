import { describe, expect, it } from "vitest";
import type { Digest } from "./hash";
import { bundleInputs, declaredInputs, ResultError, resultLocation } from "./results";

const INPUTS: Digest = `sha256:${"1".repeat(64)}`;
const encoder = new TextEncoder();
const files = (entries: Record<string, string>) =>
  new Map(Object.entries(entries).map(([path, text]) => [path, encoder.encode(text)]));

describe("resultLocation", () => {
  it("finds a declared result by file and key", () => {
    expect(resultLocation("R3.loss_delta")).toEqual({ path: "results/R3.json", keys: ["loss_delta"] });
    expect(resultLocation("R1.runs.2.score")).toEqual({ path: "results/R1.json", keys: ["runs", "2", "score"] });
  });

  it.each(["R3", "R3..x", ".x", "R3.", "sub/R3.x"])("rejects %j", (reference) => {
    expect(resultLocation(reference)).toBeNull();
  });
});

describe("bundleInputs", () => {
  const inputs = bundleInputs(
    files({
      "results/R1.json": '{"loss_delta": -0.031, "runs": [{"score": 0.5}, {"score": 0.75}], "label": "ok", "n": null}',
      "results/bad.json": '{"a": 1, "a": 2}',
      "code/run.py": "print(1)",
    }),
    INPUTS,
  );

  it("reads values at any depth, including array elements and non-numbers", () => {
    expect(inputs.result("R1.loss_delta")).toBe(-0.031);
    expect(inputs.result("R1.runs.1.score")).toBe(0.75);
    expect(inputs.result("R1.runs")).toEqual([{ score: 0.5 }, { score: 0.75 }]);
    expect(inputs.result("R1.label")).toBe("ok");
    expect(inputs.result("R1.n")).toBeNull();
  });

  it.each([
    ["a missing file", "R9.x", "There is no results/R9.json"],
    ["a missing key", "R1.accuracy", "has no value at accuracy"],
    ["an index past the end", "R1.runs.2.score", "has no value"],
    ["an index with a leading zero", "R1.runs.01.score", "has no value"],
    ["a key inside a number", "R1.loss_delta.x", "has no value"],
    ["a file that isn't strict JSON", "bad.a", "not valid JSON"],
    ["a malformed name", "R1", "not a result name"],
  ])("throws ResultError for %s", (_, reference, message) => {
    expect(() => inputs.result(reference)).toThrow(ResultError);
    expect(() => inputs.result(reference)).toThrow(message);
  });

  it("tells which files the bundle has", () => {
    expect(inputs.has?.("code/run.py")).toBe(true);
    expect(inputs.has?.("code/missing.py")).toBe(false);
  });
});

describe("declaredInputs", () => {
  it("serves only the results it was given", () => {
    const inputs = declaredInputs(INPUTS, { "R1.x": 2 });
    expect(inputs.result("R1.x")).toBe(2);
    expect(() => inputs.result("R1.y")).toThrow(ResultError);
    expect(() => inputs.result("toString")).toThrow(ResultError);
    expect(inputs.has).toBeUndefined();
  });
});
