import { describe, expect, it } from "vitest";
import type { Digest } from "../hash";
import { bundleInputs } from "../results";
import { code, shellQuote, shown } from "./format";
import { pair } from "./match";
import { compareComputation, proposeMatch, proposeReproduction, type MatchedResult } from "./verdicts";

const INPUTS = `sha256:${"0".repeat(64)}` as Digest;
const files = (entries: Record<string, string>) =>
  bundleInputs(new Map(Object.entries(entries).map(([path, text]) => [path, new TextEncoder().encode(text)])), INPUTS);

const declared = files({ "results/R1.json": '{"loss": -0.031, "label": "ok", "runs": [0.5, 0.75]}' });
const computation = (result: string, tolerance?: number) => ({ result, produced_by: "code/eval.py", ...(tolerance !== undefined && { tolerance }) });

describe("proposeReproduction", () => {
  it("proposes reproduced when every result agrees, saying what came out", () => {
    const produced = files({ "results/R1.json": '{"loss": -0.0305, "label": "ok"}' });
    const results = [compareComputation(computation("R1.loss", 0.002), declared, produced), compareComputation(computation("R1.label"), declared, produced)];
    expect(proposeReproduction(results)).toEqual({
      verdict: "reproduced",
      reason: 'Every result agrees: R1.loss came out -0.0305 (declared -0.031, tolerance 0.002); R1.label came out "ok" (declared "ok", exact).',
    });
  });

  it("proposes mismatch when any result disagrees, even when another is missing", () => {
    const produced = files({ "results/R1.json": '{"loss": -0.04}' });
    const results = [compareComputation(computation("R1.loss", 0.002), declared, produced), compareComputation(computation("R1.label"), declared, produced)];
    expect(proposeReproduction(results)).toEqual({
      verdict: "mismatch",
      reason: "R1.loss came out -0.04; the bundle declares -0.031 (tolerance 0.002).",
    });
  });

  it("proposes could_not_run when a result wasn't produced, saying why", () => {
    const cases: [Record<string, string>, string][] = [
      [{}, "R1.loss: the run didn't produce it (There is no results/R1.json)."],
      [{ "results/R1.json": '{"lost": 1}' }, "R1.loss: the run didn't produce it (results/R1.json has no value at loss)."],
      [{ "results/R1.json": "{nope" }, "R1.loss: the run didn't produce it (results/R1.json is not valid JSON: Not valid JSON"],
    ];
    for (const [written, reason] of cases) {
      const proposal = proposeReproduction([compareComputation(computation("R1.loss"), declared, files(written))]);
      expect(proposal.verdict).toBe("could_not_run");
      expect(proposal.reason.startsWith(reason)).toBe(true);
    }
  });

  it("proposes could_not_run whenever the run failed, whatever it left behind", () => {
    const produced = files({ "results/R1.json": '{"loss": -0.031}' });
    expect(proposeReproduction([compareComputation(computation("R1.loss"), declared, produced)], "The run exited with code 1.")).toEqual({
      verdict: "could_not_run",
      reason: "The run exited with code 1.",
    });
  });

  it("compares arrays and other values exactly, tolerance or not", () => {
    const produced = files({ "results/R1.json": '{"runs": [0.5, 0.76]}' });
    expect(proposeReproduction([compareComputation(computation("R1.runs", 0.1), declared, produced)]).verdict).toBe("mismatch");
  });
});

describe("proposeMatch", () => {
  const result = (agrees: boolean | null, extra: Partial<MatchedResult> = {}): MatchedResult => ({
    result: "R1.t",
    original: "claim:ab",
    original_result: "R2.t",
    tolerance: 0.5,
    replication: 151.6,
    original_value: 151.8,
    agrees,
    ...extra,
  });

  it("matches when every pair agrees, mismatches when any disagrees, and can't judge what's unclear", () => {
    expect(proposeMatch([result(true)]).verdict).toBe("matched");
    expect(proposeMatch([result(true), result(false, { replication: 140 })])).toEqual({
      verdict: "mismatched",
      reason: "R1.t is 140; the original's R2.t is 151.8 (tolerance 0.5).",
    });
    expect(proposeMatch([result(true)], ["Against claim:ab…: the pairing isn't clear."])).toEqual({
      verdict: "could_not_judge",
      reason: "Against claim:ab…: the pairing isn't clear.",
    });
    expect(proposeMatch([result(false)], ["Against another original: unclear."]).verdict).toBe("mismatched");
    expect(proposeMatch([]).verdict).toBe("could_not_judge");
  });
});

describe("pair", () => {
  it("pairs one result with one, or the same names with each other, and nothing else", () => {
    expect(pair(["R1.t"], ["R2.melting_point"])).toEqual([["R1.t", "R2.melting_point"]]);
    expect(pair(["R1.a", "R1.b"], ["R1.b", "R1.a"])).toEqual([
      ["R1.a", "R1.a"],
      ["R1.b", "R1.b"],
    ]);
    expect(pair(["R1.a", "R1.b"], ["R2.a", "R2.b"])).toMatch(/isn't clear/);
    expect(pair(["R1.a"], ["R2.a", "R2.b"])).toMatch(/isn't clear/);
    expect(pair([], ["R2.a"])).toBe("the replication claim names no results");
    expect(pair(["R1.a"], [])).toBe("the original claim names no results");
  });
});

describe("format", () => {
  it("shows text from a bundle as code, with anything hidden made visible and nothing that breaks out", () => {
    expect(code("R1.loss")).toBe("`R1.loss`");
    expect(code("a`b")).toBe("`` a`b ``");
    expect(code("a|b")).toBe("`a\\|b`");
    expect(code("R1.​loss")).toBe("`R1.<U+200B>loss`");
    expect(shown("x".repeat(100))).toHaveLength(60);
    expect(shown({ a: "‮" })).toBe('{"a":"<U+202E>"}');
  });

  it("quotes a path as one shell word", () => {
    expect(shellQuote("/jobs/job-1")).toBe("/jobs/job-1");
    expect(shellQuote("/my jobs/it's")).toBe("'/my jobs/it'\"'\"'s'");
  });
});
