import type { Computation } from "../claims";
import type { UnfinishedProof } from "../proofs";
import { resultAgrees, type BundleInputs } from "../results";
import { revealHidden } from "../scan";
import type { JobKind } from "../vocabulary";
import { shown } from "./format";
import { declaredValue } from "./job";
import type { CheckedTheorem } from "./proof-check";

/** One computation's result: what the bundle declares and what the run wrote. */
export interface ReproducedResult {
  result: string;
  produced_by: string;
  tolerance?: number;
  declared?: unknown;
  produced?: unknown;
  /** Null when the two couldn't be compared, and `problem` says why. */
  agrees: boolean | null;
  problem?: string;
}

/** One result of a replication claim, paired with the result of the claim it replicates. */
export interface MatchedResult {
  result: string;
  original: string;
  original_result: string;
  /** The original's tolerance: how far a new measurement may land and still agree. */
  tolerance?: number;
  replication?: unknown;
  original_value?: unknown;
  agrees: boolean | null;
  problem?: string;
}

export interface ClaimVerdict {
  local_id: string;
  claim_id: string;
  verdict: string;
  reason: string;
  /** Who chose the verdict: the harness proposed it, or the verifier set it. */
  by: "harness" | "verifier";
  results: ReproducedResult[] | MatchedResult[] | CheckedTheorem[];
  /** For a review, how significant the reviewer rates the claim. */
  significance?: string;
}

/**
 * What verdicts.json is about: a job's kind; an author's own check of its bundle; or, for a
 * challenge review, the harness re-running the challenged claim.
 */
export type VerdictsKind = JobKind | "self_check" | "challenge_rerun";

/** verdicts.json */
export interface VerdictsRecord {
  harness: string;
  kind: VerdictsKind;
  job?: string;
  bundle: string;
  compared_at: string;
  /** The run passed its time limit, so the work took more than its declared minutes. */
  over_budget: boolean;
  claims: ClaimVerdict[];
  /** For a replication match: the original claims and the declared results fetched for each. */
  originals?: { claim: string; bundle: string; folder: string; files: Record<string, string> }[];
  /** For a proof check, as information: where the proofs use the checker's unfinished-proof keywords. */
  unfinished?: (UnfinishedProof & { path: string })[];
  /** The result files the evidence carries, and any left out to stay under the evidence limit. */
  results_files?: { copied: string[]; omitted: { path: string; bytes?: number; digest?: string; reason: string }[] };
}

/** Compares what a run produced for one computation with what the bundle declares. */
export function compareComputation(computation: Computation, declared: BundleInputs, produced: BundleInputs): ReproducedResult {
  const base = {
    result: computation.result,
    produced_by: computation.produced_by,
    ...(computation.tolerance !== undefined && { tolerance: computation.tolerance }),
  };
  const expected = declaredValue(declared, computation.result);
  if ("problem" in expected) return { ...base, agrees: null, problem: `the bundle declares no value (${expected.problem})` };
  const got = declaredValue(produced, computation.result);
  if ("problem" in got) return { ...base, declared: expected.value, agrees: null, problem: `the run didn't produce it (${got.problem})` };
  return {
    ...base,
    declared: expected.value,
    produced: got.value,
    agrees: resultAgrees(got.value, expected.value, computation.tolerance),
  };
}

/**
 * A reproduction verdict: could_not_run when the run failed, mismatch when any result
 * disagrees, could_not_run when one wasn't produced, and reproduced when every one agrees.
 * A failed run's outputs may be partial, so they decide nothing.
 */
export function proposeReproduction(results: ReproducedResult[], failure?: string): { verdict: string; reason: string } {
  if (failure) return { verdict: "could_not_run", reason: failure };
  const disagree = results.filter((result) => result.agrees === false);
  if (disagree.length > 0) {
    return { verdict: "mismatch", reason: disagree.map((result) => disagreement(result.result, result.produced, result.declared, result.tolerance, "came out", "the bundle declares")).join(" ") };
  }
  const missing = results.filter((result) => result.agrees === null);
  if (missing.length > 0) {
    return { verdict: "could_not_run", reason: missing.map((result) => `${name(result.result)}: ${result.problem}.`).join(" ") };
  }
  if (results.length === 0) return { verdict: "could_not_run", reason: "The claim names no computation to compare." };
  return {
    verdict: "reproduced",
    reason: `Every result agrees: ${results.map((result) => `${name(result.result)} came out ${shown(result.produced)} (declared ${shown(result.declared)}, ${tolerance(result.tolerance)})`).join("; ")}.`,
  };
}

/**
 * A proof-check verdict: could_not_run when the run failed, failed when any theorem the claim
 * names failed, could_not_run when the checker never reported on one, and passed when every one
 * passed.
 */
export function proposeProofCheck(theorems: CheckedTheorem[], failure?: string): { verdict: string; reason: string } {
  if (failure) return { verdict: "could_not_run", reason: failure };
  const sentences = (list: CheckedTheorem[]) => list.map((theorem) => `${revealHidden(theorem.reason)}.`).join(" ");
  const failed = theorems.filter((theorem) => theorem.status === "failed");
  if (failed.length > 0) return { verdict: "failed", reason: sentences(failed) };
  const unknown = theorems.filter((theorem) => theorem.status === "unknown");
  if (unknown.length > 0) return { verdict: "could_not_run", reason: sentences(unknown) };
  if (theorems.length === 0) return { verdict: "could_not_run", reason: "The claim names no proof to check." };
  return { verdict: "passed", reason: sentences(theorems) };
}

/**
 * A replication-match verdict, by the same rule as a reproduction's: mismatched when any pair
 * of results disagrees, could_not_judge when a pairing is unclear (`unclear` says why) or a
 * value is missing, and matched when every pair agrees.
 */
export function proposeMatch(results: MatchedResult[], unclear: string[] = []): { verdict: string; reason: string } {
  const disagree = results.filter((result) => result.agrees === false);
  if (disagree.length > 0) {
    return { verdict: "mismatched", reason: disagree.map((result) => disagreement(result.result, result.replication, result.original_value, result.tolerance, "is", `the original's ${name(result.original_result)} is`)).join(" ") };
  }
  const missing = results.filter((result) => result.agrees === null);
  if (unclear.length > 0 || missing.length > 0) {
    return { verdict: "could_not_judge", reason: [...unclear, ...missing.map((result) => `${name(result.result)}: ${result.problem}.`)].join(" ") };
  }
  if (results.length === 0) return { verdict: "could_not_judge", reason: "There are no results to compare." };
  return {
    verdict: "matched",
    reason: `Every result agrees with the original's: ${results.map((result) => `${name(result.result)} is ${shown(result.replication)}, the original's ${name(result.original_result)} ${shown(result.original_value)} (${tolerance(result.tolerance)})`).join("; ")}.`,
  };
}

function disagreement(result: string, got: unknown, expected: unknown, within: number | undefined, verb: string, expectedVerb: string): string {
  return `${name(result)} ${verb} ${shown(got)}; ${expectedVerb} ${shown(expected)} (${tolerance(within)}).`;
}

function tolerance(value: number | undefined): string {
  return value === undefined ? "exact" : `tolerance ${value}`;
}

/** A result name from the bundle, with anything hidden in it made visible. */
function name(result: string): string {
  return revealHidden(result);
}
