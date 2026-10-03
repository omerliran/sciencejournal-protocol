import { join } from "node:path";
import { z } from "zod";
import { EvidenceSchema, resultsNamed, type Evidence } from "../claims";
import type { Digest } from "../hash";
import { bundleInputs, resultAgrees, resultLocation, type BundleInputs } from "../results";
import { NodeClient } from "./client";
import { HarnessError, type Deps } from "./context";
import { writeReport } from "./evidence";
import { readFiles, readJsonFile, removeTree, writeJsonFile, writeUnder } from "./files";
import { declaredValue, loadJob, parseClaims, type ScanRecord } from "./job";
import { proposeMatch, type ClaimVerdict, type MatchedResult, type VerdictsRecord } from "./verdicts";
import { HARNESS } from "./version";

/** A claim on the ledger that a replication claim replicates, and its declared results. */
type Original =
  | { claim: string; bundle: string; evidence: Evidence[]; inputs: BundleInputs; files: Record<string, string> }
  | { claim: string; bundle: string; problem: string };

// Only results are read from these files, which no verification inputs digest is needed for.
const RESULTS_ONLY = `sha256:${"0".repeat(64)}` as Digest;

/**
 * For a replication_match job: fetches each original claim and its bundle's declared results
 * through the public API, pairs them with the results each replication claim names, and
 * proposes matched or mismatched where the pairing is unambiguous (each side names one result,
 * or both name the same ones) and could_not_judge, saying why, where it isn't. The original's
 * tolerance decides, since it says how far a new measurement may land and still agree.
 */
export async function matchJob(jobDir: string, options: { node?: string }, deps: Deps): Promise<number> {
  const record = await loadJob(jobDir);
  if (record.kind !== "replication_match") throw new HarnessError(`This is a ${record.kind} job; match is for replication_match jobs.`);
  const client = new NodeClient(options.node ?? record.node, deps);
  const bundleDir = join(jobDir, "bundle");
  const claims = parseClaims((await readFiles(bundleDir, ["claims.json"])).get("claims.json"));
  if (!claims) throw new HarnessError("The job's claims.json doesn't parse as claims, so there is nothing to match.");
  const replicationClaims = new Map(claims.map((claim) => [claim.local_id, claim]));
  const ownPaths = [...new Set(claims.flatMap((claim) => resultsNamed(claim).flatMap((name) => resultLocation(name)?.path ?? [])))];
  const own = bundleInputs(await readFiles(bundleDir, ownPaths.filter((path) => path in record.files)), record.verification_inputs);

  // Files are content-addressed, so each is fetched once and read for both the comparison and the evidence.
  const cache = new Map<string, Uint8Array>();
  const originals = new Map<string, Original>();
  for (const link of record.replicates ?? []) {
    if (!originals.has(link.original)) originals.set(link.original, await fetchOriginal(client, link.original, link.original_bundle, cache));
  }

  const verdicts: ClaimVerdict[] = record.claims
    .filter((claim) => claim.needs_verdict)
    .map((claim) => {
      const replication = replicationClaims.get(claim.local_id);
      const results: MatchedResult[] = [];
      const unclear: string[] = [];
      for (const link of (record.replicates ?? []).filter((l) => l.claim_id === claim.claim_id)) {
        const original = originals.get(link.original)!;
        if ("problem" in original) {
          unclear.push(`Against ${short(link.original)}: ${original.problem}.`);
          continue;
        }
        const pairing = pair(replication ? resultsNamed(replication) : [], resultsNamed({ evidence: original.evidence }));
        if (typeof pairing === "string") {
          unclear.push(`Against ${short(link.original)}: ${pairing}.`);
          continue;
        }
        for (const [mine, theirs] of pairing) {
          const tolerance = loosest(original.evidence, theirs);
          const base = { result: mine, original: link.original, original_result: theirs, ...(tolerance !== undefined && { tolerance }) };
          const ours = declaredValue(own, mine);
          const its = declaredValue(original.inputs, theirs);
          if ("problem" in ours) results.push({ ...base, agrees: null, problem: `the replication declares no value (${ours.problem})` });
          else if ("problem" in its) results.push({ ...base, replication: ours.value, agrees: null, problem: `the original declares no value (${its.problem})` });
          else results.push({ ...base, replication: ours.value, original_value: its.value, agrees: resultAgrees(ours.value, its.value, tolerance) });
        }
      }
      return { local_id: claim.local_id, claim_id: claim.claim_id, ...proposeMatch(results, unclear), by: "harness" as const, results };
    });

  // The original results compared go into the evidence, so anyone can see what was matched.
  await removeTree(join(jobDir, "evidence", "originals"));
  const fetched: NonNullable<VerdictsRecord["originals"]> = [];
  for (const original of originals.values()) {
    if ("problem" in original) continue;
    const folder = `originals/${original.bundle.slice("sha256:".length, "sha256:".length + 16)}`;
    const files = await readOriginalFiles(client, original.files, cache);
    for (const [path, bytes] of files) await writeUnder(join(jobDir, "evidence"), `${folder}/${path}`, bytes);
    fetched.push({ claim: original.claim, bundle: original.bundle, folder, files: original.files });
  }
  const matched: VerdictsRecord = {
    harness: HARNESS,
    kind: "replication_match",
    job: record.job,
    bundle: record.bundle,
    compared_at: deps.now().toISOString(),
    over_budget: false,
    claims: verdicts,
    originals: fetched,
  };
  await writeJsonFile(join(jobDir, "verdicts.json"), matched);
  const scan = await readJsonFile<ScanRecord>(join(jobDir, "scan.json")).catch(() => null);
  await writeReport(jobDir, null, matched, scan);

  deps.print("Proposed verdicts (verdicts.json):");
  for (const claim of verdicts) deps.print(`  ${claim.local_id}: ${claim.verdict}. ${claim.reason}`);
  deps.print(`Evidence: ${join(jobDir, "evidence")}`);
  return 0;
}

async function fetchOriginal(client: NodeClient, claim: string, bundle: string, cache: Map<string, Uint8Array>): Promise<Original> {
  try {
    const found = await client.get<{ claim: { evidence?: unknown } }>(`/api/v1/claims/${encodeURIComponent(claim)}`);
    const evidence = z.array(EvidenceSchema).safeParse(found.claim.evidence);
    if (!evidence.success) return { claim, bundle, problem: "the node's copy of the original claim has no evidence the harness can read" };
    const published = await client.get<{ files: Record<string, string>; withdrawn_entry: number | null }>(
      `/api/v1/bundles/${encodeURIComponent(bundle)}`,
    );
    if (published.withdrawn_entry !== null) {
      return { claim, bundle, problem: `the original's bundle was withdrawn at entry ${published.withdrawn_entry}` };
    }
    const paths = [...new Set(resultsNamed({ evidence: evidence.data }).flatMap((name) => resultLocation(name)?.path ?? []))];
    const files = Object.fromEntries(paths.filter((path) => published.files[path]).map((path) => [path, published.files[path]]));
    const inputs = bundleInputs(await readOriginalFiles(client, files, cache), RESULTS_ONLY);
    return { claim, bundle, evidence: evidence.data, inputs, files };
  } catch (error) {
    if (error instanceof HarnessError) return { claim, bundle, problem: `the harness couldn't read the original (${error.message})` };
    throw error;
  }
}

async function readOriginalFiles(
  client: NodeClient,
  files: Record<string, string>,
  cache: Map<string, Uint8Array>,
): Promise<Map<string, Uint8Array>> {
  const read = new Map<string, Uint8Array>();
  for (const [path, digest] of Object.entries(files)) {
    if (!cache.has(digest)) cache.set(digest, await client.file(digest));
    read.set(path, cache.get(digest)!);
  }
  return read;
}

/**
 * Which result of the replication to compare with which of the original's: unambiguous when
 * each names one, or when both name the same results. Otherwise, why not.
 */
export function pair(replication: string[], original: string[]): [string, string][] | string {
  if (replication.length === 0) return "the replication claim names no results";
  if (original.length === 0) return "the original claim names no results";
  if (replication.length === 1 && original.length === 1) return [[replication[0], original[0]]];
  if (replication.length === original.length && replication.every((name) => original.includes(name))) {
    return replication.map((name) => [name, name]);
  }
  return `the replication names ${replication.join(", ")} and the original names ${original.join(", ")}, so which to compare with which isn't clear; compare them yourself`;
}

/** The loosest tolerance the original's evidence gives a result; undefined when it must match exactly. */
function loosest(evidence: Evidence[], result: string): number | undefined {
  const tolerances = evidence.flatMap((item) => ("result" in item && item.result === result && item.tolerance !== undefined ? [item.tolerance] : []));
  return tolerances.length > 0 ? Math.max(...tolerances) : undefined;
}

function short(claim: string): string {
  return `${claim.slice(0, "claim:".length + 12)}…`;
}
