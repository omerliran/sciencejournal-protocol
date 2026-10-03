import { join } from "node:path";
import { BundleLayoutError, digestEvidence } from "../bundle";
import { ATTESTATION_JOBS, HAZARD_CATEGORIES, HAZARD_VERDICTS, type AttestationJob } from "../vocabulary";
import { NodeClient, signAs, signIn, type Credentials } from "./client";
import { HarnessError, type Deps } from "./context";
import { writeReport, type RunRecord } from "./evidence";
import { listOutputs, readFiles, readJsonFile, writeJsonFile } from "./files";
import { size } from "./format";
import { loadJob, type JobRecord, type ScanRecord } from "./job";
import type { ClaimVerdict, VerdictsRecord } from "./verdicts";
import { HARNESS } from "./version";

/** What the reference node takes in evidence, when it doesn't say. */
const EVIDENCE_LIMITS = { bytes: 10 * 1024 * 1024, files: 1000 };

export interface AttestOptions extends Credentials {
  node?: string;
  hazard?: string;
  modelFamily?: string;
  /** Verdicts the verifier sets, as "<claim>=<verdict>", by local ID or claim ID. */
  verdicts?: string[];
  /** Why, as "<claim>=<reason>". */
  reasons?: string[];
  overBudget?: boolean;
}

/**
 * Signs and sends an attestation for a reproduction or replication-match job: the verdicts in
 * verdicts.json, with any the verifier sets instead, the evidence folder's digest, and the
 * verifier's own hazard screen. It refuses when a verdict has no reason or the hazard screen is
 * missing: the harness proposes, the verifier decides.
 */
export async function attest(jobDir: string, options: AttestOptions, deps: Deps): Promise<number> {
  const record = await loadJob(jobDir);
  if (record.kind !== "reproduction" && record.kind !== "replication_match") {
    throw new HarnessError(`A ${record.kind} job takes a hazard verdict, not an attestation: use the hazard command.`);
  }
  if (record.claim_ids !== "match") {
    throw new HarnessError(
      `The harness won't attest to this job: ${record.claim_ids}. If the harness is older than the node, get the current one; otherwise report it.`,
    );
  }
  const job: AttestationJob = record.kind;
  if (job === "reproduction") {
    if (!options.hazard) {
      throw new HarnessError(
        `Give your hazard screen of the work with --hazard: none, or the closest of ${HAZARD_CATEGORIES.join(", ")}. The harness never decides it for you.`,
      );
    }
    if (!(HAZARD_VERDICTS as readonly string[]).includes(options.hazard)) {
      throw new HarnessError(`--hazard is one of ${HAZARD_VERDICTS.join(", ")}, not ${options.hazard}`);
    }
  } else if (options.hazard) {
    throw new HarnessError("A replication_match attestation carries no hazard screen: the work was screened when it opened. Leave out --hazard.");
  }
  if (!options.modelFamily) {
    throw new HarnessError("Say which model family did this work with --model-family: one you declared when you registered.");
  }

  const path = join(jobDir, "verdicts.json");
  const stored = await readJsonFile<VerdictsRecord>(path).catch(() => null);
  const claims = decide(record, stored, options);
  const overBudget = job === "reproduction" && (options.overBudget === true || stored?.over_budget === true);
  const client = new NodeClient(options.node ?? record.node, deps);
  const operator = await signIn({ ...options, operator: options.operator ?? deps.env.SJ_OPERATOR ?? record.operator }, client, deps);
  if (!operator.modelFamilies.includes(options.modelFamily)) {
    throw new HarnessError(`${options.modelFamily} isn't a model family ${operator.id} declared; it declared ${operator.modelFamilies.join(", ")}`);
  }

  // The verdicts as sent go back into verdicts.json and the report, so the evidence says them.
  const final: VerdictsRecord = {
    ...(stored ?? { harness: HARNESS, kind: job, job: record.job, bundle: record.bundle, compared_at: deps.now().toISOString() }),
    over_budget: overBudget,
    claims,
  };
  await writeJsonFile(path, final);
  const run = await readJsonFile<RunRecord>(join(jobDir, "run.json")).catch(() => null);
  const scan = await readJsonFile<ScanRecord>(join(jobDir, "scan.json")).catch(() => null);
  await writeReport(jobDir, job === "reproduction" ? run : null, final, scan);

  const evidence = await readEvidence(jobDir, client);

  const entry = signAs(operator, {
    type: "attestation" as const,
    job,
    verifier: operator.id,
    bundle: record.bundle,
    claims: Object.fromEntries(claims.map((claim) => [claim.claim_id, claim.verdict])),
    evidence: evidence.digest,
    model_family: options.modelFamily,
    harness: HARNESS,
    ...(job === "reproduction" && { hazard: options.hazard }),
    ...(overBudget && { over_budget: true as const }),
  });
  const files = Object.fromEntries([...evidence.files].map(([file, bytes]) => [file, Buffer.from(bytes).toString("base64")]));
  const response = await client.post<{ attestation: number }>("/api/v1/attestations", { entry, evidence: { files } });
  await writeJsonFile(join(jobDir, "attestation.json"), { sent_at: deps.now().toISOString(), entry, response });

  for (const claim of claims) deps.print(`  ${claim.local_id}: ${claim.verdict}`);
  if (overBudget) deps.print(options.overBudget ? "Reported over budget." : "Reported over budget, since the run passed its time limit.");
  deps.print(
    `Attested: the log holds it at entry ${response.attestation}. For work still sealed, that entry is a commitment the log opens when the round closes.`,
  );
  return 0;
}

/** The verdict on each claim the job asks about: the stored proposals, with the verifier's changes. */
function decide(record: JobRecord, stored: VerdictsRecord | null, options: AttestOptions): ClaimVerdict[] {
  const asked = record.claims.filter((claim) => claim.needs_verdict);
  const allowed: readonly string[] = ATTESTATION_JOBS[record.kind as AttestationJob];
  const claimFor = (reference: string, flag: string) => {
    const claim = asked.find((c) => c.local_id === reference || c.claim_id === reference);
    if (!claim) {
      throw new HarnessError(`${flag} names ${reference}, which isn't a claim this job asks about: ${asked.map((c) => c.local_id).join(", ")}`);
    }
    return claim.claim_id;
  };
  const verdicts = pairs(options.verdicts ?? [], "--verdict", claimFor);
  const reasons = pairs(options.reasons ?? [], "--reason", claimFor);
  for (const verdict of verdicts.values()) {
    if (!allowed.includes(verdict)) throw new HarnessError(`A ${record.kind} verdict is one of ${allowed.join(", ")}, not ${verdict}`);
  }

  return asked.map((claim) => {
    const proposed = stored?.claims.find((c) => c.claim_id === claim.claim_id);
    const verdict = verdicts.get(claim.claim_id);
    const reason = reasons.get(claim.claim_id)?.trim();
    if (verdict !== undefined && verdict !== proposed?.verdict && !reason) {
      throw new HarnessError(`Say why ${claim.local_id} is ${verdict}, with --reason ${claim.local_id}="<why>"; the evidence keeps it.`);
    }
    if (!proposed && verdict === undefined) {
      const command = record.kind === "reproduction" ? "run" : "match";
      throw new HarnessError(
        `${claim.local_id} has no verdict yet. Use the ${command} command, or give one with --verdict ${claim.local_id}=<verdict> --reason ${claim.local_id}="<why>".`,
      );
    }
    const chosen = verdict ?? proposed!.verdict;
    const why = reason ?? proposed?.reason?.trim();
    if (!why) throw new HarnessError(`${claim.local_id}'s verdict has no reason; give one with --reason ${claim.local_id}="<why>".`);
    if (!allowed.includes(chosen)) throw new HarnessError(`${claim.local_id}'s verdict, ${chosen}, isn't a ${record.kind} verdict`);
    const changed = verdict !== undefined || reason !== undefined;
    return {
      local_id: claim.local_id,
      claim_id: claim.claim_id,
      verdict: chosen,
      reason: why,
      by: changed ? "verifier" : (proposed?.by ?? "verifier"),
      results: proposed?.results ?? [],
    };
  });
}

/** "<claim>=<value>" pairs, keyed by claim ID. */
function pairs(given: string[], flag: string, claimFor: (reference: string, flag: string) => string): Map<string, string> {
  const found = new Map<string, string>();
  for (const pair of given) {
    const cut = pair.indexOf("=");
    if (cut <= 0) throw new HarnessError(`${flag} takes <claim>=<value>, such as C1=reproduced; got ${pair}`);
    found.set(claimFor(pair.slice(0, cut), flag), pair.slice(cut + 1));
  }
  return found;
}

/** Every file in evidence/, checked against the node's limits and the path rules, and its digest. */
async function readEvidence(jobDir: string, client: NodeClient) {
  const directory = join(jobDir, "evidence");
  const listed = await listOutputs(directory);
  if (listed.others.length > 0) {
    throw new HarnessError(`evidence/ holds things that aren't regular files, which evidence can't carry: ${listed.others.join(", ")}`);
  }
  const files = await readFiles(directory, listed.files);
  const limits = await client
    .get<{ limits?: { max_evidence_bytes?: number; max_evidence_files?: number } }>("/api/v1/vocabulary")
    .then(({ limits }) => ({ bytes: limits?.max_evidence_bytes ?? EVIDENCE_LIMITS.bytes, files: limits?.max_evidence_files ?? EVIDENCE_LIMITS.files }))
    .catch(() => EVIDENCE_LIMITS);
  const total = [...files.values()].reduce((sum, bytes) => sum + bytes.length, 0);
  if (total > limits.bytes || files.size > limits.files) {
    const largest = [...files].sort(([, a], [, b]) => b.length - a.length).slice(0, 3);
    throw new HarnessError(
      `evidence/ holds ${files.size} files and ${size(total)}; the node takes at most ${limits.files} files and ${size(limits.bytes)}. The largest: ${largest.map(([file, bytes]) => `${file} (${size(bytes.length)})`).join(", ")}.`,
    );
  }
  try {
    return { files, digest: digestEvidence(files).evidence };
  } catch (error) {
    if (error instanceof BundleLayoutError) throw new HarnessError(`An evidence file's name breaks the path rules: ${error.message}`);
    throw error;
  }
}

export interface HazardOptions extends Credentials {
  node?: string;
  verdict?: string;
}

/** Signs and sends the verifier's hazard verdict for a screen or a hazard review. */
export async function hazard(jobDir: string, options: HazardOptions, deps: Deps): Promise<number> {
  const record = await loadJob(jobDir);
  if (record.kind !== "screen" && record.kind !== "hazard_review") {
    const how = record.kind === "reproduction" ? "as --hazard when you attest" : "nowhere: a replication match has no hazard screen";
    throw new HarnessError(`A ${record.kind} job takes its hazard verdict ${how}.`);
  }
  if (!options.verdict || !(HAZARD_VERDICTS as readonly string[]).includes(options.verdict)) {
    throw new HarnessError(`Give your verdict with --verdict: none, or the closest of ${HAZARD_CATEGORIES.join(", ")}.`);
  }
  const client = new NodeClient(options.node ?? record.node, deps);
  const operator = await signIn({ ...options, operator: options.operator ?? deps.env.SJ_OPERATOR ?? record.operator }, client, deps);
  const entry = signAs(operator, { type: "hazard_review" as const, reviewer: operator.id, bundle: record.bundle, verdict: options.verdict });
  const response = await client.post<{ review: number }>("/api/v1/hazard-reviews", entry);
  await writeJsonFile(join(jobDir, "hazard-review.json"), { sent_at: deps.now().toISOString(), entry, response });
  deps.print(`Sent your verdict, ${options.verdict}: the log holds it sealed at entry ${response.review} until the round closes or the panel decides.`);
  return 0;
}
