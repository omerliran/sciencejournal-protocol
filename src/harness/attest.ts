import { join } from "node:path";
import { BundleLayoutError, digestEvidence } from "../bundle";
import { isClaimId } from "../claims";
import {
  ATTESTATION_JOBS,
  CHALLENGE_VERDICTS,
  CITATION_VERDICTS,
  DUPLICATE_VERDICTS,
  HAZARD_CATEGORIES,
  HAZARD_VERDICTS,
  REVIEW_JOBS,
  SIGNIFICANCE_RATINGS,
  type AttestationJob,
  type CitationVerdict,
  type DuplicateVerdict,
} from "../vocabulary";
import { NodeClient, signAs, signIn, type Credentials } from "./client";
import { HarnessError, type Deps } from "./context";
import { writeReport, type RunRecord } from "./evidence";
import { listOutputs, readFiles, readJsonFile, readOutput, writeJsonFile } from "./files";
import { plural, shellQuote, size } from "./format";
import { answeredWith, loadJob, type JobRecord, type ScanRecord } from "./job";
import type { ClaimVerdict, VerdictsRecord } from "./verdicts";
import { HARNESS } from "./version";

/** What the reference node takes in evidence, when it doesn't say. */
const EVIDENCE_LIMITS = { bytes: 10 * 1024 * 1024, files: 1000 };

const REVIEWS: readonly string[] = REVIEW_JOBS;

export interface AttestOptions extends Credentials {
  node?: string;
  hazard?: string;
  modelFamily?: string;
  /** Verdicts the verifier sets, as "<claim>=<verdict>", by local ID or claim ID. */
  verdicts?: string[];
  /** Why, as "<claim>=<reason>". */
  reasons?: string[];
  /** For a review, how significant each claim is, as "<claim>=<rating>". */
  significance?: string[];
  overBudget?: boolean;
  /** For a review: something in the work told the reviewer who published it. */
  knewPublisher?: boolean;
}

/**
 * Signs and sends an attestation: for a reproduction, a proof check, or a replication match,
 * the verdicts in verdicts.json with any the verifier sets instead; for a review, the verdicts
 * and significance ratings the verifier gives, since the harness proposes none. The evidence is the evidence folder, and
 * a reproduction carries the verifier's own hazard screen. It refuses when a verdict has no
 * reason, the hazard screen is missing, or a review has no report: the harness proposes, the
 * verifier decides.
 */
export async function attest(jobDir: string, options: AttestOptions, deps: Deps): Promise<number> {
  const record = await loadJob(jobDir);
  answeredWith(record, "attest");
  if (record.claim_ids !== "match") {
    throw new HarnessError(
      `The harness won't attest to this job: ${record.claim_ids}. If the harness is older than the node, get the current one; otherwise report it.`,
    );
  }
  const job = record.kind as AttestationJob;
  const reviewing = REVIEWS.includes(job);
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
    throw new HarnessError(`A ${job} attestation carries no hazard screen: the work was screened before it opened. Leave out --hazard.`);
  }
  if (!options.modelFamily) {
    throw new HarnessError("Say which model family did this work with --model-family: one you declared when you registered.");
  }
  if (reviewing) await requireReport(jobDir, "review");
  else if (options.significance?.length) {
    throw new HarnessError(`Only a review rates significance; leave out --significance for a ${job}.`);
  } else if (options.knewPublisher) {
    throw new HarnessError(`Only a review says whether it knew whose work it judged; leave out --knew-publisher for a ${job}.`);
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

  // The verdicts as sent go into verdicts.json and the evidence, so the evidence says them: into
  // the harness's report, or beside a reviewer's own report, which the harness never touches.
  const final: VerdictsRecord = {
    ...(stored ?? { harness: HARNESS, kind: job, job: record.job, bundle: record.bundle, compared_at: deps.now().toISOString() }),
    over_budget: overBudget,
    claims,
  };
  await writeJsonFile(path, final);
  const evidenceDir = join(jobDir, "evidence");
  if (reviewing) {
    await writeJsonFile(join(evidenceDir, "verdicts.json"), {
      harness: HARNESS,
      job: record.job,
      kind: job,
      bundle: record.bundle,
      claims: claims.map(({ local_id, claim_id, verdict, reason, significance }) => ({ local_id, claim_id, verdict, significance, reason })),
    });
  } else {
    const run = await readJsonFile<RunRecord>(join(jobDir, "run.json")).catch(() => null);
    const scan = await readJsonFile<ScanRecord>(join(jobDir, "scan.json")).catch(() => null);
    await writeReport({ outDir: jobDir, evidenceDir }, job === "reproduction" || job === "proof_check" ? run : null, final, scan);
  }

  const evidence = await readEvidence(jobDir, client);
  const entry = signAs(operator, {
    type: "attestation" as const,
    job,
    verifier: operator.id,
    bundle: record.bundle,
    claims: Object.fromEntries(claims.map((claim) => [claim.claim_id, claim.verdict])),
    ...(reviewing && { significance: Object.fromEntries(claims.map((claim) => [claim.claim_id, claim.significance!])) }),
    evidence: evidence.digest,
    model_family: options.modelFamily,
    harness: HARNESS,
    ...(job === "reproduction" && { hazard: options.hazard }),
    ...(overBudget && { over_budget: true as const }),
    ...(reviewing && options.knewPublisher && { knew_publisher: true as const }),
  });
  const files = Object.fromEntries([...evidence.files].map(([file, bytes]) => [file, Buffer.from(bytes).toString("base64")]));
  const response = await client.post<{ attestation: number }>("/api/v1/attestations", { entry, evidence: { files } });
  await writeJsonFile(join(jobDir, "attestation.json"), { sent_at: deps.now().toISOString(), entry, response });

  for (const claim of claims) {
    deps.print(`  ${claim.local_id}: ${claim.verdict}${claim.significance ? `, significance ${claim.significance}` : ""}`);
  }
  if (overBudget) deps.print(options.overBudget ? "Reported over budget." : "Reported over budget, since the run passed its time limit.");
  if (reviewing && options.knewPublisher) deps.print("Said the work told you whose it was, so this review isn't marked blind.");
  const sealed =
    job === "reproduction"
      ? " For work still sealed, that entry is a commitment the log opens when the round closes."
      : reviewing
        ? " Reviews stay sealed until a bundle's three are in, so that entry is a commitment the log opens then."
        : "";
  deps.print(`Attested: the log holds it at entry ${response.attestation}.${sealed}`);
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
  const ratings = pairs(options.significance ?? [], "--significance", claimFor);
  for (const verdict of verdicts.values()) {
    if (!allowed.includes(verdict)) throw new HarnessError(`A ${record.kind} verdict is one of ${allowed.join(", ")}, not ${verdict}`);
  }
  for (const rating of ratings.values()) {
    if (!(SIGNIFICANCE_RATINGS as readonly string[]).includes(rating)) {
      throw new HarnessError(`--significance is one of ${SIGNIFICANCE_RATINGS.join(", ")}, not ${rating}`);
    }
  }
  // A review has nothing proposed: the reviewer gives every verdict, with its reason, and rates
  // every claim's significance.
  const reviewing = REVIEWS.includes(record.kind);
  const unjudged = asked.filter((claim) => !verdicts.has(claim.claim_id) && !stored?.claims.some((c) => c.claim_id === claim.claim_id));
  if (reviewing && unjudged.length > 0) {
    throw new HarnessError(
      `A review's verdicts are yours to give: add ${unjudged.map((c) => `--verdict ${c.local_id}=<verdict> --reason ${c.local_id}="<why>"`).join(" ")}, with a verdict from ${allowed.join(", ")}.`,
    );
  }
  const unrated = asked.filter((claim) => !ratings.has(claim.claim_id) && !stored?.claims.find((c) => c.claim_id === claim.claim_id)?.significance);
  if (reviewing && unrated.length > 0) {
    throw new HarnessError(
      `Rate how much each claim adds to what was known: add ${unrated.map((c) => `--significance ${c.local_id}=<rating>`).join(" ")}, with a rating from ${SIGNIFICANCE_RATINGS.join(", ")}.`,
    );
  }

  return asked.map((claim) => {
    const proposed = stored?.claims.find((c) => c.claim_id === claim.claim_id);
    const verdict = verdicts.get(claim.claim_id);
    const reason = reasons.get(claim.claim_id)?.trim();
    if (verdict !== undefined && verdict !== proposed?.verdict && !reason) {
      throw new HarnessError(`Say why ${claim.local_id} is ${verdict}, with --reason ${claim.local_id}="<why>"; the evidence keeps it.`);
    }
    if (!proposed && verdict === undefined) {
      const command = record.kind === "replication_match" ? "match" : "run";
      throw new HarnessError(
        `${claim.local_id} has no verdict yet. Use the ${command} command, or give one with --verdict ${claim.local_id}=<verdict> --reason ${claim.local_id}="<why>".`,
      );
    }
    const chosen = verdict ?? proposed!.verdict;
    const why = reason ?? proposed?.reason?.trim();
    if (!why) throw new HarnessError(`${claim.local_id}'s verdict has no reason; give one with --reason ${claim.local_id}="<why>".`);
    if (!allowed.includes(chosen)) throw new HarnessError(`${claim.local_id}'s verdict, ${chosen}, isn't a ${record.kind} verdict`);
    const changed = verdict !== undefined || reason !== undefined;
    const significance = ratings.get(claim.claim_id) ?? proposed?.significance;
    return {
      local_id: claim.local_id,
      claim_id: claim.claim_id,
      verdict: chosen,
      reason: why,
      by: changed ? "verifier" : (proposed?.by ?? "verifier"),
      results: proposed?.results ?? [],
      ...(reviewing && { significance }),
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

/**
 * The report a judgment rests on, which the verifier writes: evidence/report.md, a regular file
 * that says something. The harness writes no report for a judgment, so one there is the
 * verifier's.
 */
async function requireReport(jobDir: string, what: string): Promise<void> {
  let text = "";
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(await readOutput(join(jobDir, "evidence"), "report.md", EVIDENCE_LIMITS.bytes));
  } catch {
    // Missing, not a regular file, not UTF-8, or too large: all mean there is no report to send.
  }
  if (text.trim() === "") {
    throw new HarnessError(`Write your ${what} in ${join(jobDir, "evidence", "report.md")} first: it is your evidence, and the harness won't send a ${what} without it.`);
  }
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
  if (record.kind === "reproduction") throw new HarnessError("A reproduction job takes its hazard verdict as --hazard when you attest.");
  answeredWith(record, "hazard");
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

export interface ChallengeReviewOptions extends Credentials {
  node?: string;
  verdict?: string;
  modelFamily?: string;
}

/**
 * Signs and sends a panelist's verdict on a challenge, with the evidence folder, which holds the
 * panelist's report and anything the harness re-ran for it. The verdict is the panelist's: the
 * harness proposes none.
 */
export async function challengeReview(jobDir: string, options: ChallengeReviewOptions, deps: Deps): Promise<number> {
  const record = await loadJob(jobDir);
  answeredWith(record, "challenge-review");
  if (!record.challenge) throw new HarnessError("job.json holds no challenge: take the job again with this harness.");
  if (!options.verdict || !(CHALLENGE_VERDICTS as readonly string[]).includes(options.verdict)) {
    throw new HarnessError(`Give your verdict on the challenge with --verdict: ${CHALLENGE_VERDICTS.join(", ")}.`);
  }
  if (!options.modelFamily) {
    throw new HarnessError("Say which model family did this work with --model-family: one you declared and neither party to the challenge did.");
  }
  await requireReport(jobDir, "review of the challenge");
  const client = new NodeClient(options.node ?? record.node, deps);
  const operator = await signIn({ ...options, operator: options.operator ?? deps.env.SJ_OPERATOR ?? record.operator }, client, deps);
  if (!operator.modelFamilies.includes(options.modelFamily)) {
    throw new HarnessError(`${options.modelFamily} isn't a model family ${operator.id} declared; it declared ${operator.modelFamilies.join(", ")}`);
  }
  const evidence = await readEvidence(jobDir, client);
  const entry = signAs(operator, {
    type: "challenge_review" as const,
    reviewer: operator.id,
    challenge: record.challenge.index,
    bundle: record.bundle,
    verdict: options.verdict,
    evidence: evidence.digest,
    model_family: options.modelFamily,
  });
  const files = Object.fromEntries([...evidence.files].map(([file, bytes]) => [file, Buffer.from(bytes).toString("base64")]));
  const response = await client.post<{ review: number; challenge: string }>("/api/v1/challenge-reviews", { entry, evidence: { files } });
  await writeJsonFile(join(jobDir, "challenge-review.json"), { sent_at: deps.now().toISOString(), entry, response });
  deps.print(
    `Sent your review, ${options.verdict}: the log holds it sealed at entry ${response.review} until two reviews agree. The challenge is ${response.challenge}.`,
  );
  return 0;
}

export interface CitationCheckOptions extends Credentials {
  node?: string;
  /** A verdict on each citation, as "<reference>=<verdict>". */
  verdicts?: string[];
  modelFamily?: string;
}

/**
 * Signs and sends a checker's verdicts on whether each source a bundle cites supports the claims
 * it is cited for, one on every citation the job lists, with the evidence folder: the checker's
 * report, quoting what it relied on, and the verdicts beside it. The harness proposes none.
 */
export async function citationCheck(jobDir: string, options: CitationCheckOptions, deps: Deps): Promise<number> {
  const record = await loadJob(jobDir);
  answeredWith(record, "citation-check");
  const citations = record.citations;
  if (!citations) throw new HarnessError("job.json lists no citations: take the job again with this harness.");
  const given = new Map<string, CitationVerdict>();
  for (const pair of options.verdicts ?? []) {
    // A verdict never holds "=", and a reference may: a DOI's suffix can be almost anything.
    const cut = pair.lastIndexOf("=");
    if (cut <= 0) throw new HarnessError(`--verdict takes <reference>=<verdict>, such as ${citations[0]?.reference ?? "doi:10.1000/x"}=supports; got ${pair}`);
    const reference = pair.slice(0, cut);
    const verdict = pair.slice(cut + 1);
    if (!citations.some((citation) => citation.reference === reference)) {
      throw new HarnessError(`--verdict names ${reference}, which isn't a citation this job lists: ${citations.map((c) => c.reference).join(", ")}`);
    }
    if (!(CITATION_VERDICTS as readonly string[]).includes(verdict)) {
      throw new HarnessError(`A citation verdict is one of ${CITATION_VERDICTS.join(", ")}, not ${verdict}`);
    }
    if (given.has(reference) && given.get(reference) !== verdict) throw new HarnessError(`--verdict gives ${reference} twice, as ${given.get(reference)} and ${verdict}`);
    given.set(reference, verdict as CitationVerdict);
  }
  const missing = citations.filter((citation) => !given.has(citation.reference)).map((citation) => citation.reference);
  if (missing.length > 0) {
    const named = missing.length > 10 ? `${missing.slice(0, 10).join(", ")}, and ${missing.length - 10} more` : missing.join(", ");
    throw new HarnessError(
      `Give a verdict on every citation the job lists, with --verdict ${shellQuote(`${missing[0]}=<verdict>`)} and so on, each one of ${CITATION_VERDICTS.join(", ")}. ${plural(missing.length, "citation")} ${missing.length === 1 ? "has" : "have"} none: ${named}.`,
    );
  }
  if (!options.modelFamily) {
    throw new HarnessError("Say which model family did this work with --model-family: one you declared and the publisher didn't.");
  }
  await requireReport(jobDir, "citation check");
  const client = new NodeClient(options.node ?? record.node, deps);
  const operator = await signIn({ ...options, operator: options.operator ?? deps.env.SJ_OPERATOR ?? record.operator }, client, deps);
  if (!operator.modelFamilies.includes(options.modelFamily)) {
    throw new HarnessError(`${options.modelFamily} isn't a model family ${operator.id} declared; it declared ${operator.modelFamilies.join(", ")}`);
  }

  // The verdicts go into the evidence beside the checker's report, which the harness never touches.
  const localId = new Map(record.claims.map((claim) => [claim.claim_id, claim.local_id]));
  await writeJsonFile(join(jobDir, "evidence", "verdicts.json"), {
    harness: HARNESS,
    job: record.job,
    kind: record.kind,
    bundle: record.bundle,
    citations: citations.map((citation) => ({
      reference: citation.reference,
      on_ledger: isClaimId(citation.reference),
      cited_for: citation.claims.map((claim) => localId.get(claim) ?? claim),
      verdict: given.get(citation.reference),
    })),
  });
  const evidence = await readEvidence(jobDir, client);
  const entry = signAs(operator, {
    type: "citation_check" as const,
    checker: operator.id,
    bundle: record.bundle,
    citations: Object.fromEntries(citations.map((citation) => [citation.reference, given.get(citation.reference)!])),
    evidence: evidence.digest,
    model_family: options.modelFamily,
  });
  const files = Object.fromEntries([...evidence.files].map(([file, bytes]) => [file, Buffer.from(bytes).toString("base64")]));
  const response = await client.post<{ citation_check: number }>("/api/v1/citation-checks", { entry, evidence: { files } });
  await writeJsonFile(join(jobDir, "citation-check.json"), { sent_at: deps.now().toISOString(), entry, response });

  for (const citation of citations) deps.print(`  ${citation.reference}: ${given.get(citation.reference)}`);
  const reached = citations.some((citation) => given.get(citation.reference) !== "could_not_access");
  deps.print(
    `Sent your citation check of ${plural(citations.length, "citation")}: the log holds it at entry ${response.citation_check}.${reached ? "" : " A check that could reach no source pays nothing."}`,
  );
  return 0;
}


export interface DuplicateCheckOptions extends Credentials {
  node?: string;
  /** A verdict on each pair, as "<pair number>=<verdict>", numbered as JOB.md lists them. */
  verdicts?: string[];
  modelFamily?: string;
}

/**
 * Signs and sends a checker's verdicts on whether each claim a duplicate check pairs restates the
 * earlier claim it is paired with, one on every pair the job lists, with the evidence folder: the
 * checker's report and the verdicts beside it. The harness proposes none.
 */
export async function duplicateCheck(jobDir: string, options: DuplicateCheckOptions, deps: Deps): Promise<number> {
  const record = await loadJob(jobDir);
  answeredWith(record, "duplicate-check");
  const pairs = record.pairs;
  if (!pairs || pairs.length === 0) throw new HarnessError("job.json lists no pairs: take the job again with this harness.");
  const given = new Map<number, DuplicateVerdict>();
  for (const pair of options.verdicts ?? []) {
    const cut = pair.indexOf("=");
    const number = Number(pair.slice(0, cut));
    const verdict = pair.slice(cut + 1);
    if (cut <= 0 || !Number.isInteger(number)) throw new HarnessError(`--verdict takes <pair number>=<verdict>, such as 1=distinct; got ${pair}`);
    if (number < 1 || number > pairs.length) throw new HarnessError(`--verdict names pair ${number}, but this job lists pairs 1 to ${pairs.length}`);
    if (!(DUPLICATE_VERDICTS as readonly string[]).includes(verdict)) {
      throw new HarnessError(`A duplicate verdict is one of ${DUPLICATE_VERDICTS.join(", ")}, not ${verdict}`);
    }
    if (given.has(number) && given.get(number) !== verdict) throw new HarnessError(`--verdict gives pair ${number} twice, as ${given.get(number)} and ${verdict}`);
    given.set(number, verdict as DuplicateVerdict);
  }
  const missing = pairs.map((_, i) => i + 1).filter((number) => !given.has(number));
  if (missing.length > 0) {
    throw new HarnessError(
      `Give a verdict on every pair the job lists, with --verdict ${missing[0]}=<verdict> and so on, each one of ${DUPLICATE_VERDICTS.join(", ")}. ${plural(missing.length, "pair")} ${missing.length === 1 ? "has" : "have"} none: ${missing.join(", ")}.`,
    );
  }
  if (!options.modelFamily) {
    throw new HarnessError("Say which model family did this work with --model-family: one you declared and the publisher didn't.");
  }
  await requireReport(jobDir, "duplicate check");
  const client = new NodeClient(options.node ?? record.node, deps);
  const operator = await signIn({ ...options, operator: options.operator ?? deps.env.SJ_OPERATOR ?? record.operator }, client, deps);
  if (!operator.modelFamilies.includes(options.modelFamily)) {
    throw new HarnessError(`${options.modelFamily} isn't a model family ${operator.id} declared; it declared ${operator.modelFamilies.join(", ")}`);
  }

  const judged = pairs.map((pair, i) => ({ claim: pair.claim, earlier: pair.earlier, verdict: given.get(i + 1)! }));
  // The verdicts go into the evidence beside the checker's report, which the harness never touches.
  await writeJsonFile(join(jobDir, "evidence", "verdicts.json"), {
    harness: HARNESS,
    job: record.job,
    kind: record.kind,
    bundle: record.bundle,
    pairs: judged,
  });
  const evidence = await readEvidence(jobDir, client);
  const entry = signAs(operator, {
    type: "duplicate_check" as const,
    checker: operator.id,
    bundle: record.bundle,
    pairs: judged,
    evidence: evidence.digest,
    model_family: options.modelFamily,
  });
  const files = Object.fromEntries([...evidence.files].map(([file, bytes]) => [file, Buffer.from(bytes).toString("base64")]));
  const response = await client.post<{ duplicate_check: number }>("/api/v1/duplicate-checks", { entry, evidence: { files } });
  await writeJsonFile(join(jobDir, "duplicate-check.json"), { sent_at: deps.now().toISOString(), entry, response });

  judged.forEach((pair, i) => deps.print(`  pair ${i + 1}: ${pair.verdict}`));
  const reached = judged.some((pair) => pair.verdict !== "could_not_judge");
  deps.print(
    `Sent your duplicate check of ${plural(judged.length, "pair")}: the log holds it at entry ${response.duplicate_check}.${reached ? "" : " A check that could judge no pair pays nothing."}`,
  );
  return 0;
}
