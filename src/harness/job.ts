import { chmod, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { BundleLayoutError, digestBundle, digestEvidence } from "../bundle";
import { ClaimsFileSchema, isComputation, isProof, type Claim, type Computation } from "../claims";
import { sha256Digest, type Digest } from "../hash";
import type { IntegrityFlags } from "../integrity";
import { parseJson } from "../json";
import type { Manifest } from "../manifest";
import { bundleInputs, type BundleInputs } from "../results";
import type { Capabilities } from "../rounds";
import { scanFiles, type ScanResult } from "../scan";
import { checkClaims } from "../validate";
import { REVIEW_JOBS, type ChallengeGround, type JobKind } from "../vocabulary";
import { renderBrief, type BriefProof, type Rubric } from "./brief";
import { NodeClient, nodeUrl, signAs, signIn, type Credentials } from "./client";
import { HarnessError, type Deps } from "./context";
import { exists, readFiles, readJsonFile, sha256File, under, writeJsonFile, writeUnder } from "./files";
import { plural, size } from "./format";
import { checkMaterials, readMaterials } from "./materials";
import { findUnfinished } from "./proof-check";
import { HARNESS } from "./version";

/** A job as the node hands it out. */
export interface JobView {
  job: string;
  kind: JobKind;
  bundle: Digest;
  deadline: string;
  fields: string[];
  compute: Manifest["compute"];
  claims: { local_id: string; claim_id: string; needs_verdict: boolean }[];
  replicates?: { claim_id: string; original: string; original_bundle: string }[];
  credits: number;
  files: Record<string, string>;
  /** What the node's deterministic checks flag; absent from nodes that don't run them. */
  integrity?: IntegrityFlags;
  /** For a challenge review: the challenge's log index, the claim it disputes, its ground, and its evidence, base64. */
  challenge?: { index: number; claim: string; ground: ChallengeGround; evidence: Record<string, string> };
  /** For a citation check: each source the bundle cites, and the claims it is cited for. */
  citations?: CitationView[];
  /** For a duplicate check: each pair of a claim and an earlier claim whose statements share most of their words. */
  pairs?: PairView[];
  downloads?: Record<
    string,
    { url: string; method: string; headers: Record<string, string>; expires_at: string; digest: string; bytes: number }
  >;
}

/**
 * A source a citation check judges: a claim on the ledger or an outside source, the bundle's
 * claims it is cited for, by global ID, and for an outside source what references.json says it is.
 */
export interface CitationView {
  reference: string;
  claims: string[];
  title?: string;
  authors?: string[];
  year?: number;
}

/**
 * A pair a duplicate check judges: a claim from the bundle and an earlier claim on the ledger,
 * each with its statement, which their publishers wrote.
 */
export interface PairView {
  claim: string;
  statement: string;
  earlier: string;
  earlier_statement: string;
  earlier_bundle: string;
}

/** job.json: the job without its files' contents, and what the harness checked about it. */
export interface JobRecord extends Omit<JobView, "files" | "downloads" | "challenge"> {
  /** Every file the job carries, by digest and size. The files themselves are under bundle/. */
  files: Record<string, { digest: Digest; bytes: number }>;
  /** For a challenge review: the challenge, with its evidence files by digest and size, under challenge/. */
  challenge?: { index: number; claim: string; ground: ChallengeGround; evidence: Record<string, { digest: Digest; bytes: number }> };
  node: string;
  operator: string;
  received_at: string;
  harness: string;
  /** The digest of everything under code/, env/, data/, and proofs/, which claims with evidence bind. */
  verification_inputs: Digest;
  /** "match" when the claim IDs the job names are the ones its files give; otherwise what differs. */
  claim_ids: string;
}

/** Files larger than this aren't scanned for hidden content; no model reads them whole. */
export const SCAN_LIMIT = 64 * 1024 * 1024;

export interface ScanRecord extends ScanResult {
  harness: string;
  /** Files too large to scan. */
  skipped: { path: string; bytes: number }[];
}

/** Where a job's files go: a directory named for the job, which works as a path anywhere. */
export function jobDirectoryName(job: string): string {
  const match = /^job:([0-9a-f]{1,64})$/.exec(job);
  if (!match) throw new HarnessError(`The node sent a job ID the harness can't use as a directory name: ${JSON.stringify(job)}`);
  return `job-${match[1]}`;
}

export interface TakeJobOptions extends Credentials {
  node?: string;
  /** Where job directories go. */
  dir: string;
  can?: Capabilities;
}

/**
 * Asks the node for a job (the open one, or a new one), writes its files under
 * <dir>/<job>/bundle/, fetches and checks every large file, scans everything for hidden
 * content, and writes job.json, scan.json, and the brief, JOB.md.
 */
export async function takeJob(options: TakeJobOptions, deps: Deps): Promise<{ record: JobRecord; jobDir: string } | null> {
  const client = new NodeClient(nodeUrl(options.node, deps), deps);
  const operator = await signIn(options, client, deps);
  const request = signAs(operator, {
    type: "job_request" as const,
    operator: operator.id,
    time: deps.now().toISOString(),
    ...(options.can && { can: options.can }),
  });
  const view = await client.post<JobView | { job: null; retry_after_seconds: number }>("/api/v1/jobs", request);
  if (view.job === null) {
    deps.print(`No job fits what you can run right now. Ask again in about ${Math.ceil(view.retry_after_seconds / 60)} minutes.`);
    return null;
  }

  const jobDir = join(options.dir, jobDirectoryName(view.job));
  const again = await exists(join(jobDir, "job.json"));
  const bundleDir = join(jobDir, "bundle");
  const inline = new Map(
    Object.entries(view.files).map(([path, base64]) => [path, new Uint8Array(Buffer.from(base64, "base64"))]),
  );
  const downloads = new Map(Object.entries(view.downloads ?? {}));
  let digests: ReturnType<typeof digestBundle>;
  try {
    // The bundle's own path rules keep every file inside bundle/, whatever the job names.
    digests = digestBundle(inline, new Map([...downloads].map(([path, link]) => [path, link.digest as Digest])));
  } catch (error) {
    if (error instanceof BundleLayoutError) throw new HarnessError(`The job's files break the bundle layout: ${error.message}`);
    throw error;
  }

  // Read-only, so nothing changes the work by accident; runs use a copy.
  for (const [path, bytes] of inline) await writeUnder(bundleDir, path, bytes, 0o444);
  for (const [path, link] of downloads) {
    const target = under(bundleDir, path);
    if ((await exists(target)) && `sha256:${await sha256File(target)}` === link.digest) continue;
    deps.print(`Fetching ${path} (${size(link.bytes)})...`);
    await mkdir(dirname(target), { recursive: true });
    await client.download(link, target, link);
    await chmod(target, 0o444);
  }

  const files = Object.fromEntries(
    Object.entries(digests.files).map(([path, digest]) => [
      path,
      { digest, bytes: inline.get(path)?.length ?? downloads.get(path)!.bytes },
    ]),
  );
  const challenge = view.challenge && (await takeChallenge(join(jobDir, "challenge"), view.challenge));
  const record: JobRecord = {
    job: view.job,
    kind: view.kind,
    bundle: view.bundle,
    deadline: view.deadline,
    fields: view.fields,
    compute: view.compute,
    claims: view.claims,
    ...(view.replicates && { replicates: view.replicates }),
    ...(view.integrity && { integrity: view.integrity }),
    ...(challenge && { challenge }),
    ...(view.citations && { citations: view.citations }),
    ...(view.pairs && { pairs: view.pairs }),
    credits: view.credits,
    files,
    node: client.base,
    operator: operator.id,
    received_at: deps.now().toISOString(),
    harness: HARNESS,
    verification_inputs: digests.verificationInputs,
    claim_ids: checkClaimIds(view, inline, digests.verificationInputs, new Set(downloads.keys())),
  };
  // The challenger's evidence is someone else's text too, so it is scanned like the bundle.
  const scan = await scanBundle(bundleDir, files);
  if (challenge) addScan(scan, await scanBundle(join(jobDir, "challenge"), challenge.evidence), "challenge/");
  const rubric = HAZARD_KINDS.includes(view.kind) ? await hazardRubric(client) : undefined;
  await writeJsonFile(join(jobDir, "job.json"), record);
  await writeJsonFile(join(jobDir, "scan.json"), scan);
  const claims = parseClaims(inline.get("claims.json"));
  const inputs = bundleInputs(inline, digests.verificationInputs);
  const declared = [...computationsOf(record, claims)].flatMap(([localId, computations]) =>
    computations.map((computation) => ({ local_id: localId, ...computation, declared: declaredValue(inputs, computation.result) })),
  );
  const proofs = proofsOf(record, claims);
  const unfinished = proofs.length > 0 ? await findUnfinished(bundleDir, Object.keys(files), proofs.map((proof) => proof.checker)) : [];
  // A review judges whether the work can be repeated, so it sees what the materials' RRIDs resolve to.
  const listed = (REVIEW_JOBS as readonly string[]).includes(view.kind) ? readMaterials(inline.get("materials.json")) : null;
  if (listed?.some((material) => material.rrid)) deps.print("Looking up the RRIDs materials.json gives...");
  const materials = listed && listed.length > 0 ? await checkMaterials(listed, deps) : undefined;
  await writeUnder(
    jobDir,
    "JOB.md",
    renderBrief({ record, jobDir, scan, rubric, declared, proofs, unfinished, materials, invocation: deps.invocation, now: deps.now() }),
  );

  deps.print(`${again ? "Your open job" : "New job"} ${view.job}: ${view.kind} of ${view.bundle}, due ${view.deadline}.`);
  deps.print(`Wrote ${jobDir}: bundle/ (${plural(Object.keys(files).length, "file")}), job.json, scan.json, and JOB.md.`);
  if (record.claim_ids !== "match") deps.print(`Warning: ${record.claim_ids}.`);
  if (scan.findings.length > 0) deps.print(`The hidden-content scan found ${plural(scan.findings.length, "thing")} to look at; JOB.md lists them.`);
  return { record, jobDir };
}

/** The kinds of job whose answer includes the verifier's hazard screen. */
const HAZARD_KINDS: readonly JobKind[] = ["reproduction", "screen", "hazard_review"];

/** The command that sends the answer to each kind of job. */
export const ANSWERED_WITH: Record<JobKind, string> = {
  reproduction: "attest",
  screen: "hazard",
  hazard_review: "hazard",
  replication_match: "attest",
  challenge_review: "challenge-review",
  methods_review: "attest",
  domain_review: "attest",
  adversarial_review: "attest",
  proof_check: "attest",
  citation_check: "citation-check",
  duplicate_check: "duplicate-check",
};

/**
 * Refuses a job that `command` doesn't answer, naming the command that does. A job the node
 * added after this harness was built is answered the way /llms.txt describes.
 */
export function answeredWith(record: Pick<JobRecord, "kind">, command: string): void {
  const answering = Object.hasOwn(ANSWERED_WITH, record.kind) ? ANSWERED_WITH[record.kind] : undefined;
  if (answering === command) return;
  if (!answering) {
    throw new HarnessError(`This harness doesn't know ${record.kind} jobs yet. Get the current one, or answer the job the way /llms.txt describes.`);
  }
  throw new HarnessError(`A ${record.kind} job is answered with the ${answering} command, not ${command}.`);
}

/** Whether a job's work runs in the sandbox: a reproduction, a proof check, or a challenge that re-running fails. */
export function runsInSandbox(record: Pick<JobRecord, "kind" | "challenge">): boolean {
  return record.kind === "reproduction" || record.kind === "proof_check" || (record.kind === "challenge_review" && record.challenge?.ground === "reproduction");
}

/** Writes a challenge's evidence under challenge/, read-only, held to the evidence path rules. */
async function takeChallenge(directory: string, challenge: NonNullable<JobView["challenge"]>): Promise<JobRecord["challenge"]> {
  const evidence = new Map(Object.entries(challenge.evidence).map(([path, base64]) => [path, new Uint8Array(Buffer.from(base64, "base64"))]));
  let digested: ReturnType<typeof digestEvidence>;
  try {
    digested = digestEvidence(evidence);
  } catch (error) {
    if (error instanceof BundleLayoutError) throw new HarnessError(`The challenge's evidence breaks the path rules: ${error.message}`);
    throw error;
  }
  for (const [path, bytes] of evidence) await writeUnder(directory, path, bytes, 0o444);
  return {
    index: challenge.index,
    claim: challenge.claim,
    ground: challenge.ground,
    evidence: Object.fromEntries([...evidence].map(([path, bytes]) => [path, { digest: digested.files[path], bytes: bytes.length }])),
  };
}

/** Adds another folder's scan to a job's, its paths given from the job directory with `prefix`. */
function addScan(scan: ScanRecord, more: ScanRecord, prefix: string): void {
  scan.scanned.push(...more.scanned.map((path) => prefix + path));
  scan.binary.push(...more.binary.map((path) => prefix + path));
  scan.findings.push(...more.findings.map((finding) => ({ ...finding, path: prefix + finding.path })));
  for (const [path, count] of Object.entries(more.omitted)) scan.omitted[prefix + path] = count;
  scan.skipped.push(...more.skipped.map((file) => ({ ...file, path: prefix + file.path })));
}

/** The proofs in the evidence of each claim that needs a verdict. */
export function proofsOf(record: Pick<JobRecord, "claims">, claims: readonly Claim[] | null): BriefProof[] {
  const byLocalId = new Map((claims ?? []).map((claim) => [claim.local_id, claim]));
  return record.claims
    .filter((claim) => claim.needs_verdict)
    .flatMap((claim) => (byLocalId.get(claim.local_id)?.evidence.filter(isProof) ?? []).map((proof) => ({ local_id: claim.local_id, ...proof })));
}

/** Reads job.json from a job directory. */
export async function loadJob(jobDir: string): Promise<JobRecord> {
  const path = join(jobDir, "job.json");
  if (!(await exists(path))) throw new HarnessError(`${jobDir} has no job.json; take a job with the job command first`);
  return readJsonFile<JobRecord>(path);
}

/** Whether the claim IDs a job names are the ones its files give. */
function checkClaimIds(
  view: JobView,
  inline: ReadonlyMap<string, Uint8Array>,
  verificationInputs: Digest,
  downloaded: ReadonlySet<string>,
): string {
  let claims: unknown;
  try {
    claims = parseJson(new TextDecoder("utf-8", { fatal: true }).decode(inline.get("claims.json")));
  } catch (error) {
    return `claims.json isn't readable JSON: ${(error as Error).message}`;
  }
  const inputs = bundleInputs(inline, verificationInputs);
  const check = checkClaims(claims, { ...inputs, has: (path) => inline.has(path) || downloaded.has(path) });
  if (!check.valid) return `claims.json doesn't check: ${check.issues.map((issue) => `${issue.path} ${issue.message}`).join("; ")}`;
  const ids = new Map(check.claims.map((claim) => [claim.local_id, claim.claim_id]));
  const differ = view.claims.filter((claim) => ids.get(claim.local_id) !== claim.claim_id);
  if (differ.length > 0 || ids.size !== view.claims.length) {
    const which = differ.map((claim) => claim.local_id).join(", ") || "a different set of claims";
    return `the job's claim IDs aren't the ones its files give (${which}), so verdicts on them would be about other claims`;
  }
  return "match";
}

/** Scans every file small enough to scan, reading each from disk. */
export async function scanBundle(bundleDir: string, files: Record<string, { bytes: number }>): Promise<ScanRecord> {
  const entries = Object.entries(files);
  const result = scanFiles(await readFiles(bundleDir, entries.filter(([, file]) => file.bytes <= SCAN_LIMIT).map(([path]) => path)));
  return {
    harness: HARNESS,
    ...result,
    skipped: entries.filter(([, file]) => file.bytes > SCAN_LIMIT).map(([path, file]) => ({ path, bytes: file.bytes })),
  };
}

/** The hazard screen everyone applies, checked against its digest. */
async function hazardRubric(client: NodeClient): Promise<Rubric> {
  const rubric = await client.get<{ rubric: string; text: string; verdicts: string[] }>("/api/v1/hazard-rubric");
  if (sha256Digest(rubric.text) !== rubric.rubric) {
    throw new HarnessError("The hazard rubric the node serves doesn't match its own digest");
  }
  return { digest: rubric.rubric, text: rubric.text, verdicts: rubric.verdicts };
}

/** claims.json's claims, or null when it doesn't parse; the job's claim check says why. */
export function parseClaims(bytes: Uint8Array | undefined): Claim[] | null {
  if (!bytes) return null;
  try {
    const parsed = ClaimsFileSchema.safeParse(parseJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/** The computations in the evidence of each claim that needs a verdict, by local ID. */
export function computationsOf(record: Pick<JobRecord, "claims">, claims: readonly Claim[] | null): Map<string, Computation[]> {
  const byLocalId = new Map((claims ?? []).map((claim) => [claim.local_id, claim]));
  return new Map(
    record.claims
      .filter((claim) => claim.needs_verdict)
      .map((claim) => [claim.local_id, byLocalId.get(claim.local_id)?.evidence.filter(isComputation) ?? []]),
  );
}

/** A computation, with the value the bundle declares for its result or why there is none. */
export interface DeclaredComputation extends Computation {
  local_id: string;
  declared: { value: unknown } | { problem: string };
}

export function declaredValue(inputs: BundleInputs, result: string): DeclaredComputation["declared"] {
  try {
    return { value: inputs.result(result) };
  } catch (error) {
    return { problem: (error as Error).message };
  }
}
