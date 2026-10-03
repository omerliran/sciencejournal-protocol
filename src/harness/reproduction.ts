import { closeSync, openSync, readSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { lstat, mkdir, rename, rm } from "node:fs/promises";
import { arch, platform } from "node:os";
import { join } from "node:path";
import { VERIFICATION_INPUT_DIRECTORIES } from "../bundle";
import { isComputation, isProof, type Computation, type ProofEvidence } from "../claims";
import { canonicalDigest, type Digest } from "../hash";
import { bundleInputs, resultLocation } from "../results";
import { REVIEW_JOBS } from "../vocabulary";
import { HarnessError, type Deps } from "./context";
import { BUILD_LOG, copyResults, EVIDENCE_BUDGET, logBytes, RUN_LOG, writeLogs, writeReport, type RunRecord } from "./evidence";
import { plural, seconds } from "./format";
import { cloneTree, exists, listOutputs, LogTail, readFiles, readJsonFile, readOutput, removeTree, under, writeJsonFile } from "./files";
import { answeredWith, loadJob, parseClaims, runsInSandbox, type ScanRecord } from "./job";
import { askAboutTheorems, checkTheorems, findUnfinished, proofCommand, ProofOutput, proofProbe, type ProofProbe } from "./proof-check";
import {
  containerSandbox,
  describePlan,
  findEngine,
  ImageError,
  limitsFor,
  planCommand,
  planImage,
  type CommandPlan,
  type ImagePlan,
  type Limits,
  type OutputSink,
  type RunResult,
  type Sandbox,
} from "./sandbox";
import {
  compareComputation,
  proposeProofCheck,
  proposeReproduction,
  type ReproducedResult,
  type VerdictsKind,
  type VerdictsRecord,
} from "./verdicts";
import { HARNESS } from "./version";

/**
 * What a run checks: a job's bundle or a publisher's own, by re-running its computations or by
 * running the proof checker on its proofs.
 */
export interface Subject {
  kind: Extract<VerdictsKind, "reproduction" | "self_check" | "proof_check" | "challenge_rerun">;
  job?: string;
  bundle: string;
  /** Where the bundle's files are. */
  bundleDir: string;
  /** Where the harness writes: workspace/, run.json, and verdicts.json. */
  outDir: string;
  /** Where the evidence goes: report.md, run.log, environment.json, and results/. */
  evidenceDir: string;
  verificationInputs: Digest;
  files: Record<string, { digest: string; bytes: number }>;
  declaredMinutes: number;
  /** The claims to give verdicts on, with the computations and proofs in their evidence. */
  claims: { local_id: string; claim_id: string; computations: Computation[]; proofs: ProofEvidence[] }[];
}

export interface RunOptions {
  image?: string;
  command?: string;
  minutes?: number;
  memory?: string;
  cpus?: number;
  pids?: number;
  engine?: string;
}

/** The largest results file the harness reads to compare. */
const RESULT_BYTES = 64 * 1024 * 1024;

/** What a job directory asks a run to do: reproduce, check proofs, or re-run a challenged claim. */
export async function jobSubject(jobDir: string): Promise<Subject> {
  const record = await loadJob(jobDir);
  const nothing = (what: string) => new HarnessError(`This is a ${record.kind} job: ${what}. There is nothing to run.`);
  if (record.kind === "screen" || record.kind === "hazard_review") throw nothing("read the work and give your hazard verdict with the hazard command");
  if (record.kind === "replication_match") throw nothing("compare the results with the match command");
  if ((REVIEW_JOBS as readonly string[]).includes(record.kind)) {
    throw nothing("read the work, write your report in evidence/report.md, and attest with a --verdict and --reason for each claim");
  }
  if (record.kind === "challenge_review" && record.challenge?.ground !== "reproduction") {
    throw nothing("the challenge's ground isn't that re-running fails; weigh its evidence, write your report in evidence/report.md, and send it with challenge-review");
  }
  if (record.kind === "citation_check") {
    throw nothing("read each source it cites, write your report in evidence/report.md, and send a verdict on each with citation-check");
  }
  // A job the node added after this harness was built.
  if (!runsInSandbox(record)) answeredWith(record, "run");
  const bundleDir = join(jobDir, "bundle");
  const claims = new Map((parseClaims((await readFiles(bundleDir, ["claims.json"])).get("claims.json")) ?? []).map((c) => [c.local_id, c]));
  const kind: Subject["kind"] = record.kind === "challenge_review" ? "challenge_rerun" : record.kind === "proof_check" ? "proof_check" : "reproduction";
  return {
    kind,
    job: record.job,
    bundle: record.bundle,
    bundleDir,
    outDir: jobDir,
    // A challenge review's report is the reviewer's own, so what the harness re-ran goes beside it.
    evidenceDir: kind === "challenge_rerun" ? join(jobDir, "evidence", "rerun") : join(jobDir, "evidence"),
    verificationInputs: record.verification_inputs,
    files: record.files,
    declaredMinutes: record.compute.minutes,
    claims: record.claims
      .filter((claim) => claim.needs_verdict)
      .map((claim) => {
        const evidence = claims.get(claim.local_id)?.evidence ?? [];
        return { local_id: claim.local_id, claim_id: claim.claim_id, computations: evidence.filter(isComputation), proofs: evidence.filter(isProof) };
      }),
  };
}

/**
 * Runs a bundle's work in a sandbox: a fresh copy of its verification inputs with an empty
 * results/, in the image env/ declares. A reproduction runs the command the bundle implies and
 * compares what it wrote with what the bundle declares; a proof check runs each proof's checker
 * and asks it what each named theorem rests on. Either way it proposes a verdict for each claim
 * and writes the evidence.
 */
export async function runSubject(
  subject: Subject,
  options: RunOptions,
  deps: Deps,
  /** The container engine found here, unless a test says otherwise; null when none answers. */
  sandbox?: Sandbox | null,
): Promise<{ run: RunRecord | null; verdicts: VerdictsRecord }> {
  const paths = new Set(Object.keys(subject.files));
  const proving = subject.kind === "proof_check";
  const probe = proving ? proofProbe(subject.claims.flatMap((claim) => claim.proofs)) : null;
  const command: CommandPlan = probe
    ? proofCommand(probe, options.command)
    : planCommand(
        paths,
        subject.claims.flatMap((claim) => claim.computations.map((computation) => computation.produced_by)),
        options.command,
        (path) => firstLine(under(subject.bundleDir, path)),
      );
  const plan = planImage(paths, options.image);
  if (!plan) {
    const example = proving ? "rocq/rocq-prover:9.0 for Rocq, or one with elan and the Lean toolchain the proofs pin" : "python:3.12-slim";
    throw new HarnessError(
      `The bundle doesn't say what to run it in: it has no env/Dockerfile, env/Containerfile, env/requirements.txt, or env/environment.yml. Give an image that has what it needs with --image, such as ${example}.`,
    );
  }
  const run: RunRecord = {
    harness: HARNESS,
    subject: {
      kind: subject.kind,
      ...(subject.job && { job: subject.job }),
      bundle: subject.bundle,
      verification_inputs: subject.verificationInputs,
      declared_minutes: subject.declaredMinutes,
    },
    host: { platform: platform(), arch: arch(), node: process.version },
    command,
  };

  // Nothing from an earlier run stays to be mistaken for this one's: its workspace and logs go.
  await removeTree(join(subject.outDir, "workspace"));
  for (const log of ["run.log", "build.log"]) await rm(join(subject.evidenceDir, log), { force: true });
  const box = sandbox === undefined ? await engineSandbox(options.engine) : sandbox;
  if (!box) {
    run.failure = "No container engine (Docker or Podman) answered here, and the harness runs bundle code only in a container.";
    return finish(subject, run, {}, deps, { probe });
  }
  run.engine = box.engine;
  const limits = limitsFor(box.capacity, subject.declaredMinutes, options);
  run.limits = limits;

  // Each run works in a directory no earlier run mounted, which becomes workspace/ when it ends:
  // engines that share files into a virtual machine can cache a mounted path, and serve a
  // directory deleted since as if it were still there.
  const fresh = join(subject.outDir, `.run-${randomBytes(6).toString("hex")}`);
  const build = new LogTail(BUILD_LOG.head, BUILD_LOG.tail);
  const log = new LogTail(RUN_LOG.head, RUN_LOG.tail);
  const output = probe && new ProofOutput(probe);
  try {
    for (const directory of VERIFICATION_INPUT_DIRECTORIES) {
      await cloneTree(join(subject.bundleDir, directory), join(fresh, directory));
    }
    const scratch = join(subject.outDir, ".build");
    deps.print(`Preparing the image: ${describePlan(plan)}.`);
    try {
      run.image = await box.image(plan, { workspace: fresh, scratch, key: imageKey(plan, subject) }, build);
    } catch (error) {
      if (!(error instanceof ImageError)) throw error;
      run.failure = error.message;
      return await finish(subject, run, { build }, deps, { workspace: fresh, probe });
    } finally {
      await removeTree(scratch);
    }
    await mkdir(join(fresh, "results"), { recursive: true });
    // After the build, so the questions never change what the image is built from.
    if (probe) await askAboutTheorems(fresh, probe);
    const sink: OutputSink = output
      ? { write: (chunk, stream) => (log.write(chunk), output.write(chunk, stream)) }
      : log;
    const what = proving ? "the proof checks" : command.command;
    deps.print(`Running ${what} in ${box.engine.name}, with no network, for at most ${Math.round(limits.minutes * 100) / 100} minutes.`);
    run.result = await box.run({ image: run.image, workspace: fresh, command: command.command, limits }, sink);
    const failure = failureOf(run.result, limits, subject.declaredMinutes, proving);
    if (failure) run.failure = failure;
    return await finish(subject, run, { build, run: log }, deps, { workspace: fresh, probe, output });
  } finally {
    await removeTree(fresh);
  }
}

/**
 * Compares the workspace's results again, as they are now, for example after the agent ran
 * something by hand: what the last run did is kept, but whether it failed no longer decides.
 */
export async function compareAgain(subject: Subject, deps: Deps): Promise<{ run: RunRecord | null; verdicts: VerdictsRecord }> {
  if (subject.kind === "proof_check") {
    throw new HarnessError("A proof check has no results to compare: what it found comes from the checker as it runs, so run it again.");
  }
  const results = join(subject.outDir, "workspace", "results");
  if (!(await exists(results))) {
    throw new HarnessError(`There is no ${results}: re-run the work with the run command first.`);
  }
  const run = await readJsonFile<RunRecord>(join(subject.outDir, "run.json")).catch(() => null);
  if (run) {
    const finished = run.result ? Date.parse(run.result.finishedAt) : 0;
    const listed = await listOutputs(results);
    let changed = false;
    for (const path of listed.files) changed ||= (await lstat(join(results, ...path.split("/")))).mtimeMs > finished;
    run.compared_again = { at: deps.now().toISOString(), changed_after_run: changed };
  }
  return finish(subject, run, {}, deps, { ignoreFailure: true });
}

async function finish(
  subject: Subject,
  run: RunRecord | null,
  logs: { build?: LogTail; run?: LogTail },
  deps: Deps,
  {
    ignoreFailure = false,
    workspace,
    probe = null,
    output = null,
  }: { ignoreFailure?: boolean; workspace?: string; probe?: ProofProbe | null; output?: ProofOutput | null } = {},
): Promise<{ run: RunRecord | null; verdicts: VerdictsRecord }> {
  if (workspace) await rename(workspace, join(subject.outDir, "workspace"));
  await writeLogs(subject.evidenceDir, logs);
  const failure = ignoreFailure ? undefined : run?.failure;
  let verdicts: VerdictsRecord;
  if (probe) {
    verdicts = await checkProofs(subject, probe, output, run?.result?.exitCode ?? null, failure, deps.now());
  } else {
    const named = new Set(
      subject.claims.flatMap((claim) => claim.computations.flatMap((computation) => resultLocation(computation.result)?.path ?? [])),
    );
    verdicts = await compareSubject(subject, failure, named, deps.now());
    verdicts.over_budget = Boolean(run?.result?.timedOut && run.limits && run.limits.minutes >= subject.declaredMinutes);
    verdicts.results_files = await copyResults(
      join(subject.outDir, "workspace"),
      subject.evidenceDir,
      named,
      EVIDENCE_BUDGET - (await logBytes(subject.evidenceDir)),
    );
  }
  if (run) await writeJsonFile(join(subject.outDir, "run.json"), run);
  await writeJsonFile(join(subject.outDir, "verdicts.json"), verdicts);
  const scan = await readJsonFile<ScanRecord>(join(subject.outDir, "scan.json")).catch(() => null);
  await writeReport(subject.evidenceDir, run, verdicts, scan);
  printOutcome(subject, run, verdicts, logs.run, deps);
  return { run, verdicts };
}

async function compareSubject(subject: Subject, failure: string | undefined, named: ReadonlySet<string>, now: Date): Promise<VerdictsRecord> {
  const declared = bundleInputs(await readFiles(subject.bundleDir, [...named].filter((path) => path in subject.files)), subject.verificationInputs);
  const workspace = join(subject.outDir, "workspace");
  const producedFiles = new Map<string, Uint8Array>();
  const unreadable = new Map<string, string>();
  for (const path of named) {
    try {
      producedFiles.set(path, await readOutput(workspace, path, RESULT_BYTES));
    } catch (error) {
      unreadable.set(path, (error as Error).message);
    }
  }
  const produced = bundleInputs(producedFiles, subject.verificationInputs);
  return {
    ...recordOf(subject, now),
    claims: subject.claims.map((claim) => {
      const results: ReproducedResult[] = claim.computations.map((computation) => {
        const compared = compareComputation(computation, declared, produced);
        const path = resultLocation(computation.result)?.path;
        const why = path && unreadable.get(path);
        // Say why a file the run left wasn't read, rather than that it isn't there.
        return why && compared.agrees === null && compared.declared !== undefined
          ? { ...compared, problem: `the run didn't produce it (${why})` }
          : compared;
      });
      return { local_id: claim.local_id, claim_id: claim.claim_id, ...proposeReproduction(results, failure), by: "harness" as const, results };
    }),
  };
}

/** Each claim's proof-check proposal, from what the checker said about each theorem it names. */
async function checkProofs(
  subject: Subject,
  probe: ProofProbe,
  output: ProofOutput | null,
  exitCode: number | null,
  failure: string | undefined,
  now: Date,
): Promise<VerdictsRecord> {
  const theorems = failure || !output ? [] : checkTheorems(probe, output, exitCode);
  const unfinished = await findUnfinished(subject.bundleDir, Object.keys(subject.files), probe.files.map((file) => file.checker));
  return {
    ...recordOf(subject, now),
    claims: subject.claims.map((claim) => {
      const results = theorems.filter((theorem) => claim.proofs.some((proof) => proof.proof === theorem.proof && proof.theorem === theorem.theorem));
      return { local_id: claim.local_id, claim_id: claim.claim_id, ...proposeProofCheck(results, failure), by: "harness" as const, results };
    }),
    unfinished,
  };
}

function recordOf(subject: Subject, now: Date): VerdictsRecord {
  return {
    harness: HARNESS,
    kind: subject.kind,
    ...(subject.job && { job: subject.job }),
    bundle: subject.bundle,
    compared_at: now.toISOString(),
    over_budget: false,
    claims: [],
  };
}

/**
 * Why a run that happened didn't finish well, or undefined if it did. A checker that rejects a
 * proof exits nonzero without the run failing, so a proof check fails only when the run itself
 * did: past its time, out of memory, or a command the engine couldn't start.
 */
function failureOf(result: RunResult, limits: Limits, declaredMinutes: number, proving: boolean): string | undefined {
  if (result.timedOut) {
    const share = limits.minutes === declaredMinutes * 1.5 ? `, 1.5 times the ${declaredMinutes} the bundle declares,` : "";
    return `The run passed its time limit of ${Math.round(limits.minutes * 100) / 100} minutes${share} and was stopped.`;
  }
  if (result.outOfMemory) return `The run ran out of memory, at its limit of ${limits.memory}, and was stopped.`;
  const meaning: Record<number, string> = {
    125: " (the engine couldn't start the container)",
    126: " (a command couldn't be executed)",
    127: " (a command wasn't found)",
    137: " (it was killed)",
  };
  const started = result.exitCode !== null && !(result.exitCode in meaning);
  if (result.exitCode !== 0 && !(proving && started)) {
    return `The run exited with code ${result.exitCode}${meaning[result.exitCode ?? -1] ?? ""}; see run.log.`;
  }
  return undefined;
}

/** Names an image built from these inputs, so a later run can use it again. */
function imageKey(plan: ImagePlan, subject: Subject): string {
  const inputs =
    plan.from === "Dockerfile"
      ? subject.verificationInputs
      : canonicalDigest(
          Object.fromEntries(Object.entries(subject.files).filter(([path]) => path.startsWith("env/")).map(([path, file]) => [path, file.digest])),
        );
  return canonicalDigest({ harness: HARNESS, plan, inputs }).slice("sha256:".length, "sha256:".length + 16);
}

async function engineSandbox(preferred?: string): Promise<Sandbox | null> {
  const engine = await findEngine(preferred);
  return engine && containerSandbox(engine);
}

/** A file's first line, for a shebang. */
function firstLine(path: string): string | undefined {
  try {
    const fd = openSync(path, "r");
    try {
      const buffer = Buffer.alloc(256);
      const read = readSync(fd, buffer, 0, buffer.length, 0);
      return buffer.subarray(0, read).toString("utf8").split(/\r?\n/)[0];
    } finally {
      closeSync(fd);
    }
  } catch {
    return undefined;
  }
}

function printOutcome(subject: Subject, run: RunRecord | null, verdicts: VerdictsRecord, log: LogTail | undefined, deps: Deps): void {
  const result = run?.result;
  if (run?.compared_again) {
    deps.print(
      `Compared the workspace's results again${run.compared_again.changed_after_run ? "; they changed after the harness's run, and the report says so" : ""}.`,
    );
  } else if (result) {
    deps.print(
      result.timedOut
        ? `Stopped at the time limit after ${seconds(result.seconds)}.`
        : `Exit code ${result.exitCode} after ${seconds(result.seconds)}${result.outOfMemory ? ", out of memory" : ""}.`,
    );
    if (run?.failure && log) for (const line of log.lastLines(12)) deps.print(`  | ${line}`);
  } else if (run?.failure) {
    deps.print(run.failure);
  }
  if (subject.kind === "challenge_rerun") {
    deps.print("What the re-run found for the challenged claim (verdicts.json; your verdict on the challenge is yours to give):");
  } else {
    deps.print("Proposed verdicts (verdicts.json):");
  }
  for (const claim of verdicts.claims) deps.print(`  ${claim.local_id}: ${claim.verdict}. ${claim.reason}`);
  if (verdicts.over_budget && subject.kind !== "challenge_rerun") {
    deps.print("The work ran past its declared minutes; attesting reports it over budget.");
  }
  if (verdicts.unfinished && verdicts.unfinished.length > 0) {
    deps.print(`As information: the proofs use unfinished-proof keywords ${plural(verdicts.unfinished.length, "time")} (the report lists where).`);
  }
  deps.print(`Evidence: ${subject.evidenceDir}`);
}
