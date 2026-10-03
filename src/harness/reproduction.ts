import { closeSync, openSync, readSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { lstat, mkdir, rename, rm } from "node:fs/promises";
import { arch, platform } from "node:os";
import { join } from "node:path";
import { VERIFICATION_INPUT_DIRECTORIES } from "../bundle";
import type { Computation } from "../claims";
import { canonicalDigest, type Digest } from "../hash";
import { bundleInputs, resultLocation } from "../results";
import { HarnessError, type Deps } from "./context";
import { BUILD_LOG, copyResults, EVIDENCE_BUDGET, logBytes, RUN_LOG, writeLogs, writeReport, type RunRecord } from "./evidence";
import { seconds } from "./format";
import { cloneTree, exists, listOutputs, LogTail, readFiles, readJsonFile, readOutput, removeTree, under, writeJsonFile } from "./files";
import { computationsOf, loadJob, parseClaims, type ScanRecord } from "./job";
import {
  containerSandbox,
  describePlan,
  findEngine,
  ImageError,
  limitsFor,
  planCommand,
  planImage,
  type ImagePlan,
  type Limits,
  type RunResult,
  type Sandbox,
} from "./sandbox";
import { compareComputation, proposeReproduction, type ReproducedResult, type VerdictsRecord } from "./verdicts";
import { HARNESS } from "./version";

/** What a run reproduces: a job's bundle, or a publisher's own. */
export interface Subject {
  kind: "reproduction" | "self_check";
  job?: string;
  bundle: string;
  /** Where the bundle's files are. */
  bundleDir: string;
  /** Where the harness writes: workspace/, evidence/, run.json, and verdicts.json. */
  outDir: string;
  verificationInputs: Digest;
  files: Record<string, { digest: string; bytes: number }>;
  declaredMinutes: number;
  /** The claims to give verdicts on, each with the computations in its evidence. */
  claims: { local_id: string; claim_id: string; computations: Computation[] }[];
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

/** What a job directory asks a run to reproduce. */
export async function jobSubject(jobDir: string): Promise<Subject> {
  const record = await loadJob(jobDir);
  if (record.kind === "screen" || record.kind === "hazard_review") {
    throw new HarnessError(`This is a ${record.kind} job: read the work and give your hazard verdict with the hazard command. There is nothing to run.`);
  }
  if (record.kind === "replication_match") {
    throw new HarnessError("This is a replication_match job: compare the results with the match command. There is nothing to run.");
  }
  const bundleDir = join(jobDir, "bundle");
  const claims = parseClaims((await readFiles(bundleDir, ["claims.json"])).get("claims.json"));
  const computations = computationsOf(record, claims);
  return {
    kind: "reproduction",
    job: record.job,
    bundle: record.bundle,
    bundleDir,
    outDir: jobDir,
    verificationInputs: record.verification_inputs,
    files: record.files,
    declaredMinutes: record.compute.minutes,
    claims: record.claims
      .filter((claim) => claim.needs_verdict)
      .map((claim) => ({ local_id: claim.local_id, claim_id: claim.claim_id, computations: computations.get(claim.local_id) ?? [] })),
  };
}

/**
 * Re-runs a bundle's computations in a sandbox: a fresh copy of its verification inputs with
 * an empty results/, so whatever lands there was written by the run; the image env/ declares;
 * the command the bundle implies. Then compares what the run wrote with what the bundle
 * declares, proposes a verdict for each claim, and writes the evidence.
 */
export async function runSubject(
  subject: Subject,
  options: RunOptions,
  deps: Deps,
  /** The container engine found here, unless a test says otherwise; null when none answers. */
  sandbox?: Sandbox | null,
): Promise<{ run: RunRecord | null; verdicts: VerdictsRecord }> {
  const paths = new Set(Object.keys(subject.files));
  const producedBy = subject.claims.flatMap((claim) => claim.computations.map((computation) => computation.produced_by));
  const command = planCommand(paths, producedBy, options.command, (path) => firstLine(under(subject.bundleDir, path)));
  const plan = planImage(paths, options.image);
  if (!plan) {
    throw new HarnessError(
      "The bundle doesn't say what to run it in: it has no env/Dockerfile, env/Containerfile, env/requirements.txt, or env/environment.yml. Give an image that has what the code needs with --image, such as python:3.12-slim.",
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
  for (const log of ["run.log", "build.log"]) await rm(join(subject.outDir, "evidence", log), { force: true });
  const box = sandbox === undefined ? await engineSandbox(options.engine) : sandbox;
  if (!box) {
    run.failure = "No container engine (Docker or Podman) answered here, and the harness runs bundle code only in a container.";
    return finish(subject, run, {}, deps);
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
      return await finish(subject, run, { build }, deps, { workspace: fresh });
    } finally {
      await removeTree(scratch);
    }
    await mkdir(join(fresh, "results"), { recursive: true });
    deps.print(`Running ${command.command} in ${box.engine.name}, with no network, for at most ${Math.round(limits.minutes * 100) / 100} minutes.`);
    run.result = await box.run({ image: run.image, workspace: fresh, command: command.command, limits }, log);
    const failure = failureOf(run.result, limits, subject.declaredMinutes);
    if (failure) run.failure = failure;
    return await finish(subject, run, { build, run: log }, deps, { workspace: fresh });
  } finally {
    await removeTree(fresh);
  }
}

/**
 * Compares the workspace's results again, as they are now, for example after the agent ran
 * something by hand: what the last run did is kept, but whether it failed no longer decides.
 */
export async function compareAgain(subject: Subject, deps: Deps): Promise<{ run: RunRecord | null; verdicts: VerdictsRecord }> {
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
  { ignoreFailure = false, workspace }: { ignoreFailure?: boolean; workspace?: string } = {},
): Promise<{ run: RunRecord | null; verdicts: VerdictsRecord }> {
  if (workspace) await rename(workspace, join(subject.outDir, "workspace"));
  await writeLogs(subject.outDir, logs);
  const named = new Set(
    subject.claims.flatMap((claim) => claim.computations.flatMap((computation) => resultLocation(computation.result)?.path ?? [])),
  );
  const verdicts = await compareSubject(subject, ignoreFailure ? undefined : run?.failure, named, deps.now());
  verdicts.over_budget = Boolean(run?.result?.timedOut && run.limits && run.limits.minutes >= subject.declaredMinutes);
  verdicts.results_files = await copyResults(subject.outDir, named, EVIDENCE_BUDGET - (await logBytes(subject.outDir)));
  if (run) await writeJsonFile(join(subject.outDir, "run.json"), run);
  await writeJsonFile(join(subject.outDir, "verdicts.json"), verdicts);
  const scan = await readJsonFile<ScanRecord>(join(subject.outDir, "scan.json")).catch(() => null);
  await writeReport(subject.outDir, run, verdicts, scan);
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
    harness: HARNESS,
    kind: subject.kind,
    ...(subject.job && { job: subject.job }),
    bundle: subject.bundle,
    compared_at: now.toISOString(),
    over_budget: false,
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

/** Why a run that happened didn't finish well, or undefined if it did. */
function failureOf(result: RunResult, limits: Limits, declaredMinutes: number): string | undefined {
  if (result.timedOut) {
    const share = limits.minutes === declaredMinutes * 1.5 ? `, 1.5 times the ${declaredMinutes} the bundle declares,` : "";
    return `The run passed its time limit of ${Math.round(limits.minutes * 100) / 100} minutes${share} and was stopped.`;
  }
  if (result.outOfMemory) return `The run ran out of memory, at its limit of ${limits.memory}, and was stopped.`;
  if (result.exitCode !== 0) {
    const meaning: Record<number, string> = {
      125: " (the engine couldn't start the container)",
      126: " (a command couldn't be executed)",
      127: " (a command wasn't found)",
      137: " (it was killed)",
    };
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
  deps.print("Proposed verdicts (verdicts.json):");
  for (const claim of verdicts.claims) deps.print(`  ${claim.local_id}: ${claim.verdict}. ${claim.reason}`);
  if (verdicts.over_budget) deps.print("The work ran past its declared minutes; attesting reports it over budget.");
  deps.print(`Evidence: ${join(subject.outDir, "evidence")}`);
}
