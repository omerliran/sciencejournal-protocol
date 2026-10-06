import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { digestEvidence } from "../bundle";
import { HIDDEN_KINDS, revealHidden } from "../scan";
import { HarnessError } from "./context";
import { code, plural, seconds, shown, size } from "./format";
import { exists, listOutputs, readOutput, removeTree, sha256File, sha256Output, under, writeJsonFile, writeUnder, type LogTail } from "./files";
import type { ScanRecord } from "./job";
import { describePlan, type CommandPlan, type ImageInfo, type Limits, type RunResult } from "./sandbox";
import type { JudgeRun } from "./judge";
import type { CheckedTheorem } from "./proof-check";
import type { MatchedResult, ReproducedResult, VerdictsRecord } from "./verdicts";

/**
 * What the harness puts in the evidence, which the reference node takes up to 10 MB of. The
 * rest of that is room for whatever the verifier adds.
 */
export const EVIDENCE_BUDGET = 8 * 1024 * 1024;
/** The most result files the evidence carries; the node takes 1,000 files in all. */
const RESULT_FILES = 900;
export const RUN_LOG = { head: 512 * 1024, tail: 512 * 1024 };
export const BUILD_LOG = { head: 128 * 1024, tail: 128 * 1024 };
/** The logs a run may leave in the evidence. */
const LOGS = ["run.log", "build.log", "judge.log"];

/** run.json, and the evidence's environment.json: how the run went. */
export interface RunRecord {
  harness: string;
  subject: { kind: string; job?: string; bundle: string; verification_inputs: string; declared_minutes: number };
  host: { platform: string; arch: string; node: string };
  engine?: { name: string; version: string };
  image?: ImageInfo;
  command?: CommandPlan;
  limits?: Limits;
  result?: RunResult;
  /** For a proof check, how the judge ran on what the run compiled. */
  judges?: JudgeRun[];
  /** Why the run didn't happen or didn't finish. */
  failure?: string;
  /** Set by compare: when the comparison was made again, and whether the results changed after the run. */
  compared_again?: { at: string; changed_after_run: boolean };
}

/**
 * Copies what the run wrote under results/ into evidence/results/: first the files the claims
 * name, then the smallest, while they fit the budget and the evidence path rules. The rest are
 * listed with their digests, so they can still be checked. Only regular files are copied.
 */
export async function copyResults(
  workspace: string,
  evidenceDir: string,
  named: ReadonlySet<string>,
  budget: number,
): Promise<NonNullable<VerdictsRecord["results_files"]>> {
  await removeTree(join(evidenceDir, "results"));
  const listed = await listOutputs(join(workspace, "results"));
  const files = await Promise.all(
    listed.files.map(async (path) => ({ path: `results/${path}`, bytes: (await stat(under(workspace, `results/${path}`))).size })),
  );
  files.sort((a, b) => Number(named.has(b.path)) - Number(named.has(a.path)) || a.bytes - b.bytes || (a.path < b.path ? -1 : 1));
  const copied: string[] = [];
  const omitted: { path: string; bytes?: number; digest?: string; reason: string }[] = listed.others.map((path) => ({
    path: `results/${path}`,
    reason: "not a regular file, so the harness didn't open it",
  }));
  const accepted = new Map<string, Uint8Array>();
  let used = 0;
  for (const file of files) {
    const leaveOut = async (reason: string) =>
      omitted.push({ path: file.path, bytes: file.bytes, digest: `sha256:${await sha256Output(workspace, file.path)}`, reason });
    if (used + file.bytes > budget || copied.length >= RESULT_FILES) {
      await leaveOut("to stay under the evidence limit");
      continue;
    }
    try {
      digestEvidence(new Map([...accepted, [file.path, new Uint8Array()]]));
    } catch (error) {
      await leaveOut(`because its name breaks the evidence path rules (${(error as Error).message})`);
      continue;
    }
    await writeUnder(evidenceDir, file.path, await readOutput(workspace, file.path, budget));
    accepted.set(file.path, new Uint8Array());
    used += file.bytes;
    copied.push(file.path);
  }
  return { copied, omitted };
}

/** Writes the run's logs into the evidence. */
export async function writeLogs(evidenceDir: string, logs: { run?: LogTail; build?: LogTail; judge?: LogTail }): Promise<void> {
  await mkdir(evidenceDir, { recursive: true });
  for (const [name, log] of Object.entries(logs)) {
    if (log && log.total > 0) await writeFile(join(evidenceDir, `${name}.log`), log.bytes());
  }
}

/** What the logs and other harness files take, so the results get the rest of the budget. */
export async function logBytes(evidenceDir: string): Promise<number> {
  let total = 64 * 1024; // room for report.md and environment.json
  for (const name of LOGS) total += (await stat(join(evidenceDir, name)).catch(() => null))?.size ?? 0;
  return total;
}

/**
 * Writes evidence/report.md and evidence/environment.json. The report is the harness's, written
 * again whenever the verdicts change, up to the moment they are sent, so it never writes over a
 * report the verifier changed: what they added would be lost from the evidence without a word.
 * What it wrote last is remembered by digest in `outDir`, beside the evidence and never in it.
 */
export async function writeReport(
  dirs: { outDir: string; evidenceDir: string },
  run: RunRecord | null,
  verdicts: VerdictsRecord,
  scan: ScanRecord | null,
): Promise<void> {
  const { outDir, evidenceDir: evidence } = dirs;
  const path = join(evidence, "report.md");
  const remembered = join(outDir, "report.sha256");
  if ((await exists(path)) && (await sha256File(path)) !== (await readFile(remembered, "utf8").catch(() => "")).trim()) {
    throw new HarnessError(
      `${path} isn't the report the harness last wrote there. The harness writes that report again with the verdicts you send, so anything you added to it would be lost. Move what you added to a file of its own under ${evidence}, such as notes.md, which the harness sends as you wrote it, then delete report.md and run this again.`,
    );
  }
  await mkdir(evidence, { recursive: true });
  if (run) {
    const environment: Partial<RunRecord> = { ...run };
    delete environment.subject;
    await writeJsonFile(join(evidence, "environment.json"), environment);
  }
  const logs = new Set<string>();
  for (const name of LOGS) if (await exists(join(evidence, name))) logs.add(name);
  const report = renderReport(run, verdicts, scan, logs);
  await writeFile(path, report);
  await writeFile(remembered, `${createHash("sha256").update(report).digest("hex")}\n`);
}

const TITLES: Partial<Record<VerdictsRecord["kind"], string>> = {
  reproduction: "Reproduction report",
  self_check: "Self-check report",
  replication_match: "Replication match report",
  proof_check: "Proof check report",
  challenge_rerun: "Re-run of the challenged claim",
};

/** The report; `logs` names the logs in the evidence beside it. */
export function renderReport(run: RunRecord | null, verdicts: VerdictsRecord, scan: ScanRecord | null, logs: ReadonlySet<string>): string {
  const title = TITLES[verdicts.kind] ?? "Report";
  const lines = [
    `# ${title}`,
    "",
    `Made by ${verdicts.harness}${verdicts.job ? ` for job ${verdicts.job}` : ""}, on bundle \`${verdicts.bundle}\`${run ? `, whose verification inputs are \`${run.subject.verification_inputs}\`` : ""}.`,
  ];
  if (run) lines.push("", "## How it ran", "", ...howItRan(run));

  // A re-run for a challenge review informs the reviewer's verdict on the challenge; it gives none of its own.
  const heading = verdicts.kind === "challenge_rerun" ? "What the re-run found" : "Verdicts";
  lines.push("", `## ${heading}`, "", "| Claim | Verdict | Chosen by | Why |", "| --- | --- | --- | --- |");
  for (const claim of verdicts.claims) {
    lines.push(`| ${code(claim.local_id)} | ${claim.verdict} | ${claim.by === "harness" ? "the harness" : "the verifier"} | ${cell(claim.reason)} |`);
  }
  lines.push("", `Claim IDs: ${verdicts.claims.map((claim) => `${claim.local_id} is \`${claim.claim_id}\``).join("; ")}.`);
  if (verdicts.over_budget) lines.push("", "Reported over budget: the work took more than the minutes its bundle declares.");

  if (verdicts.kind === "proof_check") {
    lines.push("", ...proofResults(verdicts, run));
  } else if (verdicts.kind === "replication_match") {
    lines.push(
      "",
      "## Results",
      "",
      "| Claim | Result | Original claim | Its result | Replication | Original | Tolerance | Agrees |",
      "| --- | --- | --- | --- | --- | --- | --- | --- |",
    );
    for (const claim of verdicts.claims) {
      for (const result of claim.results as MatchedResult[]) {
        lines.push(
          `| ${code(claim.local_id)} | ${code(result.result)} | \`${result.original}\` | ${code(result.original_result)} | ${value(result.replication)} | ${value(result.original_value)} | ${result.tolerance ?? "exact"} | ${agrees(result)} |`,
        );
      }
    }
  } else {
    lines.push(
      "",
      "## Results",
      "",
      "| Claim | Result | Produced by | Declared | Produced | Tolerance | Agrees |",
      "| --- | --- | --- | --- | --- | --- | --- |",
    );
    for (const claim of verdicts.claims) {
      for (const result of claim.results as ReproducedResult[]) {
        lines.push(
          `| ${code(claim.local_id)} | ${code(result.result)} | ${code(result.produced_by)} | ${value(result.declared)} | ${value(result.produced)} | ${result.tolerance ?? "exact"} | ${agrees(result)} |`,
        );
      }
    }
    lines.push(
      "",
      "A number agrees when it lands within its tolerance of the declared value, compared as the decimals canonical JSON writes; anything else must be equal.",
    );
  }

  if (scan) lines.push("", "## Hidden content", "", ...hiddenContent(scan));
  lines.push("", "## Files", "", ...files(run, verdicts, logs));
  return `${lines.join("\n")}\n`;
}

function proofResults(verdicts: VerdictsRecord, run: RunRecord | null): string[] {
  const lines = ["## Theorems", "", "| Claim | Proof | Theorem | Checker | Rests on | Checked |", "| --- | --- | --- | --- | --- | --- |"];
  for (const claim of verdicts.claims) {
    for (const theorem of claim.results as CheckedTheorem[]) {
      const axioms = theorem.axioms === undefined ? "not reported" : theorem.axioms.length > 0 ? theorem.axioms.map(code).join(", ") : "no axioms";
      lines.push(`| ${code(claim.local_id)} | ${code(theorem.proof)} | ${code(theorem.theorem)} | ${theorem.checker} | ${axioms} | ${theorem.status} |`);
    }
  }
  lines.push(
    "",
    "Checked in two steps. The first compiled each proof file, under a module name the harness chose, in the image the bundle declares; a proof file runs code while it is compiled and can print what it likes, so `run.log` is only the record of what that step printed. The second, the judge, ran in a fresh container built from the pinned checker alone, given nothing but the compiled files: it ran none of their code, had the kernel check every declaration in them again (Lean's kernel replaying them, or Rocq's independent checker, rocqchk), and worked out itself what each theorem rests on. Only the judge's answer decides.",
  );
  for (const judge of run?.judges ?? []) {
    if (judge.failure) lines.push("", `The ${judge.checker === "lean4" ? "Lean" : "Rocq"} judge didn't run to the end: ${judge.failure}`);
  }
  const unfinished = verdicts.unfinished ?? [];
  lines.push("", "## Unfinished-proof keywords", "");
  if (unfinished.length === 0) {
    lines.push("As information: no proof file uses its checker's unfinished-proof keywords (Lean's `sorry` and `admit`, Rocq's `Admitted` and `admit`) outside comments and strings.");
  } else {
    lines.push(
      "As information, where the proofs use their checker's unfinished-proof keywords, outside comments and strings; what each theorem rests on is what decides:",
      "",
      ...unfinished.slice(0, 50).map((found) => `- ${code(found.path)}, line ${found.line}, column ${found.column}: \`${found.keyword}\``),
      ...(unfinished.length > 50 ? [`- and ${unfinished.length - 50} more`] : []),
    );
  }
  return lines;
}

function howItRan(run: RunRecord): string[] {
  const lines: string[] = [];
  if (run.engine) lines.push(`- **Engine:** ${run.engine.name} ${run.engine.version}, on ${run.host.platform} ${run.host.arch} with Node ${run.host.node}.`);
  if (run.image) {
    const digests = run.image.digests.length > 0 ? ` Registry digest: ${run.image.digests.map((d) => `\`${d}\``).join(", ")}.` : "";
    lines.push(
      `- **Image:** \`${run.image.ref}\`, ${describePlan(run.image.plan)}${run.image.reused ? (run.image.plan.from === "given" ? ", already here" : " (built before from the same inputs, and used again)") : ""}. Image ID \`${run.image.id}\`.${digests}${run.image.home ? ` It runs as a user whose home, \`${run.image.home}\`, the run keeps.` : ""}`,
    );
  }
  if (run.command) {
    const from = {
      given: "given by the verifier",
      "code/run": "the bundle's code/run",
      produced_by: "the files the computations name",
      checker: "each proof file's checker",
    }[run.command.from];
    lines.push(`- **Command:** ${code(run.command.command)}, from ${from}, run from the bundle's root.`);
  }
  if (run.limits) {
    const declared = run.subject.declared_minutes;
    const time = run.limits.minutes === declared * 1.5 ? `${minutes(run.limits.minutes)} (1.5 times the ${minutes(declared)} the bundle declares)` : `${minutes(run.limits.minutes)} (the bundle declares ${minutes(declared)})`;
    lines.push(
      `- **Limits:** no network, every capability dropped, no new privileges, at most ${run.limits.pids} processes, ${run.limits.memory} of memory, ${plural(run.limits.cpus, "CPU")}, and ${time}.`,
    );
  }
  if (run.result) {
    const r = run.result;
    const outcome = r.timedOut
      ? `stopped at the time limit, after ${seconds(r.seconds)}`
      : r.outOfMemory
        ? `ran out of memory and was stopped (exit code ${r.exitCode}) after ${seconds(r.seconds)}`
        : `exit code ${r.exitCode} after ${seconds(r.seconds)}`;
    lines.push(`- **Outcome:** ${outcome}. Started ${r.startedAt}, finished ${r.finishedAt}.`);
  }
  if (run.failure) lines.push(`- **Didn't run to the end:** ${run.failure}`);
  if (run.compared_again) {
    lines.push(
      `- **Compared again** at ${run.compared_again.at}.${run.compared_again.changed_after_run ? " The results changed after the harness's run finished, so at least some of them come from work done outside it." : ""}`,
    );
  }
  return lines;
}

function hiddenContent(scan: ScanRecord): string[] {
  if (scan.findings.length === 0) {
    return [`Before any model read the bundle, the harness's scan found nothing hidden in its ${plural(scan.scanned.length, "text file")}.`];
  }
  return [
    `Before any model read the bundle, the harness's scan found ${plural(scan.findings.length, "thing")} hidden from a rendered view (each is in scan.json, with hidden characters made visible):`,
    "",
    ...scan.findings.slice(0, 50).map(
      (finding) =>
        `- ${code(finding.path)}, line ${finding.line}, column ${finding.column}: ${HIDDEN_KINDS[finding.kind].split(",")[0]}${finding.code_points ? ` (${finding.count}: ${finding.code_points.join(", ")})` : ""}: ${code(finding.excerpt)}`,
    ),
  ];
}

function files(run: RunRecord | null, verdicts: VerdictsRecord, logs: ReadonlySet<string>): string[] {
  const lines: string[] = [];
  if (logs.has("run.log")) lines.push("- `run.log`: everything the run printed, or its start and end when it was long.");
  else if (run?.result) lines.push("- No `run.log`: the run printed nothing.");
  if (logs.has("build.log")) lines.push("- `build.log`: what preparing the images printed.");
  if (logs.has("judge.log")) lines.push("- `judge.log`: what the judge printed, its answer about each theorem included.");
  if (run) lines.push("- `environment.json`: the machine, engine, image, command, limits, and outcome.");
  for (const original of verdicts.originals ?? []) {
    const fetched = Object.entries(original.files).map(([path, digest]) => `${code(path)} (\`${digest}\`)`);
    lines.push(
      `- \`${original.folder}/\`: the declared results of \`${original.claim}\`, from bundle \`${original.bundle}\`, as the node served them: ${fetched.join(", ") || "none"}.`,
    );
  }
  const results = verdicts.results_files;
  if (results) {
    lines.push(
      results.copied.length > 0
        ? `- \`results/\`: the ${plural(results.copied.length, "file")} the run wrote under results/.`
        : "- The run wrote nothing under results/.",
    );
    for (const file of results.omitted) {
      const what = file.digest ? ` (${size(file.bytes ?? 0)}, \`${file.digest}\`)` : "";
      lines.push(`- Left out ${file.reason}: ${code(file.path)}${what}.`);
    }
  }
  return lines;
}

function agrees(result: { agrees: boolean | null; problem?: string }): string {
  return result.agrees === null ? cell(`no: ${result.problem}`) : result.agrees ? "yes" : "**no**";
}

function value(v: unknown): string {
  return v === undefined ? "none" : code(shown(v));
}

function cell(text: string): string {
  return revealHidden(text).replaceAll("|", "\\|");
}

function minutes(value: number): string {
  return plural(Math.round(value * 100) / 100, "minute");
}
