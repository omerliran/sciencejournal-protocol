import { randomBytes } from "node:crypto";
import { copyFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { ProofEvidence } from "../claims";
import { PROOF_FILE_EXTENSIONS, THEOREM_NAMES, unfinishedProofs, type UnfinishedProof } from "../proofs";
import type { ProofChecker } from "../vocabulary";
import { HarnessError } from "./context";
import { under } from "./files";
import { COMPILE_DIR, moduleName, type JudgeAnswer, type JudgeAsk } from "./judge";
import type { CommandPlan } from "./sandbox";

// Proof checks, in the two steps judge.ts describes. The first compiles each proof file, copied
// under a module name the harness picks, in the image the work declares, and says whether the
// checker accepted it. The second, the judge, decides what each named theorem is and rests on.
// A theorem passes when its file compiled without errors, the judge found it accepted by the
// kernel, and it rests on nothing beyond the checker's standard axioms. What the first step
// printed is only a record: a proof file runs code while it is compiled and can print anything.

/** The axioms each checker's foundations assume. Anything else, `sorryAx` included, is an assumption. */
export const STANDARD_AXIOMS: Record<ProofChecker, readonly string[]> = {
  lean4: ["propext", "Classical.choice", "Quot.sound"],
  rocq: [],
};

export interface ProofFile {
  path: string;
  checker: ProofChecker;
  /** The module the harness compiles it as. */
  module: string;
  /** Where its copy goes in the workspace, compiled under the module's name. */
  copy: string;
  theorems: { theorem: string; index: number }[];
}

/** The proofs a check compiles and the theorems the judge is asked about. */
export interface ProofProbe {
  nonce: string;
  files: ProofFile[];
  /** Theorems whose names the checker couldn't be asked about safely. */
  unaskable: { proof: string; theorem: string }[];
}

/** The proofs to check, from the claims' evidence: each file once, in order of first appearance. */
export function proofProbe(proofs: readonly ProofEvidence[], nonce = randomBytes(8).toString("hex")): ProofProbe {
  const files: ProofFile[] = [];
  const unaskable: ProofProbe["unaskable"] = [];
  let index = 0;
  for (const proof of proofs) {
    let file = files.find((f) => f.path === proof.proof);
    if (file && file.checker !== proof.checker) {
      throw new HarnessError(`Claims name ${proof.proof} for two checkers, ${file.checker} and ${proof.checker}`);
    }
    if (!file) {
      const compiled = moduleName(files.length);
      files.push((file = { path: proof.proof, checker: proof.checker, module: compiled, copy: `${COMPILE_DIR}/${compiled}${PROOF_FILE_EXTENSIONS[proof.checker]}`, theorems: [] }));
    }
    if (!THEOREM_NAMES[proof.checker].test(proof.theorem)) {
      unaskable.push({ proof: proof.proof, theorem: proof.theorem });
      continue;
    }
    if (!file.theorems.some((t) => t.theorem === proof.theorem)) file.theorems.push({ theorem: proof.theorem, index: index++ });
  }
  return { nonce, files, unaskable };
}

const marker = (nonce: string, what: string | number) => `sj_harness_${nonce}_${what}`;

/** Copies each proof file to where the first step compiles it, under its module's name. */
export async function placeProofs(workspace: string, probe: ProofProbe): Promise<void> {
  await mkdir(join(workspace, COMPILE_DIR), { recursive: true });
  for (const file of probe.files) {
    await copyFile(under(workspace, file.path), under(workspace, file.copy)).catch(() => {
      throw new HarnessError(`${file.path}, which a claim names, isn't in the bundle`);
    });
  }
}

/**
 * The first step's command: the one given, or each file's copy compiled with its checker, from
 * the folder the copies are in, after a line saying which version of each checker the image
 * has. Lean writes `<module>.olean`, Rocq `<module>.vo` under the logical name `SJ`. After each
 * file the harness notes the checker's exit status.
 */
export function compileCommand(probe: ProofProbe, given?: string): CommandPlan {
  const files = probe.files.map((file) => file.path);
  if (given) return { command: given, from: "given", files };
  if (files.length === 0) throw new HarnessError("No claim needing a verdict names a proof to check");
  const checkers = new Set(probe.files.map((file) => file.checker));
  const versions = [
    ...(checkers.has("lean4") ? [`echo "${marker(probe.nonce, "lean")} $(lean --version 2>&1 | head -n 1)"`] : []),
    ...(checkers.has("rocq") ? [`echo "${marker(probe.nonce, "rocq")} $( (rocq --version || coqc --version) 2>&1 | head -n 1)"`] : []),
  ];
  const steps = probe.files.map((file, f) => {
    const name = `${file.module}${PROOF_FILE_EXTENSIONS[file.checker]}`;
    const compile =
      file.checker === "lean4"
        ? `lean --root=. -o ${file.module}.olean ${name}`
        : `if command -v rocq >/dev/null 2>&1; then rocq compile -Q . SJ ${name}; else coqc -Q . SJ ${name}; fi`;
    return `(cd ${COMPILE_DIR} && ${compile}); echo "${marker(probe.nonce, `exit${f}`)} $?"`;
  });
  return { command: [...versions, ...steps].join("\n"), from: "checker", files };
}

/** A checker's error: where it points, and the first line of what it says. */
export interface CheckerError {
  path: string;
  line: number;
  message: string;
}

/**
 * Reads the first step's output as it streams, line by line and stream by stream: the
 * harness's markers and the checkers' errors, by the format each checker writes them in. Keeps
 * only what it needs, so output of any length fits.
 */
export class ProofOutput {
  /** Each file's checker exit status, when the harness's command ran it. */
  readonly exits = new Map<number, number>();
  /** What each checker said its version was; the work's own image says it, so it only picks the judge's. */
  readonly versions = new Map<ProofChecker, string>();
  readonly errors: CheckerError[] = [];
  private readonly partial = { stdout: "", stderr: "" };
  /** A Rocq location line, waiting for the line that says whether it is an error. */
  private readonly located = { stdout: null as { path: string; line: number } | null, stderr: null as { path: string; line: number } | null };
  private readonly token: RegExp;

  constructor(readonly probe: ProofProbe) {
    this.token = new RegExp(`^sj_harness_${probe.nonce}_(?:exit(\\d+) (\\d+)|(lean|rocq) (.*))$`);
  }

  write(chunk: Uint8Array | string, stream: "stdout" | "stderr" = "stdout"): void {
    const text = this.partial[stream] + (typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    const lines = text.split(/\r?\n/);
    this.partial[stream] = lines.pop()!;
    for (const line of lines) this.line(line, stream);
  }

  /** Reads what is left after the run ends. */
  end(): void {
    for (const stream of ["stdout", "stderr"] as const) {
      if (this.partial[stream]) this.line(this.partial[stream], stream);
      this.partial[stream] = "";
    }
  }

  private line(line: string, stream: "stdout" | "stderr"): void {
    const mark = this.token.exec(line);
    if (mark) {
      const [, exit, status, checker, version] = mark;
      if (exit !== undefined) this.exits.set(Number(exit), Number(status));
      else if (!this.versions.has(checker === "lean" ? "lean4" : "rocq")) this.versions.set(checker === "lean" ? "lean4" : "rocq", version.trim());
      return;
    }
    const lean = /^(.+?):(\d+):(\d+): error(?:\([^)]*\))?: (.*)$/.exec(line);
    if (lean) this.error({ path: lean[1], line: Number(lean[2]), message: lean[4] });
    const location = /^File "(.+?)", line (\d+), characters \d+-\d+:$/.exec(line);
    if (location) {
      this.located[stream] = { path: location[1], line: Number(location[2]) };
    } else if (this.located[stream] && /^(Error|Warning)\b/.test(line)) {
      if (line.startsWith("Error")) this.error({ ...this.located[stream]!, message: line.replace(/^Error:\s*/, "") });
      this.located[stream] = null;
    } else if (/^Error:/.test(line)) {
      // Rocq's errors at the end of a file come without a location.
      this.error({ path: "", line: 0, message: line.replace(/^Error:\s*/, "") });
    }
  }

  private error(error: CheckerError): void {
    if (this.errors.length < 200) this.errors.push({ ...error, path: error.path.replace(/^(\.\/)+/, "") });
  }
}

/** The judge's questions, one per theorem, by checker, with each theorem's index in the probe. */
export function judgeAsks(probe: ProofProbe, checker: ProofChecker): (JudgeAsk & { index: number })[] {
  return probe.files
    .filter((file) => file.checker === checker)
    .flatMap((file) => file.theorems.map((t) => ({ module: file.module, theorem: t.theorem, index: t.index })));
}

/** One theorem's check: what it rests on, and whether it passed. */
export interface CheckedTheorem {
  proof: string;
  theorem: string;
  checker: ProofChecker;
  status: "passed" | "failed" | "unknown";
  /** What the judge found it rests on; absent when the judge said nothing about it. */
  axioms?: string[];
  reason: string;
}

/**
 * Each theorem's result: failed when its file didn't compile; otherwise what the judge said,
 * passed only when the kernel accepted it and it rests on no more than the standard axioms.
 * `judged` holds the judge's answers by theorem index, and `judgeFailure` says why there are
 * none, when the judge couldn't run.
 */
export function checkTheorems(
  probe: ProofProbe,
  output: ProofOutput,
  exitCode: number | null,
  judged: ReadonlyMap<number, JudgeAnswer>,
  judgeFailure?: string,
): CheckedTheorem[] {
  output.end();
  const results: CheckedTheorem[] = probe.unaskable.map(({ proof, theorem }) => {
    const checker = probe.files.find((file) => file.path === proof)!.checker;
    return { proof, theorem, checker, status: "failed" as const, reason: `${theorem} isn't a name ${checkerName(checker)} can be asked about` };
  });
  for (const [f, file] of probe.files.entries()) {
    const errors = output.errors.filter(
      (error) => samePath(error.path, file.copy) || samePath(error.path, file.copy.slice(COMPILE_DIR.length + 1)) || (error.path === "" && file.checker === "rocq"),
    );
    const status = output.exits.get(f) ?? exitCode;
    const firstError = errors[0] && ` (line ${errors[0].line}: ${errors[0].message})`;
    for (const { theorem, index } of file.theorems) {
      const base = { proof: file.path, theorem, checker: file.checker };
      if (status === 126 || status === 127) {
        const what = status === 127 ? "isn't in the image" : "couldn't be executed";
        results.push({ ...base, status: "unknown", reason: `${checkerName(file.checker)}'s checker ${what} (exit status ${status}), so ${theorem} wasn't checked; give an image that has it with --image` });
        continue;
      }
      if (errors.length > 0 || (status !== null && status !== 0)) {
        const why = firstError ?? (status !== null ? ` (exit status ${status})` : "");
        results.push({ ...base, status: "failed", reason: `${checkerName(file.checker)} reported errors in ${file.path}${why}` });
        continue;
      }
      const answer = judged.get(index);
      if (!answer) {
        results.push({ ...base, status: "unknown", reason: judgeFailure ?? `the judge said nothing about ${theorem}` });
      } else if (answer.status !== "checked") {
        results.push({ ...base, status: answer.status, reason: answer.reason });
      } else {
        const axioms = answer.axioms.map((axiom) => ownName(axiom, file.module));
        const extra = axioms.filter((axiom) => !STANDARD_AXIOMS[file.checker].includes(axiom));
        results.push(
          extra.length > 0
            ? { ...base, status: "failed", axioms, reason: restsOn(file.checker, theorem, extra) }
            : { ...base, status: "passed", axioms, reason: `${checkerName(file.checker)} compiled ${file.path}, the kernel accepted ${theorem} again on its own, and it rests on no more than ${standard(file.checker)}` },
        );
      }
    }
  }
  return results;
}

/** An axiom's name as the proof file spells it, without the module path the harness gave the file. */
function ownName(axiom: string, module: string): string {
  for (const prefix of [`SJ.${module}.`, `${module}.`]) if (axiom.startsWith(prefix)) return axiom.slice(prefix.length);
  return axiom;
}

/** What a checker's answer says a theorem rests on, or null if it holds no answer. */
export function assumptions(checker: ProofChecker, lines: readonly string[]): string[] | null {
  if (checker === "lean4") {
    for (const line of lines) {
      const depends = /'(.+)' depends on axioms: \[(.*)\]/.exec(line);
      if (depends) return depends[2].split(",").map((axiom) => axiom.trim()).filter(Boolean);
      if (/'(.+)' does not depend on any axioms/.test(line)) return [];
    }
    return null;
  }
  // Rocq: "Closed under the global context", or headed sections such as "Axioms:" listing
  // `name : type`, where a type too long for one line continues on indented lines.
  let found: string[] | null = null;
  let inSection = false;
  for (const line of lines) {
    if (line.trim() === "Closed under the global context") return [];
    if (/^[A-Z][A-Za-z ]*:$/.test(line)) {
      inSection = true;
      found ??= [];
      continue;
    }
    const entry = /^(\S+) :(?:\s|$)/.exec(line);
    if (inSection && entry) found!.push(entry[1]);
  }
  return found;
}

function restsOn(checker: ProofChecker, theorem: string, extra: string[]): string {
  if (checker === "lean4" && extra.includes("sorryAx")) {
    const others = extra.filter((axiom) => axiom !== "sorryAx");
    return `${theorem} rests on sorryAx, an unfinished proof${others.length > 0 ? `, and on ${others.join(", ")}` : ""}`;
  }
  if (extra.includes(theorem) || extra.some((axiom) => theorem.endsWith(`.${axiom}`))) {
    return `${theorem} is itself assumed, not proved (Admitted)${extra.length > 1 ? `, and rests on ${extra.join(", ")}` : ""}`;
  }
  return `${theorem} rests on ${extra.join(", ")}, beyond ${standard(checker)}`;
}

function standard(checker: ProofChecker): string {
  return checker === "lean4" ? `Lean's standard axioms (${STANDARD_AXIOMS.lean4.join(", ")})` : "Rocq's own foundations, which assume no axioms";
}

function checkerName(checker: ProofChecker): string {
  return checker === "lean4" ? "Lean" : "Rocq";
}

/** Whether a path a checker printed names the file `path`, from whatever directory it ran in. */
function samePath(printed: string, path: string): boolean {
  if (!printed) return false;
  const a = printed.split("/").filter((part) => part !== "" && part !== ".");
  const b = path.split("/");
  const shorter = a.length <= b.length ? a : b;
  const longer = a.length <= b.length ? b : a;
  return shorter.length > 0 && shorter.every((part, i) => longer[longer.length - shorter.length + i] === part);
}

/**
 * Where the bundle's proofs use their checker's unfinished-proof keywords: every file under
 * proofs/ in the language of a checker the claims name. Information only; what each theorem
 * rests on is what decides.
 */
export async function findUnfinished(
  bundleDir: string,
  paths: Iterable<string>,
  checkers: Iterable<ProofChecker>,
): Promise<(UnfinishedProof & { path: string })[]> {
  const found: (UnfinishedProof & { path: string })[] = [];
  const wanted = [...new Set(checkers)];
  for (const path of [...paths].sort()) {
    if (!path.startsWith("proofs/")) continue;
    for (const checker of wanted) {
      if (!path.endsWith(PROOF_FILE_EXTENSIONS[checker])) continue;
      const text = await readFile(under(bundleDir, path), "utf8").catch(() => null);
      if (text !== null) for (const proof of unfinishedProofs(checker, text)) found.push({ path, ...proof });
    }
  }
  return found;
}
