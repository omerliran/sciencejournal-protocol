import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import type { ProofEvidence } from "../claims";
import { PROOF_FILE_EXTENSIONS, unfinishedProofs, type UnfinishedProof } from "../proofs";
import type { ProofChecker } from "../vocabulary";
import { HarnessError } from "./context";
import { under } from "./files";
import { shellQuote } from "./format";
import type { CommandPlan } from "./sandbox";

// Proof checks. The checker runs on each proof file in the sandbox, and the harness asks it, at
// the end of its own copy of the file, what each named theorem rests on: Lean's `#print axioms`,
// Rocq's `Print Assumptions`. A theorem passes when the checker accepts its file and it rests on
// nothing beyond the checker's standard axioms. Each question is preceded by a marker holding a
// fresh random nonce, so a report counts only if it follows the harness's own question; a proof
// file runs code while it is checked and can print anything, but it can't know the nonce
// without reading its own copy, which is a deliberate attack the log shows. The agent decides.

/** The axioms each checker's foundations assume. Anything else, `sorryAx` included, is an assumption. */
export const STANDARD_AXIOMS: Record<ProofChecker, readonly string[]> = {
  lean4: ["propext", "Classical.choice", "Quot.sound"],
  rocq: [],
};

const NAMES: Record<ProofChecker, RegExp> = {
  // Lean names: parts of letters, digits, `_`, `'`, `!`, `?`, or «quoted», joined by dots.
  lean4: /^(?:«[^»\n]+»|[\p{L}_][\p{L}\p{N}_'!?]*)(?:\.(?:«[^»\n]+»|[\p{L}_][\p{L}\p{N}_'!?]*))*$/u,
  // Rocq names: identifiers of letters, digits, `_`, and `'`, joined by dots.
  rocq: /^[\p{L}_][\p{L}\p{N}_']*(?:\.[\p{L}_][\p{L}\p{N}_']*)*$/u,
};

export interface ProofFile {
  path: string;
  checker: ProofChecker;
  /** Lines in the file as published; the harness's questions come after them. */
  lines: number;
  theorems: { theorem: string; index: number; line: number }[];
}

/** The questions the harness asks a run, and how to recognize the answers. */
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
    if (!file) files.push((file = { path: proof.proof, checker: proof.checker, lines: 0, theorems: [] }));
    if (!NAMES[proof.checker].test(proof.theorem)) {
      unaskable.push({ proof: proof.proof, theorem: proof.theorem });
      continue;
    }
    if (!file.theorems.some((t) => t.theorem === proof.theorem)) file.theorems.push({ theorem: proof.theorem, index: index++, line: 0 });
  }
  return { nonce, files, unaskable };
}

const marker = (nonce: string, what: string | number) => `sj_harness_${nonce}_${what}`;

/**
 * Adds the harness's questions to the end of each proof file in the workspace, and records the
 * lines they are on, so the checker's errors there are known to be about them.
 */
export async function askAboutTheorems(workspace: string, probe: ProofProbe): Promise<void> {
  for (const [f, file] of probe.files.entries()) {
    const target = under(workspace, file.path);
    let text = await readFile(target, "utf8").catch(() => {
      throw new HarnessError(`${file.path}, which a claim names, isn't in the bundle`);
    });
    if (!text.endsWith("\n")) text += "\n";
    file.lines = text.split("\n").length - 1;
    const lines: string[] = [""];
    for (const theorem of file.theorems) {
      const name = marker(probe.nonce, theorem.index);
      if (file.checker === "lean4") {
        lines.push(`#print "${name}"`);
        theorem.line = file.lines + lines.length + 1;
        lines.push(`#print axioms ${theorem.theorem}`);
      } else {
        lines.push(`Definition ${name} := Prop.`, `Print ${name}.`);
        theorem.line = file.lines + lines.length + 1;
        lines.push(`Print Assumptions ${theorem.theorem}.`);
      }
    }
    const end = marker(probe.nonce, `end${f}`);
    lines.push(...(file.checker === "lean4" ? [`#print "${end}"`] : [`Definition ${end} := Prop.`, `Print ${end}.`]));
    await writeFile(target, `${text}${lines.join("\n")}\n`);
  }
}

/**
 * The command that checks every proof file: the one given, or each file with its checker, from
 * the bundle's root: `lean` for Lean 4, and `rocq compile` for Rocq, or `coqc` where the image
 * has Coq's older name for it. After each file the harness notes the checker's exit status.
 */
export function proofCommand(probe: ProofProbe, given?: string): CommandPlan {
  const files = probe.files.map((file) => file.path);
  if (given) return { command: given, from: "given", files };
  if (files.length === 0) throw new HarnessError("No claim needing a verdict names a proof to check");
  const steps = probe.files.map((file, f) => {
    const path = shellQuote(file.path);
    const check =
      file.checker === "lean4"
        ? `lean ${path}`
        : `if command -v rocq >/dev/null 2>&1; then rocq compile ${path}; else coqc ${path}; fi`;
    return `${check}; echo "${marker(probe.nonce, `exit${f}`)} $?"`;
  });
  return { command: steps.join("\n"), from: "checker", files };
}

/** A checker's error: where it points, and the first line of what it says. */
export interface CheckerError {
  path: string;
  line: number;
  message: string;
}

/**
 * Reads a run's output as it streams, line by line and stream by stream: the harness's markers,
 * what follows each question, and the checkers' errors, by the format each checker writes them
 * in. Keeps only what it needs, so output of any length fits.
 */
export class ProofOutput {
  /** The lines that followed each question, by theorem index. */
  readonly answers = new Map<number, string[]>();
  /** Files whose end marker printed: the checker reached every question in them. */
  readonly ended = new Set<number>();
  /** Each file's checker exit status, when the harness's command ran it. */
  readonly exits = new Map<number, number>();
  readonly errors: CheckerError[] = [];
  private readonly partial = { stdout: "", stderr: "" };
  private readonly current = { stdout: null as number | null, stderr: null as number | null };
  /** A Rocq location line, waiting for the line that says whether it is an error. */
  private readonly located = { stdout: null as { path: string; line: number } | null, stderr: null as { path: string; line: number } | null };
  private readonly token: RegExp;

  constructor(readonly probe: ProofProbe) {
    this.token = new RegExp(`sj_harness_${probe.nonce}_(\\d+|end(\\d+)|exit(\\d+))\\b(?:\\s+(\\d+))?`);
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
      const [, what, end, exit, status] = mark;
      if (end !== undefined) {
        this.ended.add(Number(end));
        this.current[stream] = null;
      } else if (exit !== undefined) {
        if (status !== undefined) this.exits.set(Number(exit), Number(status));
      } else {
        this.current[stream] = Number(what);
        this.answers.set(Number(what), []);
      }
      return;
    }
    const lean = /^(.+?):(\d+):(\d+): error: (.*)$/.exec(line);
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
    const answering = this.current[stream];
    if (answering !== null) {
      const lines = this.answers.get(answering)!;
      if (lines.length < 400) lines.push(line);
    }
  }

  private error(error: CheckerError): void {
    if (this.errors.length < 200) this.errors.push({ ...error, path: error.path.replace(/^(\.\/)+/, "") });
  }
}

/** One theorem's check: what it rests on, and whether it passed. */
export interface CheckedTheorem {
  proof: string;
  theorem: string;
  checker: ProofChecker;
  status: "passed" | "failed" | "unknown";
  /** What the checker said it rests on; absent when it said nothing. */
  axioms?: string[];
  reason: string;
}

/**
 * Each theorem's result, from what the checker said after the harness's question, the errors it
 * reported in the theorem's file, and the file's exit status.
 */
export function checkTheorems(probe: ProofProbe, output: ProofOutput, exitCode: number | null): CheckedTheorem[] {
  output.end();
  const results: CheckedTheorem[] = probe.unaskable.map(({ proof, theorem }) => {
    const checker = probe.files.find((file) => file.path === proof)!.checker;
    return { proof, theorem, checker, status: "failed" as const, reason: `${theorem} isn't a name ${checkerName(checker)} can be asked about` };
  });
  for (const [f, file] of probe.files.entries()) {
    const errors = output.errors.filter((error) => samePath(error.path, file.path) || (error.path === "" && file.checker === "rocq"));
    const inFile = errors.filter((error) => error.line <= file.lines);
    const atQuestions = errors.filter((error) => error.line > file.lines);
    const status = output.exits.get(f) ?? exitCode;
    // A question about a theorem that isn't there makes the checker exit nonzero; that says
    // nothing about the file itself, whose own errors are the ones within its lines.
    const fileFailed = inFile.length > 0 || (status !== null && status !== 0 && atQuestions.length === 0);
    const firstError = inFile[0] && ` (line ${inFile[0].line}: ${inFile[0].message})`;
    for (const { theorem, index, line } of file.theorems) {
      const base = { proof: file.path, theorem, checker: file.checker };
      if (status === 126 || status === 127) {
        const what = status === 127 ? "isn't in the image" : "couldn't be executed";
        results.push({ ...base, status: "unknown", reason: `${checkerName(file.checker)}'s checker ${what} (exit status ${status}), so ${theorem} wasn't checked; give an image that has it with --image` });
        continue;
      }
      const axioms = output.answers.has(index) ? assumptions(file.checker, output.answers.get(index)!) : null;
      if (axioms) {
        const extra = axioms.filter((axiom) => !STANDARD_AXIOMS[file.checker].includes(axiom));
        if (extra.length > 0) {
          results.push({ ...base, status: "failed", axioms, reason: restsOn(file.checker, theorem, extra) });
        } else if (fileFailed) {
          const why = firstError ?? (status !== null ? ` (exit status ${status})` : "");
          results.push({ ...base, status: "failed", axioms, reason: `${theorem} rests on no more than ${standard(file.checker)}, but the checker reported errors in ${file.path}${why}` });
        } else {
          results.push({ ...base, status: "passed", axioms, reason: `${checkerName(file.checker)} accepted ${file.path}, and ${theorem} rests on no more than ${standard(file.checker)}` });
        }
        continue;
      }
      const asked = errors.find((error) => error.line === line);
      if (asked) {
        results.push({ ...base, status: "failed", reason: `${checkerName(file.checker)} couldn't find ${theorem}: ${asked.message}` });
      } else if (inFile.length > 0) {
        results.push({ ...base, status: "failed", reason: `${checkerName(file.checker)} reported errors in ${file.path} before reaching ${theorem}${firstError}` });
      } else if (atQuestions.some((error) => error.line < line)) {
        // Rocq stops at its first error, so an earlier question that failed ends the file's checks.
        const earlier = atQuestions.find((error) => error.line < line)!;
        results.push({
          ...base,
          status: "unknown",
          reason: `${checkerName(file.checker)} stopped at an earlier question in ${file.path} (${earlier.message}) before the harness could ask about ${theorem}; check it again without the theorem it couldn't find`,
        });
      } else if (status === 0 && !output.ended.has(f)) {
        results.push({
          ...base,
          status: "failed",
          reason: `${checkerName(file.checker)} accepted ${file.path} but stopped before the harness's questions at its end (look for something like #exit), so it never reported on ${theorem}`,
        });
      } else {
        const elsewhere = output.errors[0] ? `; its first error: ${output.errors[0].message}` : "";
        results.push({
          ...base,
          status: "unknown",
          reason: `${checkerName(file.checker)} never reported on ${theorem}, and showed no error in ${file.path}${elsewhere}; see run.log`,
        });
      }
    }
  }
  return results;
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

/** Whether a path a checker printed names the bundle file `path`, from whatever directory it ran in. */
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
