import { randomBytes } from "node:crypto";
import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { canonicalDigest } from "../hash";
import { THEOREM_NAMES, theoremNameParts } from "../proofs";
import type { ProofChecker } from "../vocabulary";
import { HarnessError } from "./context";
import { exists, removeTree, type LogTail } from "./files";
import { shellQuote } from "./format";
import type { ImageInfo, Limits, RunResult, Sandbox } from "./sandbox";
import { ImageError } from "./sandbox";
import { HARNESS } from "./version";

// The judge. A proof file runs code while its checker reads it, so nothing that run prints can
// decide a proof check: a file can take over the checker's own commands and print whatever a
// clean answer looks like. So a proof check runs in two steps. The first compiles each proof
// file, in whatever image the work declares. The second, the judge, runs in a fresh container
// built from nothing but the pinned checker, and is given only the compiled files. It runs none
// of their code: it replays every declaration they hold through the checker's kernel, finds the
// theorems it was asked about, and works out what each rests on itself. Only the judge's answer
// is a verdict.

/** Where the first step puts each proof file's copy, and the compiled result, in the workspace. */
export const COMPILE_DIR = ".sj-proofs";
/** Where the judge's workspace holds the judge's own program and the compiled files it is given. */
export const JUDGE_DIR = "judge";
export const COMPILED_DIR = "compiled";

/** The module name each proof file is compiled under: chosen by the harness, so none can stand in for a library's. */
export function moduleName(index: number): string {
  return `SJProof${index}`;
}

const LEAN_TOOLCHAIN = /^leanprover\/lean4:v\d+\.\d+\.\d+(?:-rc\d+)?$/;
const MATHLIB_REV = /^[0-9a-f]{40}$/;
const ROCQ_VERSION = /^\d+\.\d+(?:\.\d+)?$/;

/** A Lean toolchain, as a `lean-toolchain` file names it, or null when the text isn't one. */
export function leanToolchain(text: string): string | null {
  const line = text.trim();
  return LEAN_TOOLCHAIN.test(line) ? line : null;
}

/** The toolchain a `lean --version` line reports, or null. */
export function leanToolchainOfVersion(output: string): string | null {
  const version = /Lean \(version (\d+\.\d+\.\d+(?:-rc\d+)?)[,)]/.exec(output)?.[1];
  return version ? `leanprover/lean4:v${version}` : null;
}

/** The version a `rocq --version` or `coqc --version` line reports, or null. */
export function rocqVersionOf(output: string): string | null {
  const version = /(?:Rocq Prover|Coq Proof Assistant), version (\d+\.\d+(?:\.\d+)?)/.exec(output)?.[1];
  return version ?? null;
}

/**
 * The official image of a Rocq or Coq release. Rocq's images are tagged by release, with a
 * release's first patch tagged by its minor version alone (9.1, not 9.1.0); Coq's live under its
 * old name.
 */
export function rocqImage(version: string): string {
  if (!ROCQ_VERSION.test(version)) throw new HarnessError(`${version} isn't a Rocq release`);
  const tag = version.replace(/^(\d+\.\d+)\.0$/, "$1");
  return Number(version.split(".")[0]) >= 9 ? `rocq/rocq-prover:${tag}` : `coqorg/coq:${tag}`;
}

/** The judge's image: the pinned checker and, for Lean, Mathlib at a pinned commit if the work needs it. */
export type JudgeImage = { checker: "lean4"; toolchain: string; mathlib?: string } | { checker: "rocq"; version: string };

/** Elan's directory for a toolchain: `leanprover/lean4:v4.34.1` is `leanprover--lean4---v4.34.1`. */
function elanDirectory(toolchain: string): string {
  return toolchain.replace("/", "--").replace(":", "---");
}

/** Where the judge's Lean image keeps the search path for the libraries it holds. */
export const LEAN_PATH_FILE = "/opt/sj-lean/lean-path";

/**
 * The Dockerfile of the judge's Lean image: Debian, elan, and the one toolchain, with its own
 * binaries first on the path so nothing runs through elan's proxy; and, when asked, a Lake
 * project that requires Mathlib at one commit and fetches its compiled library.
 */
export function judgeDockerfile(image: Extract<JudgeImage, { checker: "lean4" }>): string {
  if (!LEAN_TOOLCHAIN.test(image.toolchain)) throw new HarnessError(`${image.toolchain} isn't a Lean toolchain`);
  if (image.mathlib !== undefined && !MATHLIB_REV.test(image.mathlib)) throw new HarnessError(`${image.mathlib} isn't a Mathlib commit`);
  const library = image.mathlib
    ? [
        `RUN printf '%s\\n' 'name = "sjjudge"' '' '[[require]]' 'name = "mathlib"' 'git = "https://github.com/leanprover-community/mathlib4"' 'rev = "${image.mathlib}"' > lakefile.toml \\`,
        ` && echo '${image.toolchain}' > lean-toolchain \\`,
        " && lake update && lake exe cache get \\",
        ` && lake env printenv LEAN_PATH > ${LEAN_PATH_FILE} \\`,
        " && chmod -R a+rX /opt/sj-lean",
      ]
    : [`RUN : > ${LEAN_PATH_FILE} && chmod -R a+rX /opt/sj-lean`];
  return [
    "FROM public.ecr.aws/docker/library/debian:bookworm-slim",
    "RUN apt-get update \\",
    " && apt-get install -y --no-install-recommends ca-certificates curl git \\",
    " && rm -rf /var/lib/apt/lists/*",
    "ENV ELAN_HOME=/opt/elan",
    "RUN curl -sSfL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \\",
    `      | sh -s -- -y --no-modify-path --default-toolchain ${image.toolchain} \\`,
    " && chmod -R a+rX /opt/elan",
    `ENV PATH=/opt/elan/toolchains/${elanDirectory(image.toolchain)}/bin:/opt/elan/bin:$PATH`,
    "WORKDIR /opt/sj-lean",
    ...library,
    "WORKDIR /",
    "RUN lean --version",
    "",
  ].join("\n");
}

/** One theorem the judge is asked about: the module that must declare it, and what its type must be, if anything. */
export interface JudgeAsk {
  module: string;
  theorem: string;
  /** For a goal: the constant, from the statement module, that the theorem's type must be exactly. */
  states?: { module: string; name: string };
}

/** What the judge said about one theorem. */
export interface JudgeAnswer {
  status: "checked" | "failed" | "unknown";
  reason: string;
  axioms: string[];
}

/** The judge's command for Lean: its program, run by the image's own `lean`, with the compiled files last on the search path. */
export function leanJudgeCommand(asks: readonly JudgeAsk[]): string {
  const request = {
    out: `/work/${COMPILED_DIR}`,
    asks: asks.map((ask) => ({
      module: ask.module,
      theorem: leanParts(ask.theorem),
      ...(ask.states && { states: { module: ask.states.module, name: leanParts(ask.states.name) } }),
    })),
  };
  return `LEAN_PATH="$(cat ${LEAN_PATH_FILE})" lean --run ${JUDGE_DIR}/Judge.lean ${shellQuote(JSON.stringify(request))}`;
}

function leanParts(name: string): string[] {
  if (!THEOREM_NAMES.lean4.test(name)) throw new HarnessError(`${name} isn't a Lean name`);
  return theoremNameParts(name);
}

/** A marker the Rocq judge prints before each question, so each answer is read as the one it follows. */
export const ROCQ_MARKER = "sj_judge";

/**
 * The judge's commands for Rocq: the image's own independent checker re-checks every compiled
 * file, and a fresh Rocq that loads them, and nothing of the work's own plugins, says what each
 * theorem rests on.
 */
export function rocqJudgeCommand(asks: readonly JudgeAsk[]): string {
  const modules = [...new Set(asks.map((ask) => ask.module))];
  const questions = [
    ...modules.map((module) => `Require SJ.${module}.`),
    ...asks.flatMap((ask, i) => {
      if (!THEOREM_NAMES.rocq.test(ask.theorem)) throw new HarnessError(`${ask.theorem} isn't a Rocq name`);
      return [`Definition ${ROCQ_MARKER}_${i} := Prop.`, `Print ${ROCQ_MARKER}_${i}.`, `Print Assumptions SJ.${ask.module}.${ask.theorem}.`];
    }),
    `Definition ${ROCQ_MARKER}_end := Prop.`,
    `Print ${ROCQ_MARKER}_end.`,
  ];
  const checker = 'if command -v rocqchk >/dev/null 2>&1; then echo rocqchk; else echo coqchk; fi';
  const repl = 'if command -v rocq >/dev/null 2>&1; then echo "rocq repl"; else echo coqtop; fi';
  return [
    `cd ${COMPILED_DIR}`,
    `$(${checker}) -silent -o -Q . SJ ${modules.map((module) => `SJ.${module}`).join(" ")}; echo "${ROCQ_MARKER}_checked $?"`,
    `printf '%s\\n' ${questions.map(shellQuote).join(" ")} | $(${repl}) -q -Q . SJ`,
  ].join("\n");
}

/**
 * Reads the Lean judge's answers, one JSON line each after `sj-judge `. The judge runs none of
 * the work's code, so what it prints is the judge's own.
 */
export function readLeanJudge(output: string, asks: readonly JudgeAsk[]): JudgeAnswer[] {
  const answers: (JudgeAnswer | undefined)[] = asks.map(() => undefined);
  for (const line of output.split(/\r?\n/)) {
    if (!line.startsWith("sj-judge ")) continue;
    try {
      const said = JSON.parse(line.slice("sj-judge ".length)) as { ask: number; status: string; reason: string; axioms: string[] };
      if (!Number.isInteger(said.ask) || said.ask < 0 || said.ask >= asks.length) continue;
      if (said.status !== "checked" && said.status !== "failed" && said.status !== "unknown") continue;
      answers[said.ask] = { status: said.status, reason: String(said.reason), axioms: Array.isArray(said.axioms) ? said.axioms.map(String) : [] };
    } catch {
      continue;
    }
  }
  return answers.map((answer) => answer ?? { status: "unknown", reason: "the judge didn't answer; see judge.log", axioms: [] });
}

/**
 * Reads the Rocq judge's answers: whether the independent checker accepted every compiled file,
 * then what follows each marker, read as `Print Assumptions` writes it.
 */
export function readRocqJudge(output: string, asks: readonly JudgeAsk[], assumptions: (lines: string[]) => string[] | null): JudgeAnswer[] {
  const checked = new RegExp(`^${ROCQ_MARKER}_checked (\\d+)$`);
  const marker = new RegExp(`^${ROCQ_MARKER}_(\\d+|end) =`);
  let accepted: boolean | null = null;
  const sections = new Map<number, string[]>();
  let current: number | null = null;
  for (const raw of output.split(/\r?\n/)) {
    const line = raw.replace(/^(Rocq|Coq) < /, "");
    const status = checked.exec(line);
    if (status) {
      accepted = status[1] === "0";
      continue;
    }
    const mark = marker.exec(line);
    if (mark) {
      current = mark[1] === "end" ? null : Number(mark[1]);
      if (current !== null) sections.set(current, []);
      continue;
    }
    if (current !== null) sections.get(current)!.push(line);
  }
  return asks.map((ask, i) => {
    if (accepted === null) return { status: "unknown", reason: "the independent checker didn't run; see judge.log", axioms: [] };
    if (!accepted) return { status: "failed", reason: "the independent checker rejected the compiled proof; see judge.log", axioms: [] };
    const lines = sections.get(i);
    if (!lines) return { status: "unknown", reason: "the judge never reached the question; see judge.log", axioms: [] };
    if (lines.some((line) => /^Error:/.test(line.trim()))) return { status: "failed", reason: `${ask.theorem} isn't in the compiled proof`, axioms: [] };
    const axioms = assumptions(lines.filter((line) => !/^Fetching opaque proofs/.test(line)));
    if (axioms === null) return { status: "unknown", reason: `the judge said nothing it recognizes about ${ask.theorem}; see judge.log`, axioms: [] };
    // Rocq names an axiom of the proof's own module by its short path; the judge loaded it as SJ.<module>.
    return { status: "checked", reason: `the independent checker accepted ${ask.theorem}`, axioms };
  });
}

/** How the judge ran, for the record. */
export interface JudgeRun {
  checker: ProofChecker;
  image?: ImageInfo;
  command?: string;
  limits?: Limits;
  result?: RunResult;
  /** Why the judge didn't run, or didn't finish. */
  failure?: string;
}

/** The name the judge's image is kept under, so it is built once for each toolchain. */
export function judgeImageKey(image: JudgeImage): string {
  return canonicalDigest({ harness: HARNESS, plan: { from: "judge", image } }).slice("sha256:".length, "sha256:".length + 16);
}

/** The most of the judge's output kept to read its answers from. */
const JUDGE_OUTPUT_BYTES = 8 * 1024 * 1024;

/**
 * Runs the judge on compiled files: prepares its image, gives a fresh workspace nothing but the
 * judge's own program and the compiled files named, runs it with no network, and reads its
 * answers. Answers are null when the judge couldn't run or didn't finish, and the run says why.
 */
export async function runJudge(
  box: Sandbox,
  request: {
    image: JudgeImage;
    asks: readonly JudgeAsk[];
    /** Each compiled file to give the judge: its path now, and its name in the judge's `compiled/`. */
    compiled: readonly { from: string; name: string }[];
    /** A directory of the judge's own, which is gone when it returns. */
    dir: string;
    limits: Limits;
    /** Reads what Rocq's `Print Assumptions` wrote. */
    assumptions: (lines: string[]) => string[] | null;
  },
  log: LogTail,
  print: (line: string) => void,
): Promise<{ answers: JudgeAnswer[] | null; run: JudgeRun }> {
  const { image, asks, dir, limits } = request;
  const run: JudgeRun = { checker: image.checker, limits };
  const workspace = join(dir, `work-${randomBytes(6).toString("hex")}`);
  try {
    const plan = { from: "judge" as const, image };
    const key = judgeImageKey(image);
    print(`Preparing the judge's image for ${image.checker === "lean4" ? image.toolchain : `Rocq ${image.version}`}.`);
    try {
      run.image = await box.image(plan, { workspace, scratch: join(dir, ".build"), key }, log);
    } catch (error) {
      if (!(error instanceof ImageError)) throw error;
      run.failure = `The judge's image couldn't be prepared: ${error.message}`;
      return { answers: null, run };
    }
    await mkdir(join(workspace, JUDGE_DIR), { recursive: true });
    await mkdir(join(workspace, COMPILED_DIR), { recursive: true });
    if (image.checker === "lean4") await writeFile(join(workspace, JUDGE_DIR, "Judge.lean"), LEAN_JUDGE);
    for (const file of request.compiled) {
      if (!/^[A-Za-z0-9_.]+$/.test(file.name)) throw new HarnessError(`${file.name} isn't a name the judge gives a compiled file`);
      if (await exists(file.from)) await copyFile(file.from, join(workspace, COMPILED_DIR, file.name));
    }
    run.command = image.checker === "lean4" ? leanJudgeCommand(asks) : rocqJudgeCommand(asks);
    let output = "";
    const sink = {
      write(chunk: Uint8Array | string) {
        log.write(chunk);
        if (output.length < JUDGE_OUTPUT_BYTES) output += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
      },
    };
    print(`Running the judge in ${box.engine.name}, with no network, on the compiled proofs alone.`);
    run.result = await box.run({ image: run.image, workspace, command: run.command, limits }, sink);
    if (run.result.timedOut) run.failure = `The judge passed its time limit of ${limits.minutes} minutes and was stopped.`;
    else if (run.result.outOfMemory) run.failure = `The judge ran out of memory, at its limit of ${limits.memory}.`;
    if (run.failure) return { answers: null, run };
    const answers = image.checker === "lean4" ? readLeanJudge(output, asks) : readRocqJudge(output, asks, request.assumptions);
    return { answers, run };
  } finally {
    await removeTree(dir);
  }
}

/** The checker a proof file's judge runs, by the file's checker. */
export function judgeChecker(checker: ProofChecker): string {
  return checker === "lean4" ? "Lean's kernel, replaying every declaration" : "rocqchk, Rocq's independent checker";
}

/**
 * The judge's Lean program. It is the harness's own and never changes with the work: it reads
 * the compiled modules it is asked about, replays each one's declarations through the kernel on
 * top of what the module imports (as leanchecker does), and answers for each theorem, as a JSON
 * line, whether the kernel accepted it, whether it is declared in the module named and states
 * exactly what it must, and which axioms it rests on, found by walking the constants it uses
 * rather than from anything a module recorded about itself. Loading compiled modules this way
 * runs none of their code: no initializer runs, and no environment extension is loaded.
 */
export const LEAN_JUDGE = String.raw`import Lean.CoreM
import Lean.Replay
import Lean.Data.Json

open Lean

unsafe def moduleParts (module : Name) : IO (Array (ModuleData × CompactedRegion)) := do
  let file ← findOLean module
  unless (← file.pathExists) do throw <| IO.userError s!"{module} wasn't compiled"
  let mut files := #[file]
  let server := OLeanLevel.server.adjustFileName file
  if (← server.pathExists) then
    files := files.push server
    let priv := OLeanLevel.private.adjustFileName file
    if (← priv.pathExists) then files := files.push priv
  readModuleDataParts files

/-- What the kernel rejected in a module, if anything; throws when the module can't be loaded at all. -/
unsafe def replayModule (module : Name) : IO (Option String) := do
  let parts ← moduleParts module
  if h : parts.size = 0 then throw <| IO.userError s!"{module} holds nothing" else
  let (data, _) := parts[0]
  let (_, s) ← importModulesCore data.imports |>.run
  let env ← finalizeImport s data.imports {} 0 false false (isModule := true)
  let mut constants := {}
  for name in parts[parts.size-1].1.constNames, info in parts[parts.size-1].1.constants do
    constants := constants.insert name info
  try
    discard <| env.toKernelEnv.replay constants
    return none
  catch e => return some (toString e)
  finally env.freeRegions

partial def axiomsOf (env : Environment) (root : Name) : Array Name := Id.run do
  let mut seen : NameSet := {}
  let mut todo := #[root]
  let mut found : NameSet := {}
  while h : todo.size > 0 do
    let c := todo[todo.size - 1]
    todo := todo.pop
    if seen.contains c then continue
    seen := seen.insert c
    let uses (e : Expr) := e.getUsedConstants
    match env.find? c with
    | some (.axiomInfo v) => found := found.insert c; todo := todo ++ uses v.type
    | some (.defnInfo v) => todo := todo ++ uses v.type ++ uses v.value
    | some (.thmInfo v) => todo := todo ++ uses v.type ++ uses v.value
    | some (.opaqueInfo v) => todo := todo ++ uses v.type ++ uses v.value
    | some (.quotInfo _) => pure ()
    | some (.ctorInfo v) => todo := todo ++ uses v.type
    | some (.recInfo v) => todo := todo ++ uses v.type
    | some (.inductInfo v) => todo := todo ++ uses v.type ++ v.ctors.toArray
    | none => found := found.insert c
  return found.toArray.qsort Name.lt

def nameOf (parts : Array Json) : Except String Name :=
  parts.foldlM (init := Name.anonymous) fun n part => do
    let s ← part.getStr?
    if s.isEmpty then throw "an empty name part" else pure (Name.mkStr n s)

def say (ask : Nat) (status : String) (reason : String) (axioms : Array Name := #[]) : IO Unit :=
  IO.println <| "sj-judge " ++ (Json.mkObj [
    ("ask", toJson ask), ("status", toJson status), ("reason", toJson reason),
    ("axioms", toJson (axioms.map toString))]).compress

structure Ask where
  module : Name
  thm : Name
  states : Option (Name × Name)

def parseAsk (j : Json) : Except String Ask := do
  let module := (← j.getObjValAs? String "module").toName
  let thm ← nameOf (← j.getObjValAs? (Array Json) "theorem")
  let states ← match j.getObjVal? "states" with
    | .ok s => pure (some ((← s.getObjValAs? String "module").toName, ← nameOf (← s.getObjValAs? (Array Json) "name")))
    | .error _ => pure none
  return { module, thm, states }

unsafe def main (args : List String) : IO UInt32 := do
  let [request] := args | IO.eprintln "The judge takes one JSON argument."; return 2
  let some (out, asks) := (do
      let j ← Json.parse request
      let out ← j.getObjValAs? String "out"
      let asks ← (← j.getObjValAs? (Array Json) "asks").mapM parseAsk
      return (out, asks) : Except String _).toOption
    | IO.eprintln "The judge's request isn't what it expects."; return 2
  initSearchPath (← findSysroot)
  searchPathRef.modify (· ++ [System.FilePath.mk out])
  let mut modules : Array Name := #[]
  for ask in asks do
    unless modules.contains ask.module do modules := modules.push ask.module
    if let some (m, _) := ask.states then unless modules.contains m do modules := modules.push m
  let mut rejected : NameMap String := {}
  let mut unloadable : NameMap String := {}
  for m in modules do
    try
      if let some why ← replayModule m then rejected := rejected.insert m why
    catch e => unloadable := unloadable.insert m (toString e)
  -- Each proof is read on its own, with only the statement it must prove beside it.
  for ask in asks, i in [0:asks.size] do
    let involved := ask.module :: (ask.states.map (·.1)).toList
    if let some why := involved.findSome? unloadable.find? then
      say i "unknown" s!"the compiled proof couldn't be loaded: {why}"; continue
    if let some why := involved.findSome? rejected.find? then
      say i "failed" s!"the kernel rejected a declaration: {why}"; continue
    let env? ← (try pure (some (← importModules (involved.toArray.map ({ module := · })) {} 0 (loadExts := false)))
      catch _ => pure none)
    let some env := env? | say i "unknown" "the compiled proof couldn't be loaded beside its statement"; continue
    let some info := env.find? ask.thm | say i "failed" s!"{ask.thm} isn't in the compiled proof"; continue
    unless env.getModuleIdxFor? ask.thm == env.getModuleIdx? ask.module do
      say i "failed" s!"{ask.thm} isn't declared in the proof itself"; continue
    unless info matches .thmInfo _ do say i "failed" s!"{ask.thm} isn't a theorem"; continue
    if let some (m, stmt) := ask.states then
      let some s := env.find? stmt | say i "failed" s!"{stmt} isn't in the statement"; continue
      unless env.getModuleIdxFor? stmt == env.getModuleIdx? m do
        say i "failed" s!"{stmt} doesn't come from the statement"; continue
      let expected := mkConst stmt (info.levelParams.map mkLevelParam)
      unless info.type == expected && s.levelParams.length == info.levelParams.length do
        say i "failed" s!"{ask.thm} states something other than the goal"; continue
    say i "checked" s!"the kernel accepted {ask.thm}" (axiomsOf env ask.thm)
    env.freeRegions
  return 0
`;
