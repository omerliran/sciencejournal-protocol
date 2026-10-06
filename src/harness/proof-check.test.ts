import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  judgeDockerfile,
  leanJudgeCommand,
  leanToolchain,
  leanToolchainOfVersion,
  readLeanJudge,
  readRocqJudge,
  rocqImage,
  rocqJudgeCommand,
  rocqVersionOf,
  type JudgeAnswer,
} from "./judge";
import { assumptions, checkTheorems, compileCommand, judgeAsks, placeProofs, ProofOutput, proofProbe, type ProofProbe } from "./proof-check";

const NONCE = "abc123";
const lean = (theorem: string, proof = "proofs/Main.lean") => ({ proof, theorem, checker: "lean4" as const });
const rocq = (theorem: string, proof = "proofs/Main.v") => ({ proof, theorem, checker: "rocq" as const });

function compiled(probe: ProofProbe, stdout: string[], stderr: string[] = []): ProofOutput {
  const output = new ProofOutput(probe);
  // Streams arrive in pieces that split lines anywhere.
  const text = stdout.join("\n") + "\n";
  output.write(text.slice(0, 7), "stdout");
  output.write(text.slice(7), "stdout");
  if (stderr.length > 0) output.write(stderr.join("\n") + "\n", "stderr");
  return output;
}

const checked = (axioms: string[] = []): JudgeAnswer => ({ status: "checked", reason: "the kernel accepted it", axioms });

describe("the first step of a proof check", () => {
  it("copies each proof file under a module name the harness picks", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "sj-proofs-"));
    await mkdir(join(workspace, "proofs"));
    await writeFile(join(workspace, "proofs", "Main.lean"), "theorem t1 : 1 = 1 := rfl");
    await writeFile(join(workspace, "proofs", "Main.v"), "Theorem t2 : True.\nProof. exact I. Qed.\n");
    const probe = proofProbe([lean("t1"), rocq("t2"), lean("t1")], NONCE);
    await placeProofs(workspace, probe);
    expect(probe.files.map((file) => [file.path, file.module, file.copy])).toEqual([
      ["proofs/Main.lean", "SJProof0", ".sj-proofs/SJProof0.lean"],
      ["proofs/Main.v", "SJProof1", ".sj-proofs/SJProof1.v"],
    ]);
    // The copies are the files as published: nothing is added to them.
    expect(await readFile(join(workspace, ".sj-proofs", "SJProof0.lean"), "utf8")).toBe("theorem t1 : 1 = 1 := rfl");
    await expect(placeProofs(workspace, proofProbe([lean("t", "proofs/Gone.lean")], NONCE))).rejects.toThrow("isn't in the bundle");
  });

  it("never asks the judge about a claim's theorem unless it is a name", () => {
    const probe = proofProbe([lean("Main.thm'"), lean("«odd name».x"), lean("t\n#eval IO.println 1"), rocq("Lib.t_1'"), rocq("t. Print X")], NONCE);
    expect(probe.files.flatMap((file) => file.theorems.map((t) => t.theorem))).toEqual(["Main.thm'", "«odd name».x", "Lib.t_1'"]);
    expect(probe.unaskable.map((t) => t.theorem)).toEqual(["t\n#eval IO.println 1", "t. Print X"]);
  });

  it("compiles each copy with its checker, notes its exit status and the checker's version, or runs the command given", () => {
    const probe = proofProbe([lean("t1", "proofs/A b.lean"), rocq("t2")], NONCE);
    expect(compileCommand(probe).command).toBe(
      [
        'echo "sj_harness_abc123_lean $(lean --version 2>&1 | head -n 1)"',
        'echo "sj_harness_abc123_rocq $( (rocq --version || coqc --version) 2>&1 | head -n 1)"',
        '(cd .sj-proofs && lean --root=. -o SJProof0.olean SJProof0.lean); echo "sj_harness_abc123_exit0 $?"',
        '(cd .sj-proofs && if command -v rocq >/dev/null 2>&1; then rocq compile -Q . SJ SJProof1.v; else coqc -Q . SJ SJProof1.v; fi); echo "sj_harness_abc123_exit1 $?"',
      ].join("\n"),
    );
    expect(compileCommand(probe, "cd proofs && lake build")).toEqual({ command: "cd proofs && lake build", from: "given", files: ["proofs/A b.lean", "proofs/Main.v"] });
  });

  it("reads the checkers' versions and exit statuses, and only from the harness's own markers", () => {
    const probe = proofProbe([lean("t1"), rocq("t2")], NONCE);
    const output = compiled(probe, [
      "sj_harness_abc123_lean Lean (version 4.34.1, aarch64-unknown-linux-gnu, commit 5045d00, Release)",
      "sj_harness_abc123_rocq The Rocq Prover, version 9.0.1",
      "sj_harness_abc123_exit0 0",
      "sj_harness_other_exit1 0",
      "sj_harness_abc123_exit1 1",
    ]);
    expect(output.versions.get("lean4")).toContain("version 4.34.1");
    expect(leanToolchainOfVersion(output.versions.get("lean4")!)).toBe("leanprover/lean4:v4.34.1");
    expect(rocqVersionOf(output.versions.get("rocq")!)).toBe("9.0.1");
    expect([...output.exits]).toEqual([
      [0, 0],
      [1, 1],
    ]);
  });
});

describe("a theorem's result", () => {
  const probe = () => proofProbe([lean("Main.ok"), lean("Main.classical"), lean("Main.unfinished"), lean("Main.missing")], NONCE);

  it("comes from the judge: passed on the standard axioms, failed on any other, or when the judge found fault", () => {
    const p = probe();
    const judged = new Map<number, JudgeAnswer>([
      [0, checked()],
      [1, checked(["Classical.choice", "Quot.sound", "propext"])],
      [2, checked(["sorryAx"])],
      [3, { status: "failed", reason: "Main.missing isn't in the compiled proof", axioms: [] }],
    ]);
    const results = checkTheorems(p, compiled(p, ["sj_harness_abc123_exit0 0"]), 0, judged);
    expect(results.map((r) => [r.theorem, r.status, r.axioms])).toEqual([
      ["Main.ok", "passed", []],
      ["Main.classical", "passed", ["Classical.choice", "Quot.sound", "propext"]],
      ["Main.unfinished", "failed", ["sorryAx"]],
      ["Main.missing", "failed", undefined],
    ]);
    expect(results[0].reason).toBe(
      "Lean compiled proofs/Main.lean, the kernel accepted Main.ok again on its own, and it rests on no more than Lean's standard axioms (propext, Classical.choice, Quot.sound)",
    );
    expect(results[2].reason).toBe("Main.unfinished rests on sorryAx, an unfinished proof");
    expect(results[3].reason).toBe("Main.missing isn't in the compiled proof");
  });

  it("ignores whatever the compiled file printed: only the judge decides", () => {
    const p = proofProbe([lean("Main.unfinished")], NONCE);
    const output = compiled(p, ["'Main.unfinished' does not depend on any axioms", "verdict passed", "sj_harness_abc123_exit0 0"]);
    expect(checkTheorems(p, output, 0, new Map([[0, checked(["sorryAx"])]]))[0]).toMatchObject({ status: "failed", axioms: ["sorryAx"] });
  });

  it("fails every theorem of a file that didn't compile, whatever the judge said", () => {
    const p = proofProbe([lean("Main.ok")], NONCE);
    const results = checkTheorems(p, compiled(p, ["SJProof0.lean:12:2: error: tactic 'rfl' failed", "sj_harness_abc123_exit0 1"]), 0, new Map([[0, checked()]]));
    expect(results[0]).toMatchObject({ status: "failed", reason: "Lean reported errors in proofs/Main.lean (line 12: tactic 'rfl' failed)" });
    // Lean 4.34 names its errors: error(lean.unknownIdentifier).
    const named = checkTheorems(p, compiled(p, ["SJProof0.lean:3:9: error(lean.unknownIdentifier): Unknown identifier `x`", "sj_harness_abc123_exit0 1"]), 0, new Map());
    expect(named[0].reason).toBe("Lean reported errors in proofs/Main.lean (line 3: Unknown identifier `x`)");
  });

  it("can't tell when the checker never started or the judge couldn't run, and says so", () => {
    const p = proofProbe([lean("t1")], NONCE);
    expect(checkTheorems(p, compiled(p, ["sh: 1: lean: not found", "sj_harness_abc123_exit0 127"]), 127, new Map())[0]).toMatchObject({
      status: "unknown",
      reason: expect.stringContaining("isn't in the image (exit status 127)"),
    });
    expect(checkTheorems(p, compiled(p, ["sj_harness_abc123_exit0 0"]), 0, new Map(), "The judge's image couldn't be prepared")[0]).toMatchObject({
      status: "unknown",
      reason: "The judge's image couldn't be prepared",
    });
  });

  it("names a Rocq axiom of the proof's own file as the file spells it", () => {
    const p = proofProbe([rocq("plus_O_n"), rocq("unfinished"), rocq("excluded")], NONCE);
    const judged = new Map<number, JudgeAnswer>([
      [0, checked()],
      [1, checked(["SJProof0.unfinished"])],
      [2, checked(["classic"])],
    ]);
    const results = checkTheorems(p, compiled(p, ["sj_harness_abc123_exit0 0"]), 0, judged);
    expect(results.map((r) => [r.theorem, r.status, r.axioms])).toEqual([
      ["plus_O_n", "passed", []],
      ["unfinished", "failed", ["unfinished"]],
      ["excluded", "failed", ["classic"]],
    ]);
    expect(results[1].reason).toBe("unfinished is itself assumed, not proved (Admitted)");
    expect(results[2].reason).toBe("excluded rests on classic, beyond Rocq's own foundations, which assume no axioms");
  });

  it("reads a Rocq warning's location as a warning, not an error", () => {
    const p = proofProbe([rocq("t1")], NONCE);
    const output = compiled(p, ["sj_harness_abc123_exit0 0"], ['File "./SJProof0.v", line 1, characters 0-0:', "Warning: Loading Stdlib without prefix is deprecated."]);
    expect(checkTheorems(p, output, 0, new Map([[0, checked()]]))[0].status).toBe("passed");
    const broken = compiled(p, ["sj_harness_abc123_exit0 1"], ['File "./SJProof0.v", line 2, characters 7-18:', 'Error: Unable to unify "3" with "1 + 1".']);
    expect(checkTheorems(p, broken, 1, new Map())[0]).toMatchObject({ status: "failed", reason: 'Rocq reported errors in proofs/Main.v (line 2: Unable to unify "3" with "1 + 1".)' });
  });
});

describe("the judge", () => {
  it("is asked about each theorem by the module the harness compiled it as", () => {
    const probe = proofProbe([lean("A.t", "proofs/A.lean"), rocq("u"), lean("B.t", "proofs/B.lean"), lean("A.s", "proofs/A.lean")], NONCE);
    expect(judgeAsks(probe, "lean4")).toEqual([
      { module: "SJProof0", theorem: "A.t", index: 0 },
      { module: "SJProof0", theorem: "A.s", index: 3 },
      { module: "SJProof2", theorem: "B.t", index: 2 },
    ]);
    expect(judgeAsks(probe, "rocq")).toEqual([{ module: "SJProof1", theorem: "u", index: 1 }]);
  });

  it("gets its request as JSON, with names in parts, and only names", () => {
    const command = leanJudgeCommand([{ module: "SJProof0", theorem: "«odd name».x", states: { module: "SJStatement", name: "SJGoal.stmt" } }]);
    expect(command).toContain(`lean --run judge/Judge.lean`);
    const request = JSON.parse(/'(.*)'$/.exec(command)![1]) as unknown;
    expect(request).toEqual({
      out: "/work/compiled",
      asks: [{ module: "SJProof0", theorem: ["odd name", "x"], states: { module: "SJStatement", name: ["SJGoal", "stmt"] } }],
    });
    expect(() => leanJudgeCommand([{ module: "SJProof0", theorem: "x\n#exit" }])).toThrow("isn't a Lean name");
    expect(() => rocqJudgeCommand([{ module: "SJProof0", theorem: "x. Print X" }])).toThrow("isn't a Rocq name");
  });

  it("is read only from its own lines, and a theorem it never answered about is unknown", () => {
    const asks = [{ module: "SJProof0", theorem: "a" }, { module: "SJProof0", theorem: "b" }, { module: "SJProof0", theorem: "c" }];
    const output = [
      "some warning",
      'sj-judge {"ask":0,"axioms":["propext"],"reason":"the kernel accepted a","status":"checked"}',
      'sj-judge {"ask":1,"axioms":[],"reason":"the kernel rejected a declaration","status":"failed"}',
      'sj-judge {"ask":7,"axioms":[],"reason":"out of range","status":"checked"}',
      "sj-judge not json",
    ].join("\n");
    expect(readLeanJudge(output, asks)).toEqual([
      { status: "checked", reason: "the kernel accepted a", axioms: ["propext"] },
      { status: "failed", reason: "the kernel rejected a declaration", axioms: [] },
      { status: "unknown", reason: "the judge didn't answer; see judge.log", axioms: [] },
    ]);
  });

  it("reads Rocq's independent checker, then what each theorem rests on", () => {
    const asks = [{ module: "SJProof0", theorem: "clean" }, { module: "SJProof0", theorem: "uses_cheat" }, { module: "SJProof0", theorem: "nope" }];
    const output = [
      "CONTEXT SUMMARY",
      "* Axioms:",
      "    SJ.SJProof0.cheat",
      "sj_judge_checked 0",
      "Rocq < sj_judge_0 = Prop",
      "     : Type",
      "Rocq < Fetching opaque proofs from disk for SJ.SJProof0",
      "Closed under the global context",
      "Rocq < sj_judge_1 = Prop",
      "     : Type",
      "Rocq < Axioms:",
      "SJProof0.cheat : False",
      "Rocq < sj_judge_2 = Prop",
      "     : Type",
      "Rocq < Toplevel input, characters 18-34:",
      "Error: The reference SJ.SJProof0.nope was not found in the current",
      "Rocq < sj_judge_end = Prop",
    ].join("\n");
    const read = (lines: string[]) => assumptions("rocq", lines);
    expect(readRocqJudge(output, asks, read).map((answer) => [answer.status, answer.axioms])).toEqual([
      ["checked", []],
      ["checked", ["SJProof0.cheat"]],
      ["failed", []],
    ]);
    expect(readRocqJudge(output.replace("sj_judge_checked 0", "sj_judge_checked 1"), asks, read).map((answer) => answer.status)).toEqual(["failed", "failed", "failed"]);
    expect(readRocqJudge("nothing", asks, read)[0].status).toBe("unknown");
  });

  it("runs in an image built from the pinned toolchain alone, and nothing else gets into it", () => {
    const dockerfile = judgeDockerfile({ checker: "lean4", toolchain: "leanprover/lean4:v4.34.1" });
    expect(dockerfile).toContain("--default-toolchain leanprover/lean4:v4.34.1");
    expect(dockerfile).toContain("ENV PATH=/opt/elan/toolchains/leanprover--lean4---v4.34.1/bin:/opt/elan/bin:$PATH");
    expect(dockerfile).not.toContain("mathlib");
    const withMathlib = judgeDockerfile({ checker: "lean4", toolchain: "leanprover/lean4:v4.34.1", mathlib: "a".repeat(40) });
    expect(withMathlib).toContain(`'rev = "${"a".repeat(40)}"'`);
    expect(withMathlib).toContain("lake exe cache get");
    expect(() => judgeDockerfile({ checker: "lean4", toolchain: "leanprover/lean4:v4.34.1; curl evil" })).toThrow("isn't a Lean toolchain");
    expect(() => judgeDockerfile({ checker: "lean4", toolchain: "leanprover/lean4:v4.34.1", mathlib: "main" })).toThrow("isn't a Mathlib commit");
  });

  it("knows a pinned toolchain and Rocq's official images", () => {
    expect(leanToolchain("leanprover/lean4:v4.34.1\n")).toBe("leanprover/lean4:v4.34.1");
    expect(leanToolchain("leanprover/lean4:v4.35.0-rc2")).toBe("leanprover/lean4:v4.35.0-rc2");
    expect(leanToolchain("leanprover/lean4:nightly")).toBeNull();
    expect(rocqImage("9.0.1")).toBe("rocq/rocq-prover:9.0.1");
    expect(rocqImage("9.1.0")).toBe("rocq/rocq-prover:9.1");
    expect(rocqImage("8.20.1")).toBe("coqorg/coq:8.20.1");
    expect(rocqVersionOf("The Coq Proof Assistant, version 8.20.1")).toBe("8.20.1");
  });
});

describe("assumptions", () => {
  it("is null when a checker said nothing it recognizes", () => {
    expect(assumptions("lean4", ["something else"])).toBeNull();
    expect(assumptions("rocq", ["sj_harness_x = Prop", "     : Type"])).toBeNull();
  });
});
