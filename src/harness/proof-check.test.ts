import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { askAboutTheorems, assumptions, checkTheorems, proofCommand, ProofOutput, proofProbe, type ProofProbe } from "./proof-check";

const NONCE = "abc123";
const lean = (theorem: string, proof = "proofs/Main.lean") => ({ proof, theorem, checker: "lean4" as const });
const rocq = (theorem: string, proof = "proofs/Main.v") => ({ proof, theorem, checker: "rocq" as const });

/** A probe as askAboutTheorems leaves it, for a file of `lines` lines. */
function asked(probe: ProofProbe, lines: number): ProofProbe {
  for (const file of probe.files) {
    file.lines = lines;
    let line = lines + 1;
    for (const theorem of file.theorems) {
      line += file.checker === "lean4" ? 2 : 3;
      theorem.line = line;
    }
  }
  return probe;
}

function run(probe: ProofProbe, stdout: string[], stderr: string[] = [], exitCode: number | null = 0) {
  const output = new ProofOutput(probe);
  // Streams arrive in pieces that split lines anywhere.
  const text = stdout.join("\n") + "\n";
  output.write(text.slice(0, 7), "stdout");
  output.write(text.slice(7), "stdout");
  if (stderr.length > 0) output.write(stderr.join("\n") + "\n", "stderr");
  return checkTheorems(probe, output, exitCode);
}

describe("the questions a proof check asks", () => {
  it("go at the end of the workspace's copy of each proof file, after a marker holding the nonce", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "sj-proofs-"));
    await mkdir(join(workspace, "proofs"));
    await writeFile(join(workspace, "proofs", "Main.lean"), "theorem t1 : 1 = 1 := rfl");
    await writeFile(join(workspace, "proofs", "Main.v"), "Theorem t2 : True.\nProof. exact I. Qed.\n");
    const probe = proofProbe([lean("t1"), rocq("t2"), lean("t1")], NONCE);
    await askAboutTheorems(workspace, probe);
    expect(await readFile(join(workspace, "proofs", "Main.lean"), "utf8")).toBe(
      ["theorem t1 : 1 = 1 := rfl", "", '#print "sj_harness_abc123_0"', "#print axioms t1", '#print "sj_harness_abc123_end0"', ""].join("\n"),
    );
    expect(await readFile(join(workspace, "proofs", "Main.v"), "utf8")).toBe(
      [
        "Theorem t2 : True.",
        "Proof. exact I. Qed.",
        "",
        "Definition sj_harness_abc123_1 := Prop.",
        "Print sj_harness_abc123_1.",
        "Print Assumptions t2.",
        "Definition sj_harness_abc123_end1 := Prop.",
        "Print sj_harness_abc123_end1.",
        "",
      ].join("\n"),
    );
    // Each question's line is known, so the checker's errors there are about that theorem.
    expect(probe.files.map((file) => [file.lines, file.theorems.map((t) => t.line)])).toEqual([
      [1, [4]],
      [2, [6]],
    ]);
  });

  it("never put a claim's theorem name into a proof file unless it is a name", () => {
    const probe = proofProbe([lean("Main.thm'"), lean("«odd name».x"), lean("t\n#eval IO.println 1"), rocq("Lib.t_1'"), rocq("t. Print X")], NONCE);
    expect(probe.files.flatMap((file) => file.theorems.map((t) => t.theorem))).toEqual(["Main.thm'", "«odd name».x", "Lib.t_1'"]);
    expect(probe.unaskable.map((t) => t.theorem)).toEqual(["t\n#eval IO.println 1", "t. Print X"]);
  });

  it("run each file's checker and note its exit status, or run the command given", () => {
    const probe = proofProbe([lean("t1", "proofs/A b.lean"), rocq("t2")], NONCE);
    expect(proofCommand(probe).command).toBe(
      [
        "lean 'proofs/A b.lean'; echo \"sj_harness_abc123_exit0 $?\"",
        'if command -v rocq >/dev/null 2>&1; then rocq compile proofs/Main.v; else coqc proofs/Main.v; fi; echo "sj_harness_abc123_exit1 $?"',
      ].join("\n"),
    );
    expect(proofCommand(probe, "cd proofs && lake build")).toEqual({ command: "cd proofs && lake build", from: "given", files: ["proofs/A b.lean", "proofs/Main.v"] });
  });
});

describe("reading what Lean 4 says", () => {
  // As Lean 4.21 prints it: messages with no position for #print, errors with one.
  const probe = () => asked(proofProbe([lean("Main.ok"), lean("Main.classical"), lean("Main.unfinished"), lean("Main.missing")], NONCE), 20);
  const answers = [
    "proofs/Main.lean:6:8: warning: declaration uses 'sorry'",
    "'Main.ok' does not depend on any axioms",
    "sj_harness_abc123_0",
    "'Main.ok' does not depend on any axioms",
    "sj_harness_abc123_1",
    "'Main.classical' depends on axioms: [propext, Classical.choice, Quot.sound]",
    "sj_harness_abc123_2",
    "'Main.unfinished' depends on axioms: [sorryAx]",
    "sj_harness_abc123_3",
    "proofs/Main.lean:29:14: error: unknown constant 'Main.missing'",
    "sj_harness_abc123_end0",
  ];

  it("passes a theorem on the standard axioms, and fails one on sorry or one that isn't there", () => {
    const results = run(probe(), answers, [], 1);
    expect(results.map((r) => [r.theorem, r.status, r.axioms])).toEqual([
      ["Main.ok", "passed", []],
      ["Main.classical", "passed", ["propext", "Classical.choice", "Quot.sound"]],
      ["Main.unfinished", "failed", ["sorryAx"]],
      ["Main.missing", "failed", undefined],
    ]);
    // Lean exited 1 only because the harness asked about a theorem that isn't there.
    expect(results[0].reason).toBe("Lean accepted proofs/Main.lean, and Main.ok rests on no more than Lean's standard axioms (propext, Classical.choice, Quot.sound)");
    expect(results[2].reason).toBe("Main.unfinished rests on sorryAx, an unfinished proof");
    expect(results[3].reason).toBe("Lean couldn't find Main.missing: unknown constant 'Main.missing'");
  });

  it("fails a clean theorem whose file has errors of its own", () => {
    const broken = asked(proofProbe([lean("Main.ok")], NONCE), 20);
    const results = run(
      broken,
      ["proofs/Main.lean:12:2: error: tactic 'rfl' failed", "sj_harness_abc123_0", "'Main.ok' does not depend on any axioms", "sj_harness_abc123_end0", "sj_harness_abc123_exit0 1"],
    );
    expect(results[0]).toMatchObject({
      status: "failed",
      reason: "Main.ok rests on no more than Lean's standard axioms (propext, Classical.choice, Quot.sound), but the checker reported errors in proofs/Main.lean (line 12: tactic 'rfl' failed)",
    });
  });

  it("passes clean theorems when the checker accepted the file", () => {
    const clean = asked(proofProbe([lean("Main.ok"), lean("Main.classical")], NONCE), 20);
    const results = run(clean, answers.slice(0, 7).concat("sj_harness_abc123_end0"), [], 0);
    expect(results.map((r) => r.status)).toEqual(["passed", "passed"]);
    expect(results[1].reason).toBe("Lean accepted proofs/Main.lean, and Main.classical rests on no more than Lean's standard axioms (propext, Classical.choice, Quot.sound)");
  });

  it("ignores a report printed before the harness asked, as a proof file could forge one", () => {
    const forged = asked(proofProbe([lean("Main.unfinished")], NONCE), 20);
    const results = run(forged, ["'Main.unfinished' does not depend on any axioms", "sj_harness_abc123_0", "'Main.unfinished' depends on axioms: [sorryAx]", "sj_harness_abc123_end0"]);
    expect(results[0]).toMatchObject({ status: "failed", axioms: ["sorryAx"] });
  });

  it("fails a theorem whose file stopped the checker early, and fails one whose file has errors", () => {
    const stopped = asked(proofProbe([lean("t1")], NONCE), 20);
    expect(run(stopped, ["proofs/Main.lean:2:0: warning: using 'exit' to interrupt Lean", "sj_harness_abc123_exit0 0"])[0]).toMatchObject({
      status: "failed",
      reason: expect.stringContaining("stopped before the harness's questions"),
    });
    const broken = asked(proofProbe([lean("t1")], NONCE), 20);
    expect(run(broken, ["proofs/Main.lean:3:0: error: unexpected token 'theorem'", "sj_harness_abc123_exit0 1"])[0]).toMatchObject({
      status: "failed",
      reason: "Lean reported errors in proofs/Main.lean before reaching t1 (line 3: unexpected token 'theorem')",
    });
  });

  it("can't tell when the checker never started, and says so", () => {
    const missing = asked(proofProbe([lean("t1")], NONCE), 20);
    expect(run(missing, ["sh: 1: lean: not found", "sj_harness_abc123_exit0 127"])[0]).toMatchObject({
      status: "unknown",
      reason: expect.stringContaining("isn't in the image (exit status 127)"),
    });
  });
});

describe("reading what Rocq says", () => {
  // As Rocq 9.0 prints it: assumptions on stdout, located errors on stderr.
  const probe = () => asked(proofProbe([rocq("plus_O_n"), rocq("unfinished"), rocq("excluded")], NONCE), 10);
  const answers = [
    "sj_harness_abc123_0 = Prop",
    "     : Type",
    "Closed under the global context",
    "sj_harness_abc123_1 = Prop",
    "     : Type",
    "Axioms:",
    "unfinished : forall n : nat, n + 0 = n",
    "sj_harness_abc123_2 = Prop",
    "     : Type",
    "Axioms:",
    "classic :",
    "  forall P : Prop, P \\/ ~ P",
    "sj_harness_abc123_end0 = Prop",
    "     : Type",
    "sj_harness_abc123_exit0 0",
  ];

  it("passes a theorem closed under the global context, and fails an admitted or classical one", () => {
    const results = run(probe(), answers);
    expect(results.map((r) => [r.theorem, r.status, r.axioms])).toEqual([
      ["plus_O_n", "passed", []],
      ["unfinished", "failed", ["unfinished"]],
      ["excluded", "failed", ["classic"]],
    ]);
    expect(results[1].reason).toBe("unfinished is itself assumed, not proved (Admitted)");
    expect(results[2].reason).toBe("excluded rests on classic, beyond Rocq's own foundations, which assume no axioms");
  });

  it("finds an error at the harness's question, and an error in the proof, by where Rocq locates it", () => {
    const one = asked(proofProbe([rocq("t1"), rocq("missing_one")], NONCE), 2);
    const results = run(
      one,
      ["sj_harness_abc123_0 = Prop", "     : Type", "Closed under the global context", "sj_harness_abc123_1 = Prop", "     : Type", "sj_harness_abc123_exit0 1"],
      ['File "./proofs/Main.v", line 9, characters 18-29:', "Error: The reference missing_one was not found in the current environment.", ""],
    );
    expect(results.map((r) => r.status)).toEqual(["passed", "failed"]);
    expect(results[1].reason).toBe("Rocq couldn't find missing_one: The reference missing_one was not found in the current environment.");

    // Rocq stops at its first error, so a question after a failed one never gets asked.
    const stopped = asked(proofProbe([rocq("missing_one"), rocq("t1")], NONCE), 2);
    const after = run(
      stopped,
      ["sj_harness_abc123_0 = Prop", "     : Type", "sj_harness_abc123_exit0 1"],
      ['File "./proofs/Main.v", line 6, characters 18-29:', "Error: The reference missing_one was not found in the current environment."],
    );
    expect(after.map((r) => r.status)).toEqual(["failed", "unknown"]);
    expect(after[1].reason).toContain("stopped at an earlier question in proofs/Main.v");

    const bad = asked(proofProbe([rocq("t1")], NONCE), 2);
    expect(
      run(bad, ["sj_harness_abc123_exit0 1"], ['File "./proofs/Main.v", line 2, characters 7-18:', 'Error: Unable to unify "3" with "1 + 1".'])[0],
    ).toMatchObject({ status: "failed", reason: 'Rocq reported errors in proofs/Main.v before reaching t1 (line 2: Unable to unify "3" with "1 + 1".)' });
  });

  it("reads a warning's location as a warning, not an error", () => {
    const warned = asked(proofProbe([rocq("t1")], NONCE), 10);
    const results = run(
      warned,
      ["sj_harness_abc123_0 = Prop", "     : Type", "Closed under the global context", "sj_harness_abc123_end0 = Prop", "sj_harness_abc123_exit0 0"],
      ['File "./proofs/Main.v", line 1, characters 0-0:', "Warning: Loading Stdlib without prefix is deprecated."],
    );
    expect(results[0].status).toBe("passed");
  });
});

describe("assumptions", () => {
  it("is null when a checker said nothing it recognizes", () => {
    expect(assumptions("lean4", ["something else"])).toBeNull();
    expect(assumptions("rocq", ["sj_harness_x = Prop", "     : Type"])).toBeNull();
  });
});
