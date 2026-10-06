import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Deps } from "./context";
import type { RunRecord } from "./evidence";
import { LogTail } from "./files";
import { checkGoalProof, type GoalCheckInput } from "./goal-check";
import { judgeImageKey, type JudgeImage } from "./judge";
import { containerSandbox, findEngine } from "./sandbox";
import { selfCheck } from "./self-check";
import type { VerdictsRecord } from "./verdicts";

// The real sandbox, on whatever container engine this machine has; skipped when it has none.
// Each bundle is a tiny Python computation whose code/run writes results/R1.json.

const engine = await findEngine();
const MINUTES = 5 * 60_000;

const COMPUTE = `
import json, os, socket
try:
    socket.create_connection(("1.1.1.1", 53), timeout=3).close()
    network = True
except OSError:
    network = False
os.makedirs("results/extra", exist_ok=True)
json.dump({"value": sum(i * i for i in range(10)) / 1000}, open("results/R1.json", "w"))
json.dump({"network": network, "uid": os.getuid()}, open("results/extra/sandbox.json", "w"))
print("computed")
`;

async function writeBundle(declared: number, overrides: Record<string, string> = {}, minutes = 1): Promise<string> {
  const root = join(await mkdtemp(join(tmpdir(), "sj-docker-")), "bundle");
  const files: Record<string, string> = {
    "manifest.json": JSON.stringify({
      operator_key_digest: `sha256:${"a".repeat(64)}`,
      fields: ["testing"],
      license: { prose: "CC-BY-4.0" },
      compute: { minutes, gpu: false },
    }),
    "paper.md": "# Summary\n\nThe sum of the first ten squares, over a thousand.\n",
    "claims.json": JSON.stringify([
      {
        local_id: "C1",
        type: "empirical",
        core: true,
        statement: "The sum of the squares of 0 through 9, divided by 1000, is 0.285.",
        evidence: [{ result: "R1.value", produced_by: "code/compute.py", tolerance: 0.001 }],
        depends_on: [],
        confidence: 0.99,
      },
    ]),
    "code/compute.py": COMPUTE,
    "code/run": "python3 code/compute.py\n",
    "env/requirements.txt": "# Nothing beyond the standard library.\n",
    "results/R1.json": JSON.stringify({ value: declared }),
    ...overrides,
  };
  for (const [path, text] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), text);
  }
  return root;
}

function deps(): Deps & { lines: string[] } {
  const lines: string[] = [];
  return { fetch, now: () => new Date(), print: (line) => lines.push(line), env: {}, home: tmpdir(), invocation: "sj-harness", findEngine, lines };
}

const read = async <T>(path: string) => JSON.parse(await readFile(path, "utf8")) as T;

describe.skipIf(!engine)(`the sandbox, on ${engine?.command ?? "no engine"}`, () => {
  it(
    "reproduces a bundle in a container built from env/requirements.txt, with no network, as the user",
    async () => {
      const bundle = await writeBundle(0.285);
      const out = deps();
      expect(await selfCheck(bundle, {}, out)).toBe(0);
      const outDir = `${bundle}-harness`;
      const verdicts = await read<VerdictsRecord>(join(outDir, "verdicts.json"));
      expect(verdicts.claims[0]).toMatchObject({ verdict: "reproduced" });
      const run = await read<RunRecord>(join(outDir, "run.json"));
      expect(run).toMatchObject({ engine: { name: engine!.command }, command: { command: "sh code/run", from: "code/run" } });
      expect(run.image).toMatchObject({ plan: { from: "requirements" }, id: expect.stringMatching(/^sha256:/) });
      expect(run.result).toMatchObject({ exitCode: 0, timedOut: false });

      const sandbox = await read<{ network: boolean; uid: number }>(join(outDir, "workspace", "results", "extra", "sandbox.json"));
      expect(sandbox.network).toBe(false);
      if (process.getuid) {
        expect(sandbox.uid).toBe(process.getuid());
        expect((await stat(join(outDir, "workspace", "results", "R1.json"))).uid).toBe(process.getuid());
      }
      expect(await readFile(join(outDir, "evidence", "run.log"), "utf8")).toBe("computed\n");
      expect(await readFile(join(outDir, "evidence", "results", "R1.json"), "utf8")).toBe('{"value": 0.285}');
      expect(await readFile(join(outDir, "evidence", "report.md"), "utf8")).toContain("| `C1` | `R1.value` | `code/compute.py` | `0.285` | `0.285` | 0.001 | yes |");

      // The image is built once for these inputs, and used again.
      expect(await selfCheck(bundle, {}, deps())).toBe(0);
      expect((await read<RunRecord>(join(outDir, "run.json"))).image).toMatchObject({ reused: true, id: run.image!.id });
    },
    MINUTES,
  );

  it(
    "finds a mismatch when the declared result is off by more than its tolerance",
    async () => {
      const bundle = await writeBundle(0.29);
      expect(await selfCheck(bundle, {}, deps())).toBe(1);
      const verdicts = await read<VerdictsRecord>(join(`${bundle}-harness`, "verdicts.json"));
      expect(verdicts.claims[0]).toMatchObject({
        verdict: "mismatch",
        reason: "R1.value came out 0.285; the bundle declares 0.29 (tolerance 0.001).",
      });
    },
    MINUTES,
  );

  it(
    "stops work that runs past its time and reports it over budget",
    async () => {
      const bundle = await writeBundle(0.285, { "code/run": "sleep 60\n" }, 0.02);
      expect(await selfCheck(bundle, {}, deps())).toBe(1);
      const outDir = `${bundle}-harness`;
      const verdicts = await read<VerdictsRecord>(join(outDir, "verdicts.json"));
      expect(verdicts.over_budget).toBe(true);
      expect(verdicts.claims[0]).toMatchObject({ verdict: "could_not_run", reason: expect.stringContaining("passed its time limit") });
      const run = await read<RunRecord>(join(outDir, "run.json"));
      expect(run.result).toMatchObject({ timedOut: true, exitCode: null });
      expect(run.result!.seconds).toBeLessThan(30);
    },
    MINUTES,
  );
});

// The judge, on Lean proofs that try to pass without being proved. Its image is the pinned
// toolchain alone (a few hundred MB), built once on a machine and kept.
const TOOLCHAIN = "leanprover/lean4:v4.34.1";
const LEAN_ATTACKS: Record<string, { theorem: string; lean: string; verdict: string; reason?: RegExp }> = {
  Honest: { theorem: "Honest.add_zero", lean: "theorem Honest.add_zero (n : Nat) : n + 0 = n := rfl", verdict: "passed" },
  Sorry: { theorem: "bogus", lean: "theorem bogus : False := sorry", verdict: "failed", reason: /sorryAx/ },
  // Takes over the very command the harness once asked with, and answers for it.
  Intercept: {
    theorem: "bogus",
    lean: [
      "import Lean",
      "open Lean Elab Command in",
      "elab_rules : command",
      "  | `(#print axioms $id) => logInfo m!\"'{id.getId}' does not depend on any axioms\"",
      "theorem bogus : False := sorry",
    ].join("\n"),
    verdict: "failed",
    reason: /sorryAx/,
  },
  // Adds a false theorem with the kernel told not to look.
  SkipKernel: {
    theorem: "bogus",
    lean: [
      "import Lean",
      "open Lean Elab Command",
      "set_option debug.skipKernelTC true",
      "run_cmd liftCoreM do",
      "  addDecl (.thmDecl { name := `bad, levelParams := [], type := mkConst ``False, value := mkConst ``True.intro })",
      "theorem bogus : False := bad",
    ].join("\n"),
    verdict: "failed",
    reason: /kernel rejected/,
  },
  Axiom: { theorem: "bogus", lean: "axiom cheat : False\ntheorem bogus : False := cheat", verdict: "failed", reason: /rests on cheat/ },
  Native: { theorem: "big", lean: "theorem big : 2 ^ 20 = 1048576 := by native_decide", verdict: "failed", reason: /native_decide/ },
  Missing: { theorem: "nowhere", lean: "theorem somewhere : True := trivial", verdict: "failed", reason: /isn't in the compiled proof/ },
};

describe.skipIf(!engine)(`the judge, on ${engine?.command ?? "no engine"}`, () => {
  const onlyProofs = async (overrides: Record<string, string>) => {
    const bundle = await writeBundle(0, overrides);
    for (const path of ["code/compute.py", "code/run", "env/requirements.txt", "results/R1.json"]) await rm(join(bundle, path), { force: true });
    return bundle;
  };
  const claims = (entries: [string, string, string][]) =>
    JSON.stringify(
      entries.map(([id, proof, theorem]) => ({ local_id: id, type: "theoretical", core: true, statement: `${id} holds.`, evidence: [{ proof, theorem, checker: "lean4" }], depends_on: [], confidence: 1 })),
    );

  it(
    "passes only the honest proof, whatever the others print or do while they compile",
    async () => {
      // The judge's image does for compiling too, so the toolchain is fetched once.
      const image: JudgeImage = { checker: "lean4", toolchain: TOOLCHAIN };
      const scratch = await mkdtemp(join(tmpdir(), "sj-judge-image-"));
      const built = await containerSandbox(engine!).image({ from: "judge", image }, { workspace: scratch, scratch: join(scratch, "build"), key: judgeImageKey(image) }, { write: () => {} });
      const files: Record<string, string> = { "proofs/lean-toolchain": `${TOOLCHAIN}\n` };
      const entries: [string, string, string][] = [];
      for (const [name, attack] of Object.entries(LEAN_ATTACKS)) {
        files[`proofs/${name}.lean`] = `${attack.lean}\n`;
        entries.push([name, `proofs/${name}.lean`, attack.theorem]);
      }
      const bundle = await onlyProofs({ ...files, "claims.json": claims(entries) });
      expect(await selfCheck(bundle, { image: built.ref }, deps())).toBe(1);
      const outDir = join(`${bundle}-harness`, "proof-check");
      const verdicts = await read<VerdictsRecord>(join(outDir, "verdicts.json"));
      for (const claim of verdicts.claims) {
        const attack = LEAN_ATTACKS[claim.local_id];
        expect([claim.local_id, claim.verdict]).toEqual([claim.local_id, attack.verdict]);
        if (attack.reason) expect(claim.reason).toMatch(attack.reason);
      }
      const run = await read<RunRecord>(join(outDir, "run.json"));
      expect(run.judges).toMatchObject([{ checker: "lean4", image: { plan: { from: "judge" }, reused: true }, result: { exitCode: 0 } }]);
      expect(await readFile(join(outDir, "evidence", "judge.log"), "utf8")).toContain("sj-judge ");
    },
    20 * 60_000,
  );

  it(
    "can't be fooled by a lean in the work's own image that only pretends to compile",
    async () => {
      const bundle = await onlyProofs({
        "claims.json": claims([["T1", "proofs/Main.lean", "bogus"]]),
        "proofs/Main.lean": "theorem bogus : False := sorry\n",
        "proofs/lean-toolchain": `${TOOLCHAIN}\n`,
        "env/Dockerfile": [
          "FROM public.ecr.aws/docker/library/alpine:3.20",
          "RUN printf '#!/bin/sh\\necho \"Lean (version 4.34.1, fake)\"\\nexit 0\\n' > /usr/local/bin/lean && chmod +x /usr/local/bin/lean",
          "",
        ].join("\n"),
      });
      expect(await selfCheck(bundle, {}, deps())).toBe(1);
      const verdicts = await read<VerdictsRecord>(join(`${bundle}-harness`, "proof-check", "verdicts.json"));
      expect(verdicts.claims[0]).toMatchObject({ verdict: "could_not_run", reason: expect.stringContaining("couldn't be loaded") });
    },
    20 * 60_000,
  );
});

describe.skipIf(!engine)(`a goal check, on ${engine?.command ?? "no engine"}`, () => {
  const base: GoalCheckInput = {
    formal: { checker: "lean4", toolchain: TOOLCHAIN },
    imports: [],
    contexts: ["def double (n : Nat) : Nat := 2 * n"],
    statement: "∀ n : Nat, double n = n + n",
    proves: "goal",
    file: "theorem double_eq (n : Nat) : double n = n + n := by\n  unfold double; omega\n",
    theorem: "double_eq",
    minutes: 2,
  };
  const check = async (changes: Partial<GoalCheckInput>) => {
    const dir = await mkdtemp(join(tmpdir(), "sj-goal-check-"));
    const logs = { build: new LogTail(1 << 16, 1 << 16), compile: new LogTail(1 << 16, 1 << 16), judge: new LogTail(1 << 16, 1 << 16) };
    return checkGoalProof({ ...base, ...changes }, containerSandbox(engine!), { dir: join(dir, "work"), logs }, { print: () => {} });
  };

  it(
    "passes a proof of exactly the goal, and fails one of something else, an unfinished one, and one that redefines the goal",
    async () => {
      expect(await check({})).toMatchObject({ verdict: "passed", axioms: expect.any(Array) });
      // A true theorem, but not the goal.
      expect(await check({ file: "theorem other : 1 + 1 = 2 := rfl\n", theorem: "other" })).toMatchObject({ verdict: "failed", reason: expect.stringContaining("doesn't compile") });
      expect(await check({ file: "theorem double_eq (n : Nat) : double n = n + n := sorry\n" })).toMatchObject({ verdict: "failed", reason: expect.stringContaining("sorryAx") });
      // The statement module is compiled before the proof, so the proof can't say what the goal is.
      expect(await check({ file: "namespace SJGoal\ndef stmt : Prop := True\nend SJGoal\ntheorem t : True := trivial\n", theorem: "t" })).toMatchObject({ verdict: "failed" });
      // A proof of the negation refutes; of the goal itself, it fails as a negation.
      expect(await check({ proves: "negation" })).toMatchObject({ verdict: "failed" });
      // A goal whose own statement doesn't compile can't be checked at all.
      expect(await check({ statement: "∀ n : Nat, undefined_name n" })).toMatchObject({ verdict: "could_not_run", reason: expect.stringContaining("goal's own statement") });
    },
    20 * 60_000,
  );
});

// A real proof checker is a large image (Rocq's official one is about 1 GB), so this runs only
// when SJ_PROOF_IMAGE names a Rocq image to use, such as rocq/rocq-prover:9.0.
const proofImage = process.env.SJ_PROOF_IMAGE;

describe.skipIf(!engine || !proofImage)(`a proof check in ${proofImage ?? "a Rocq image"}`, () => {
  it(
    "passes a proved theorem, and fails an admitted one and one that rests on an axiom",
    async () => {
      const bundle = await writeBundle(0, {
        "claims.json": JSON.stringify([
          { local_id: "T1", type: "theoretical", core: true, statement: "Zero is a left identity of addition.", evidence: [{ proof: "proofs/Main.v", theorem: "plus_O_n", checker: "rocq" }], depends_on: [], confidence: 1 },
          { local_id: "T2", type: "theoretical", core: true, statement: "Zero is a right identity of addition.", evidence: [{ proof: "proofs/Main.v", theorem: "plus_n_O", checker: "rocq" }], depends_on: [], confidence: 1 },
          { local_id: "T3", type: "theoretical", core: false, statement: "Every proposition holds or fails.", evidence: [{ proof: "proofs/Main.v", theorem: "excluded", checker: "rocq" }], depends_on: [], confidence: 1 },
        ]),
        "proofs/Main.v": [
          "(* Admitted in a comment doesn't count. *)",
          "Theorem plus_O_n : forall n : nat, 0 + n = n.",
          "Proof. intros n. reflexivity. Qed.",
          "Theorem plus_n_O : forall n : nat, n + 0 = n.",
          "Proof. intros n. admit. Admitted.",
          "Axiom classic : forall P : Prop, P \\/ ~ P.",
          "Theorem excluded : forall P : Prop, P \\/ ~ P.",
          "Proof. exact classic. Qed.",
          "",
        ].join("\n"),
        "code/compute.py": "",
        "code/run": "",
        "env/requirements.txt": "",
        "results/R1.json": "{}",
      });
      // Only proofs: no computation for the self-check to re-run.
      for (const path of ["code/compute.py", "code/run", "env/requirements.txt", "results/R1.json"]) await rm(join(bundle, path));
      expect(await selfCheck(bundle, { image: proofImage }, deps())).toBe(1);
      const verdicts = await read<VerdictsRecord>(join(`${bundle}-harness`, "proof-check", "verdicts.json"));
      expect(verdicts.claims.map((claim) => [claim.local_id, claim.verdict])).toEqual([
        ["T1", "passed"],
        ["T2", "failed"],
        ["T3", "failed"],
      ]);
      expect(verdicts.claims[1].reason).toBe("plus_n_O is itself assumed, not proved (Admitted).");
      expect(verdicts.claims[2].reason).toBe("excluded rests on classic, beyond Rocq's own foundations, which assume no axioms.");
      expect(verdicts.unfinished?.map((found) => found.keyword)).toEqual(["admit", "Admitted"]);
      // The judge decided, in Rocq's own image for the version the work's image reported.
      const run = await read<RunRecord>(join(`${bundle}-harness`, "proof-check", "run.json"));
      expect(run.judges).toMatchObject([{ checker: "rocq", image: { plan: { from: "judge" } }, result: { exitCode: 0 } }]);
      expect(await readFile(join(`${bundle}-harness`, "proof-check", "evidence", "judge.log"), "utf8")).toContain("sj_judge_checked 0");
    },
    MINUTES,
  );
});
