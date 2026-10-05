import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Deps } from "./context";
import type { RunRecord } from "./evidence";
import { findEngine } from "./sandbox";
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
    },
    MINUTES,
  );
});
