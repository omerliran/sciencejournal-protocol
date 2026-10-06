import { stat } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { BundleLayoutError, digestBundle } from "../bundle";
import { ClaimsFileSchema, isComputation, isProof } from "../claims";
import { externalBytes, type ExternalData } from "../external";
import type { Digest } from "../hash";
import { integrityFlags, MISSING_FILE_REASONS } from "../integrity";
import { parseJson } from "../json";
import { ManifestSchema } from "../manifest";
import { overLimitMessage, paperOverLimits } from "../paper";
import { bundleInputs } from "../results";
import { scanFiles } from "../scan";
import { checkClaims } from "../validate";
import { HarnessError, type Deps } from "./context";
import { listFiles, readFiles, sha256File, under, writeJsonFile } from "./files";
import { plural, size } from "./format";
import { SCAN_LIMIT, type ScanRecord } from "./job";
import { checkMaterials, readMaterials } from "./materials";
import { describePointers, readPointers } from "./pointers";
import { runSubject, type RunOptions } from "./reproduction";
import type { Sandbox } from "./sandbox";
import { HARNESS } from "./version";

export interface SelfCheckOptions extends RunOptions {
  /** Where the harness writes; next to the bundle by default, never inside it. */
  out?: string;
}

/**
 * A publisher's check of its own bundle before submitting: the same hidden-content scan, the
 * same sandbox, and the same comparison a verifier's harness will run, with no node involved.
 * Exits 0 only when every claim with a computation comes out reproduced.
 */
export async function selfCheck(bundleDir: string, options: SelfCheckOptions, deps: Deps, sandbox?: Sandbox): Promise<number> {
  const root = resolve(bundleDir);
  if (!(await stat(root).catch(() => null))?.isDirectory()) throw new HarnessError(`${bundleDir} isn't a directory`);
  const outDir = resolve(options.out ?? `${root}-harness`);
  const fromRoot = relative(root, outDir);
  if (!(fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot))) {
    throw new HarnessError("The harness's own files can't go inside the bundle, where they would become part of it; give --out a directory outside it.");
  }

  // Read what's small, and digest what's large in pieces, as large data is sent ahead of a bundle.
  const paths = await listFiles(root);
  const sizes = new Map(await Promise.all(paths.map(async (path) => [path, (await stat(under(root, path))).size] as const)));
  const small = [...sizes].filter(([, bytes]) => bytes <= SCAN_LIMIT).map(([path]) => path);
  const files = await readFiles(root, small);
  const large = new Map<string, Digest>();
  for (const [path, bytes] of sizes) if (bytes > SCAN_LIMIT) large.set(path, `sha256:${await sha256File(under(root, path))}`);
  let digests: ReturnType<typeof digestBundle>;
  try {
    digests = digestBundle(files, large);
  } catch (error) {
    if (error instanceof BundleLayoutError) throw new HarnessError(`A node would refuse this bundle: ${error.message}`);
    throw error;
  }

  let pointers: ExternalData;
  try {
    pointers = await readPointers(root, paths);
  } catch (error) {
    if (error instanceof HarnessError) throw new HarnessError(`A node would refuse this bundle: ${error.message}`);
    throw error;
  }

  const manifest = ManifestSchema.safeParse(json(files, "manifest.json"));
  if (!manifest.success) {
    throw new HarnessError(`manifest.json doesn't check: ${manifest.error.issues.map((issue) => `/${issue.path.join("/")} ${issue.message}`).join("; ")}`);
  }
  const paper = files.get("paper.md");
  if (!paper) throw new HarnessError("The bundle has no paper.md");
  const over = paperOverLimits(new TextDecoder().decode(paper));
  if (over.length > 0) throw new HarnessError(`A node would refuse this bundle: ${over.map(overLimitMessage).join("; ")}.`);
  const inputs = bundleInputs(files, digests.verificationInputs);
  const claimsJson = json(files, "claims.json");
  const checked = checkClaims(claimsJson, { ...inputs, has: (path) => sizes.has(path) });
  if (!checked.valid) {
    throw new HarnessError(`claims.json doesn't check: ${checked.issues.map((issue) => `${issue.path} ${issue.message}`).join("; ")}`);
  }
  // Valid claims parse; checkClaims gives their IDs in the same order.
  const claims = ClaimsFileSchema.parse(claimsJson).map((claim, i) => ({
    local_id: claim.local_id,
    claim_id: checked.claims[i].claim_id!,
    computations: claim.evidence.filter(isComputation),
    proofs: claim.evidence.filter(isProof),
  }));
  const reproducible = claims.filter((claim) => claim.computations.length > 0).map((claim) => ({ ...claim, proofs: [] }));
  const provable = claims.filter((claim) => claim.proofs.length > 0).map((claim) => ({ ...claim, computations: [] }));

  const scan: ScanRecord = {
    harness: HARNESS,
    ...scanFiles(small.map((path) => [path, files.get(path)!] as const)),
    skipped: [...sizes].filter(([, bytes]) => bytes > SCAN_LIMIT).map(([path, bytes]) => ({ path, bytes })),
  };
  await writeJsonFile(join(outDir, "scan.json"), scan);
  const bundleBytes = [...sizes.values()].reduce((a, b) => a + b, 0);
  deps.print(`Bundle ${digests.bundle}: ${plural(paths.length, "file")}, ${size(bundleBytes)}.`);
  const pointed = describePointers(pointers);
  if (pointed) {
    deps.print(
      `It points at ${pointed} in data/external.json. Verifiers fetch each one before they run the work, so only those that can download ${size(bundleBytes + externalBytes(pointers))} in all are given work that re-runs it.`,
    );
  }
  const builtCode = scan.binary.filter((path) => path.startsWith("code/"));
  if (builtCode.length > 0) {
    deps.print(
      `code/ holds files that aren't text, often what running it locally left behind, such as caches: ${builtCode.slice(0, 5).join(", ")}. Every file under code/ is part of each computed claim's ID; leave out what the work doesn't need.`,
    );
  }
  if (scan.findings.length > 0) {
    deps.print(`The hidden-content scan found ${plural(scan.findings.length, "thing")} a verifier's harness will flag (see ${join(outDir, "scan.json")}):`);
    for (const finding of scan.findings.slice(0, 8)) deps.print(`  ${finding.path}:${finding.line}:${finding.column} ${finding.kind}`);
  }
  await checkFlagged(files, paths, deps);
  if (reproducible.length === 0 && provable.length === 0) {
    deps.print("No claim's evidence has a computation or a proof, so there is nothing to re-run or check.");
    return 0;
  }

  if (reproducible.length > 0 && provable.length > 0 && (options.image || options.command)) {
    throw new HarnessError(
      "This bundle has computations and proofs, which run differently, so --image and --command would apply to both. Give neither: each then runs from env/, the way a verifier's harness will run it.",
    );
  }
  // As verifiers will: computations re-run as a reproduction, and proofs checked as a proof check.
  const common = {
    bundle: digests.bundle,
    bundleDir: root,
    verificationInputs: digests.verificationInputs,
    files: Object.fromEntries([...sizes].map(([path, bytes]) => [path, { digest: digests.files[path], bytes }])),
    declaredMinutes: manifest.data.compute.minutes,
    // Shared by the reproduction and the proof check, so a file is fetched once.
    externalDir: join(outDir, "external"),
  };
  let passed = true;
  if (reproducible.length > 0) {
    const { run, verdicts } = await runSubject(
      { ...common, kind: "self_check", outDir, evidenceDir: join(outDir, "evidence"), claims: reproducible },
      options,
      deps,
      sandbox,
    );
    // What a verifier's harness would do differently, or what would cost the publisher.
    const declared = manifest.data.compute.minutes;
    if (run?.result && !run.result.timedOut && run.result.seconds > declared * 60) {
      deps.print(`It took ${Math.ceil(run.result.seconds / 60)} minutes, more than the ${declared} the manifest declares; verifiers may report it over budget.`);
    }
    const reproduced = verdicts.claims.every((claim) => claim.verdict === "reproduced");
    deps.print(reproduced ? "Every computed claim reproduced, as verifiers will need it to." : "Not every computed claim reproduced; fix that before you submit.");
    passed &&= reproduced;
  }
  if (provable.length > 0) {
    const proofDir = join(outDir, "proof-check");
    await writeJsonFile(join(proofDir, "scan.json"), scan);
    const { verdicts } = await runSubject(
      { ...common, kind: "proof_check", outDir: proofDir, evidenceDir: join(proofDir, "evidence"), claims: provable },
      options,
      deps,
      sandbox,
    );
    const checked = verdicts.claims.every((claim) => claim.verdict === "passed");
    deps.print(checked ? "Every proof checked, as verifiers will need it to." : "Not every proof checked; fix that before you submit.");
    passed &&= checked;
  }
  if (options.image || options.command) {
    deps.print(
      reproducible.length > 0
        ? "You gave --image or --command; a verifier's harness won't. Put the environment in env/ (a Dockerfile, requirements.txt, or environment.yml) and the command in code/run, so it runs the same way for them."
        : "You gave --image or --command; a verifier's harness won't. Put an env/Dockerfile that builds the checker, with the toolchain your proofs pin (and for Lean, the toolchain in proofs/lean-toolchain), so they are checked the same way for verifiers.",
    );
  }
  return passed ? 0 : 1;
}

/**
 * What the node will flag for verifiers in the paper and its references: numbers not bound to
 * declared results, missing sections, uncited or unlisted sources, and missing files, so the
 * publisher can fix them first. Then what each RRID in materials.json resolves to, which
 * reviewers' harnesses look up.
 */
async function checkFlagged(files: ReadonlyMap<string, Uint8Array>, paths: string[], deps: Deps): Promise<void> {
  const flags = integrityFlags(files, paths);
  if (flags.orphan_numbers.length > 0) {
    deps.print(
      `paper.md writes ${plural(flags.orphan_numbers.length, "number")} into its Summary, Claims, or Results that no declared result binds, in digits or in words; verifiers will see each flagged. Give a result as a placeholder such as {{R1.key}}, and a parameter in Methods:`,
    );
    for (const found of flags.orphan_numbers.slice(0, 20)) deps.print(`  line ${found.line}, column ${found.column}, in ${found.section}: ${found.number}`);
    if (flags.orphan_numbers.length > 20) deps.print(`  and ${flags.orphan_numbers.length - 20} more`);
  }
  if (flags.missing_sections.length > 0) {
    deps.print(`paper.md has no ${flags.missing_sections.join(", ")} ${flags.missing_sections.length === 1 ? "section" : "sections"}; verifiers will see that flagged.`);
  }
  if (flags.uncited_references.length > 0) {
    deps.print(
      `references.json lists ${plural(flags.uncited_references.length, "source")} that paper.md never cites: ${flags.uncited_references.join(", ")}. Cite each where you use it, as a link to its ID, such as [Klebanoff (2001)](doi:10.1142/S0218348X01000828); verifiers will see that flagged.`,
    );
  }
  if (flags.unlisted_citations.length > 0) {
    deps.print(
      `paper.md cites ${plural(flags.unlisted_citations.length, "source")} that references.json doesn't list: ${flags.unlisted_citations.join(", ")}. List each there; verifiers will see that flagged.`,
    );
  }
  for (const path of flags.missing_files) deps.print(`The bundle has no ${path}, though ${MISSING_FILE_REASONS[path]}; verifiers will see that flagged.`);
  if (!files.has("materials.json")) return;
  const materials = readMaterials(files.get("materials.json"));
  if (!materials) {
    deps.print("materials.json doesn't fit its schema, so a node will refuse the bundle; /api/v1/schemas/materials.json has it.");
    return;
  }
  if (!materials.some((material) => material.rrid)) return;
  for (const lookup of (await checkMaterials(materials, deps)).lookups) {
    if (lookup.found === "unknown") deps.print(`materials.json gives ${lookup.rrid}, which the RRID resolver doesn't know.`);
    if (lookup.found === "unreachable") deps.print(`Couldn't reach the RRID resolver to look up ${lookup.rrid}.`);
    for (const problem of lookup.problems) deps.print(`${lookup.rrid}${lookup.name ? ` (${lookup.name})` : ""}: ${problem}`);
  }
}

function json(files: ReadonlyMap<string, Uint8Array>, path: string): unknown {
  const bytes = files.get(path);
  if (!bytes) throw new HarnessError(`The bundle has no ${path}`);
  try {
    return parseJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (error) {
    throw new HarnessError(`${path} isn't valid JSON: ${(error as Error).message}`);
  }
}
