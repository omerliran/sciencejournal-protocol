import { BundleLayoutError, checkFolderPaths } from "./bundle";
import { canonicalDigest, sha256Digest, type Digest } from "./hash";
import { PLAN_DIRECTORY, planDigest } from "./preregistration";

// A plan's workshop version: the folder an author shares so other agents can review its plan
// before it registers it. Its plan/ holds exactly what will be registered, and beside it, under
// the other directories a bundle has (code/, env/, data/, results/), sits what its reviewers need
// to run it: data with its outcomes taken out, the script that takes them out, a simulation
// harness. Registering it is registering plan/ alone (planDigest), and the report carries the
// same plan/; what sits beside it is never registered.

/** A plan folder's digests: each file's, the folder's as a bundle hash is made, and what registering its plan/ takes. */
export interface PlanFolderDigests {
  /** SHA-256 of every file's bytes, keyed by its path in the folder. */
  files: Record<string, Digest>;
  /** Every file of the folder, plan/ and what sits beside it: the version's digest, which reviews name. */
  folder: Digest;
  /** Its plan/ alone, with paths relative to plan/: what a registration of it names. */
  plan: Digest;
}

/**
 * Hashes a plan folder given as path -> bytes, with large files sent ahead in `uploaded` by
 * digest. Every path sits under a bundle's directories, and something sits under plan/;
 * anything else throws BundleLayoutError.
 */
export function digestPlanFolder(files: ReadonlyMap<string, Uint8Array>, uploaded: ReadonlyMap<string, Digest> = new Map()): PlanFolderDigests {
  const twice = [...uploaded.keys()].find((path) => files.has(path));
  if (twice) throw new BundleLayoutError(`"${twice}" is both sent and uploaded`, [twice]);
  checkFolderPaths([...files.keys(), ...uploaded.keys()]);
  const digests: Record<string, Digest> = {
    ...Object.fromEntries([...files].map(([path, bytes]) => [path, sha256Digest(bytes)])),
    ...Object.fromEntries(uploaded),
  };
  const plan = planDigest(digests);
  if (plan === null) throw new BundleLayoutError(`Nothing is under ${PLAN_DIRECTORY}/: a plan folder holds the plan to register there`);
  return { files: digests, folder: canonicalDigest(digests), plan };
}

/**
 * What a helper will be able to run of a plan, worked out from its files' names and contents
 * alone, with no model: it advises and never refuses. `notes` says it in words, allowing for
 * plans that rightly lack an item, such as one for data not collected yet.
 */
export interface PlanCheck {
  /** What registering this plan takes, as the registration's `plan`. */
  plan: Digest;
  /** Code under plan/, the first few. */
  code: string[];
  /** What pins the environment its code runs in: Dockerfiles whose every image is named by digest, and lockfiles; and Dockerfiles naming an image by tag. */
  environment: { pinned: string[]; unpinned: string[] };
  /** Files plan/ names by digest, how many of them this version holds, and the first few it doesn't. */
  data: { named: number; held: number; missing: Digest[] };
  /** Tests, and their output under results/, the first few. */
  tests: string[];
  /** How many files sit beside plan/, for helpers and never registered. */
  beside: number;
  notes: string[];
}

const LISTED = 5;

/** The most of one file's text the check reads for the digests it names. */
const READ_BYTES = 2 * 1024 * 1024;

const CODE_EXTENSIONS = new Set([
  "py", "r", "jl", "js", "mjs", "ts", "sh", "bash", "do", "ado", "sas", "m", "lean", "ipynb", "sql", "stan", "rs", "c", "cc", "cpp", "go", "java", "scala", "rmd", "qmd", "f90", "pl", "rb", "nf", "wdl", "smk",
]);
const CODE_NAMES = new Set(["makefile", "snakefile", "justfile"]);
const LOCKFILES = new Set([
  "renv.lock", "poetry.lock", "uv.lock", "pipfile.lock", "pdm.lock", "pixi.lock", "conda-lock.yml", "environment.lock.yml", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "cargo.lock", "go.sum", "manifest.toml", "flake.lock", "lake-manifest.json",
]);

const basename = (path: string) => path.slice(path.lastIndexOf("/") + 1).toLowerCase();
const extension = (path: string) => {
  const name = basename(path);
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot + 1) : "";
};
const isDockerfile = (path: string) => /^(dockerfile|containerfile)(\..+)?$/.test(basename(path)) || basename(path).endsWith(".dockerfile");
const isTest = (path: string) =>
  path.split("/").some((segment) => /^(tests?|spec)$/i.test(segment)) || /^test_|_test\.|\.test\.|_spec\.|\.spec\./.test(basename(path)) || path.startsWith("results/");

const text = (bytes: Uint8Array | undefined) => (bytes ? new TextDecoder("utf-8").decode(bytes.subarray(0, READ_BYTES)) : "");

/** Whether every image a Dockerfile builds from is named by digest: a stage built earlier, or scratch, needs none. */
function pinsImages(dockerfile: string): boolean {
  const stages = new Set<string>();
  let images = 0;
  for (const match of dockerfile.matchAll(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/gim)) {
    const image = match[1];
    images++;
    if (match[2]) stages.add(match[2].toLowerCase());
    if (image === "scratch" || stages.has(image.toLowerCase()) || /@sha256:[0-9a-f]{64}$/.test(image)) continue;
    return false;
  }
  return images > 0;
}

/** Whether a requirements file pins every package to one version. */
const pinsRequirements = (requirements: string) => {
  const lines = requirements.split("\n").map((line) => line.replace(/#.*/, "").trim()).filter((line) => line && !line.startsWith("-"));
  return lines.length > 0 && lines.every((line) => /===?[^=,;<>!~*]+$|===?[^=,;<>!~*]+\s*;/.test(line) || /\s--hash=/.test(line));
};

/** Checks a plan folder as a workshop takes it: `files` are those sent, `uploaded` those sent ahead, by path. */
export function planCheck(files: ReadonlyMap<string, Uint8Array>, uploaded: ReadonlyMap<string, Digest> = new Map()): PlanCheck {
  const digests = digestPlanFolder(files, uploaded);
  const paths = Object.keys(digests.files).sort();
  const inPlan = paths.filter((path) => path.startsWith(`${PLAN_DIRECTORY}/`));
  const code = inPlan.filter((path) => CODE_EXTENSIONS.has(extension(path)) || CODE_NAMES.has(basename(path)));
  const pinned: string[] = [];
  const unpinned: string[] = [];
  for (const path of paths) {
    const name = basename(path);
    if (isDockerfile(path)) (pinsImages(text(files.get(path))) ? pinned : unpinned).push(path);
    else if (LOCKFILES.has(name) || (/^requirements.*\.(txt|lock)$/.test(name) && pinsRequirements(text(files.get(path))))) pinned.push(path);
  }
  const held = new Set(Object.values(digests.files));
  const named = new Set<Digest>();
  // Images and packages a Dockerfile or lockfile pins by digest are its environment, not its data.
  const environment = new Set([...pinned, ...unpinned]);
  for (const path of inPlan.filter((path) => !environment.has(path))) {
    for (const match of text(files.get(path)).matchAll(/(?<![@=])sha256:[0-9a-f]{64}/g)) named.add(match[0] as Digest);
  }
  // A digest of a file under plan/ itself names the plan, not its data.
  for (const path of inPlan) named.delete(digests.files[path]);
  const missing = [...named].filter((digest) => !held.has(digest));
  const tests = paths.filter(isTest);
  const beside = paths.length - inPlan.length;

  const notes: string[] = [];
  if (code.length === 0) {
    notes.push(
      "plan/ holds no code, so helpers can read this plan but not run it. That's fine for a plan written before its code, or one that is prose by nature; if its analysis will be code, put the code under plan/ now, since only what's under plan/ is registered.",
    );
  } else if (pinned.length === 0) {
    notes.push(
      "Nothing pins the environment the plan's code runs in: no Dockerfile whose every FROM names an image by digest, and no lockfile. Helpers can still run it, but may get other versions of what it imports than your report will.",
    );
  }
  for (const path of unpinned.slice(0, LISTED)) notes.push(`${path} names an image by tag, which can change under it; name it by digest (image@sha256:...).`);
  if (named.size === 0) {
    notes.push(
      "plan/ names no data by digest. That's fine for data not collected yet; for data that exists, naming each file by its digest says which data the plan is for, so no one can swap it later.",
    );
  } else if (missing.length > 0) {
    notes.push(
      `plan/ names ${missing.length === 1 ? "a file" : `${missing.length} files`} by digest that this version doesn't hold, so helpers can't run on ${missing.length === 1 ? "it" : "them"} unless they can fetch ${missing.length === 1 ? "it" : "them"} themselves. Where the data has outcomes, send a copy with them taken out beside plan/, under data/, rather than the data itself.`,
    );
  }
  if (code.length > 0 && tests.length === 0) {
    notes.push("No tests or test output: helpers find more when the plan's code comes with tests on simulated data showing each estimator and decision rule does what the plan says.");
  }
  if (code.length > 0 && beside === 0 && named.size > 0) {
    notes.push(
      "Nothing sits beside plan/ for helpers. Send the data with its outcomes taken out, or the script that takes them out, under data/ or code/, so helpers can run the analysis on the real design without seeing results.",
    );
  }
  if (notes.length === 0) notes.push("Helpers can run this plan: its code, the environment it runs in, its data, and its tests are all here.");
  return {
    plan: digests.plan,
    code: code.slice(0, LISTED),
    environment: { pinned: pinned.slice(0, LISTED), unpinned: unpinned.slice(0, LISTED) },
    data: { named: named.size, held: named.size - missing.length, missing: missing.slice(0, LISTED) },
    tests: tests.slice(0, LISTED),
    beside,
    notes,
  };
}
