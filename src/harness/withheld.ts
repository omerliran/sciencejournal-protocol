import { randomBytes } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { canonicalJson } from "../canonical";
import type { Digest } from "../hash";
import { parseJson } from "../json";
import {
  checkWithheldOpening,
  readWithheldData,
  withheldBytes,
  withheldCommitment,
  WITHHELD_DATA,
  WithheldOpeningSchema,
  WithheldSetSchema,
  type WithheldData,
  type WithheldOpening,
} from "../withheld";
import { HarnessError, type Deps } from "./context";
import { exists, listFiles, sha256File, under, writeUnder } from "./files";
import { plural, shellQuote, size } from "./format";

/**
 * The data a bundle withholds, from its data/withheld.json: none when it has no such file.
 * Throws when the file can't be used, as a node refuses a bundle whose file breaks the schema.
 */
export async function readWithheld(bundleDir: string, paths: Iterable<string>): Promise<WithheldData | []> {
  if (![...paths].includes(WITHHELD_DATA)) return [];
  let value: unknown;
  try {
    value = parseJson(await readFile(under(bundleDir, WITHHELD_DATA), "utf8"));
  } catch (error) {
    throw new HarnessError(`${WITHHELD_DATA} isn't valid JSON: ${(error as Error).message}`);
  }
  const read = readWithheldData(value);
  if (read.issues) {
    throw new HarnessError(`${WITHHELD_DATA} can't be used: ${read.issues.map((issue) => `${issue.path || "/"} ${issue.message}`).join("; ")}`);
  }
  return read.sets;
}

/** One line saying what a bundle withholds, or nothing when it withholds nothing. */
export function describeWithheld(sets: readonly { files: number; bytes: number }[]): string | null {
  if (sets.length === 0) return null;
  const files = sets.reduce((total, set) => total + set.files, 0);
  return `${plural(files, "file")} (${size(withheldBytes(sets))}) in ${plural(sets.length, "set")}`;
}

export interface WithholdOptions {
  name?: string;
  /** Where the opening goes; `<name>.opening.json` beside the data's folder by default. */
  out?: string;
  /** The nonce to commit with; 16 random bytes unless a test gives its own. */
  nonce?: string;
}

/**
 * Commits to a folder of data its author withholds: digests every file in it, and writes the
 * opening, the list of those digests with a random nonce, outside the folder. Prints what the
 * bundle's data/withheld.json says of the set: how many files, how many bytes, and the
 * commitment. It reads the files only to digest them, and prints nothing they hold.
 */
export async function withhold(dataDir: string, options: WithholdOptions, deps: Deps): Promise<number> {
  const root = resolve(dataDir);
  if (!(await stat(root).catch(() => null))?.isDirectory()) throw new HarnessError(`${dataDir} isn't a directory`);
  const name = WithheldSetSchema.shape.name.safeParse(options.name);
  if (!name.success) {
    throw new HarnessError('Name the set with --name, in lowercase letters, digits, and hyphens, such as --name scans: the paper and data/withheld.json call it that.', 2);
  }
  const out = resolve(options.out ?? `${dirname(root)}${sep}${name.data}.opening.json`);
  const fromRoot = relative(root, out);
  if (!(fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot))) {
    throw new HarnessError("The opening can't go inside the folder it commits to, where it would be one of the files; give --out a path outside it.");
  }
  if (await exists(out)) {
    throw new HarnessError(
      `${out} is already there. An opening can't be made again: a new one has a new nonce, so it opens no commitment a bundle already made. Move it aside or give --out another path.`,
    );
  }
  const paths = await listFiles(root);
  if (paths.length === 0) throw new HarnessError(`${dataDir} holds no files`);
  deps.print(`Digesting ${plural(paths.length, "file")} under ${root}...`);
  const files: WithheldOpening["files"] = [];
  for (const path of paths) {
    const full = under(root, path);
    files.push({ path, sha256: `sha256:${await sha256File(full)}` as Digest, bytes: (await stat(full)).size });
  }
  const opening: WithheldOpening = { nonce: options.nonce ?? randomBytes(16).toString("hex"), files };
  const parsed = WithheldOpeningSchema.safeParse(opening);
  if (!parsed.success) throw new HarnessError(`These files can't be committed to: ${parsed.error.issues.map((issue) => issue.message).join("; ")}`);
  const bytes = files.reduce((total, file) => total + file.bytes, 0);
  const set = { name: name.data, files: files.length, bytes, commitment: withheldCommitment(opening) };
  const wrong = checkWithheldOpening(set, opening);
  if (wrong.length > 0) throw new HarnessError(`These files can't be committed to: ${wrong.map((issue) => issue.message).join("; ")}`);
  // Canonical, so the bytes kept are the bytes the commitment digests.
  await writeUnder(dirname(out), basename(out), canonicalJson(opening), 0o600);
  deps.print(`Committed to ${plural(files.length, "file")} (${size(bytes)}).`);
  deps.print(`Wrote the opening to ${out}. Keep it with the data and out of the bundle: it is what later shows these are the files, and it can't be made again.`);
  deps.print(`In the bundle's ${WITHHELD_DATA}, the set says:`);
  deps.print(JSON.stringify(set, null, 2));
  deps.print(`Add its "description", "reason", "why", and "access" in your own words, naming no person and no institution.`);
  return 0;
}

export interface CheckWithheldOptions {
  opening?: string;
  /** A bundle's folder, to check the opening against the commitment its data/withheld.json makes. */
  bundle?: string;
}

/**
 * Checks a folder of data against an opening: every file the opening lists is there, as large
 * as it says and with its SHA-256. With a bundle, also that the opening is the one a set in the
 * bundle's data/withheld.json commits to. Exits 0 only when everything asked checks.
 */
export async function checkWithheld(dataDir: string, options: CheckWithheldOptions, deps: Deps): Promise<number> {
  const root = resolve(dataDir);
  if (!(await stat(root).catch(() => null))?.isDirectory()) throw new HarnessError(`${dataDir} isn't a directory`);
  if (!options.opening) throw new HarnessError("Give the opening with --opening <file>: the list of files and the nonce its author kept.", 2);
  let value: unknown;
  try {
    value = parseJson(await readFile(resolve(options.opening), "utf8"));
  } catch (error) {
    throw new HarnessError(`${options.opening} can't be read as JSON: ${(error as Error).message}`);
  }
  const parsed = WithheldOpeningSchema.safeParse(value);
  if (!parsed.success) {
    throw new HarnessError(`${options.opening} isn't an opening: ${parsed.error.issues.map((issue) => `/${issue.path.join("/")} ${issue.message}`).join("; ")}`);
  }
  const opening = parsed.data;
  const bytes = opening.files.reduce((total, file) => total + file.bytes, 0);
  const commitment = withheldCommitment(opening);
  let passed = true;

  if (options.bundle) {
    const bundleDir = resolve(options.bundle);
    const sets = await readWithheld(bundleDir, await listFiles(bundleDir));
    const set = sets.find((candidate) => candidate.commitment === commitment);
    if (!set) {
      passed = false;
      deps.print(
        sets.length === 0
          ? `${bundleDir} has no ${WITHHELD_DATA}, so it commits to no withheld data.`
          : `No set in the bundle's ${WITHHELD_DATA} commits to this opening (${commitment}). Its sets: ${sets.map((candidate) => candidate.name).join(", ")}.`,
      );
    } else {
      const wrong = checkWithheldOpening(set, opening);
      if (wrong.length > 0) passed = false;
      deps.print(
        wrong.length > 0
          ? `The opening digests to the commitment of the bundle's set "${set.name}", but: ${wrong.map((issue) => issue.message).join("; ")}.`
          : `The opening is the one the bundle's set "${set.name}" commits to: ${plural(set.files, "file")}, ${size(set.bytes)}.`,
      );
    }
  } else {
    const wrong = checkWithheldOpening({ files: opening.files.length, bytes, commitment }, opening);
    if (wrong.length > 0) {
      passed = false;
      deps.print(`The opening doesn't hold together: ${wrong.map((issue) => issue.message).join("; ")}.`);
    }
    deps.print(`The opening commits to ${commitment}. Give --bundle <bundle dir> to check it against a study's ${WITHHELD_DATA}.`);
  }

  deps.print(`Digesting ${plural(opening.files.length, "file")} under ${root}...`);
  const problems: string[] = [];
  for (const file of opening.files) {
    const full = under(root, file.path);
    const found = await stat(full).catch(() => null);
    if (!found?.isFile()) problems.push(`${file.path} is missing`);
    else if (found.size !== file.bytes) problems.push(`${file.path} is ${found.size} bytes, not ${file.bytes}`);
    else if (`sha256:${await sha256File(full)}` !== file.sha256) problems.push(`${file.path} has other bytes than the opening says`);
  }
  const listed = new Set(opening.files.map((file) => file.path));
  const extra = (await listFiles(root)).filter((path) => !listed.has(path));
  if (problems.length > 0) {
    passed = false;
    deps.print(`${plural(problems.length, "file")} of ${opening.files.length} ${problems.length === 1 ? "doesn't" : "don't"} check:`);
    for (const problem of problems.slice(0, 20)) deps.print(`  ${problem}`);
    if (problems.length > 20) deps.print(`  and ${problems.length - 20} more`);
  } else {
    deps.print(`Every file the opening lists is here with the size and SHA-256 it says: ${plural(opening.files.length, "file")}, ${size(bytes)}.`);
  }
  if (extra.length > 0) {
    // What the folder gained since doesn't change what was committed to, but the work may read it.
    deps.print(
      `The folder also holds ${plural(extra.length, "file")} the opening doesn't list, which no commitment covers: ${extra.slice(0, 5).map(shellQuote).join(", ")}${extra.length > 5 ? `, and ${extra.length - 5} more` : ""}.`,
    );
  }
  return passed ? 0 : 1;
}
