import { z } from "zod";
import { BundleLayoutError, checkPortablePaths } from "./bundle";
import { NonceSchema } from "./entries";
import { canonicalDigest, DigestSchema, type Digest } from "./hash";
import { toIssues, type Issue } from "./validate";

// Withheld data: source data a bundle's work rests on that may not be made public, such as
// recordings of people who didn't agree to their release. The bundle neither carries it nor
// points at it. It says what it withholds and why, and commits to the exact files, so the data
// can't change afterwards and anyone later given it can show they hold the same bytes. What
// the bundle carries is what its verifiers check; the record says plainly what it leaves out.

/** Where a bundle lists the data it withholds. */
export const WITHHELD_DATA = "data/withheld.json";

/** Why data may be withheld. */
export const WITHHELD_REASONS = ["consent", "agreement", "law", "safety", "other"] as const;
export type WithheldReason = (typeof WITHHELD_REASONS)[number];

/** What each reason says, each finishing "It is withheld because …". */
export const WITHHELD_REASON_MEANINGS: Readonly<Record<WithheldReason, string>> = {
  consent: "the people it is about didn't agree to its release, or the ethics approval it was collected under doesn't allow it",
  agreement: "it is held under an agreement that forbids publishing it, such as a data use agreement",
  law: "a law or regulation forbids publishing it",
  safety: "publishing it could harm people, places, or living things, such as where an endangered species nests",
  other: "of something else, which its author says",
};

/** The most sets a bundle withholds, and the most files in one. */
export const MAX_WITHHELD_SETS = 20;
export const MAX_WITHHELD_FILES = 1_000_000;

const text = (max: number) => z.string().min(1).max(max);

/**
 * One set of withheld files: a short name the paper and the code use, what it holds in words
 * that identify no one, why it is withheld, who could be given it and how, how many files and
 * bytes it is, and the commitment to them. The words are the author's, read by verifiers who
 * must not learn whose work it is, so they name no person and no institution.
 */
export const WithheldSetSchema = z.strictObject({
  name: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/, "Expected a short name in lowercase letters, digits, and hyphens"),
  description: text(1000),
  reason: z.enum(WITHHELD_REASONS),
  /** What forbids its release, such as what the consent form or the agreement says. */
  why: text(1000),
  /** Who could be given the data to check the work, and how they would ask; or that no one can. */
  access: text(1000),
  files: z.number().int().positive().max(MAX_WITHHELD_FILES),
  bytes: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  commitment: DigestSchema,
});
export type WithheldSet = z.infer<typeof WithheldSetSchema>;

/** data/withheld.json: the sets of data a bundle's work rests on and withholds. */
export const WithheldDataSchema = z
  .array(WithheldSetSchema)
  .min(1)
  .max(MAX_WITHHELD_SETS)
  .superRefine((sets, context) => {
    const seen = new Set<string>();
    sets.forEach((set, index) => {
      if (seen.has(set.name)) context.addIssue({ code: "custom", path: [index, "name"], message: `Two sets are named "${set.name}"` });
      seen.add(set.name);
    });
  });
export type WithheldData = z.infer<typeof WithheldDataSchema>;

/**
 * What opens a commitment: every file of the set, by its path within the set, its SHA-256,
 * and its size, in order of path, with a random nonce. The author keeps it beside the data and
 * never publishes it: without the nonce, a commitment tells no one anything about the files,
 * not even whether a guess at one is right.
 */
export const WithheldOpeningSchema = z.strictObject({
  nonce: NonceSchema,
  files: z
    .array(z.strictObject({ path: z.string().min(1).max(1024), sha256: DigestSchema, bytes: z.number().int().nonnegative() }))
    .min(1)
    .max(MAX_WITHHELD_FILES),
});
export type WithheldOpening = z.infer<typeof WithheldOpeningSchema>;

/** The commitment an opening makes: the digest of its canonical JSON. */
export function withheldCommitment(opening: WithheldOpening): Digest {
  return canonicalDigest(opening);
}

/** How many bytes the sets a bundle withholds are in all. */
export function withheldBytes(sets: readonly Pick<WithheldSet, "bytes">[]): number {
  return sets.reduce((total, set) => total + set.bytes, 0);
}

/** Reads data/withheld.json: the sets, or the issues that keep it from being used. */
export function readWithheldData(value: unknown): { sets: WithheldData; issues: null } | { sets: null; issues: Issue[] } {
  const parsed = WithheldDataSchema.safeParse(value);
  return parsed.success ? { sets: parsed.data, issues: null } : { sets: null, issues: toIssues(parsed.error) };
}

/**
 * Checks an opening against the set it is said to open: its files in order of path, each path
 * portable and given once, as many files and bytes as the set says, and digesting to the set's
 * commitment. Returns what is wrong, or nothing when the opening is the set's.
 */
export function checkWithheldOpening(set: Pick<WithheldSet, "files" | "bytes" | "commitment">, value: unknown): Issue[] {
  const parsed = WithheldOpeningSchema.safeParse(value);
  if (!parsed.success) return toIssues(parsed.error);
  const opening = parsed.data;
  const paths = opening.files.map((file) => file.path);
  try {
    checkPortablePaths(paths);
  } catch (error) {
    if (!(error instanceof BundleLayoutError)) throw error;
    return [{ path: "/files", message: error.message }];
  }
  // One order for everyone: by UTF-16 code units, as canonical JSON orders an object's names.
  const unordered = paths.findIndex((path, index) => index > 0 && !(paths[index - 1] < path));
  if (unordered > 0) return [{ path: `/files/${unordered}/path`, message: `"${paths[unordered]}" is out of order: files go in order of path` }];
  const issues: Issue[] = [];
  if (opening.files.length !== set.files) {
    issues.push({ path: "/files", message: `The opening lists ${opening.files.length} files, and the set says ${set.files}` });
  }
  const bytes = opening.files.reduce((total, file) => total + file.bytes, 0);
  if (bytes !== set.bytes) issues.push({ path: "/files", message: `The opening's files are ${bytes} bytes in all, and the set says ${set.bytes}` });
  if (withheldCommitment(opening) !== set.commitment) {
    issues.push({ path: "", message: "The opening doesn't digest to the set's commitment" });
  }
  return issues;
}
