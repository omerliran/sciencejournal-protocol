import { z } from "zod";
import { BundleLayoutError, checkPointedPaths } from "./bundle";
import { DigestSchema } from "./hash";
import { toIssues, type Issue } from "./validate";

/** Where a bundle lists the public files it points at instead of carrying them. */
export const EXTERNAL_DATA = "data/external.json";

/**
 * The most a bundle may point at in all, 10 TB: as much as any job request can say its
 * verifier downloads, so no more could ever be run.
 */
export const MAX_EXTERNAL_BYTES = 10_000_000 * 1_000_000;

/**
 * A public file a bundle's work reads without carrying it: where the work reads it (under
 * data/), the https URL of its exact bytes, their SHA-256 and size, their license, and
 * optionally the DOI of the dataset it belongs to, which cites it and finds it again if the
 * URL moves. Verifiers fetch each file from its URL, check it, and put it at its path before
 * the work runs, so the work reads it as if the bundle carried it.
 */
export const ExternalFileSchema = z.strictObject({
  path: z.string().min(1).max(1024),
  url: z.string().max(2048).refine(isHttpsUrl, "Expected an https URL"),
  sha256: DigestSchema,
  bytes: z.number().int().positive().max(MAX_EXTERNAL_BYTES),
  license: z.string().min(1).max(200),
  doi: z.string().regex(/^10\.[0-9]{4,9}\/\S+$/, "Expected a DOI such as 10.5281/zenodo.1234567").optional(),
});
export type ExternalFile = z.infer<typeof ExternalFileSchema>;

/**
 * data/external.json: the public files a bundle points at. Only data that was public before
 * the bundle belongs here; data the work collected travels with the bundle, so verifiers can
 * screen it while it is sealed. A pointer at a deposit of the author's own would also tell
 * a verifier whose sealed work it is.
 */
export const ExternalDataSchema = z
  .array(ExternalFileSchema)
  .min(1)
  .max(1000)
  .refine((files) => externalBytes(files) <= MAX_EXTERNAL_BYTES, {
    message: `The files together are more than the ${MAX_EXTERNAL_BYTES / 1e12} TB any verifier can say it downloads`,
  });
export type ExternalData = z.infer<typeof ExternalDataSchema>;

/** Whether a string is an https URL as written, with nothing a parser would have to fix. */
function isHttpsUrl(value: string): boolean {
  if (!value.startsWith("https://") || /\s/.test(value)) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

/** How many bytes a verifier downloads to run work that points at these files. */
export function externalBytes(files: readonly Pick<ExternalFile, "bytes">[]): number {
  return files.reduce((total, file) => total + file.bytes, 0);
}

/**
 * Reads data/external.json against the bundle's other paths: its entries must fit the schema,
 * and their paths must sit under data/ and keep the bundle's path rules beside its own files,
 * so every file can go where its path says. `paths` is every path the bundle has, sent or
 * uploaded. Returns the files, or the issues that keep them from being used.
 */
export function readExternalData(
  value: unknown,
  paths: Iterable<string>,
): { files: ExternalData; issues: null } | { files: null; issues: Issue[] } {
  const parsed = ExternalDataSchema.safeParse(value);
  if (!parsed.success) return { files: null, issues: toIssues(parsed.error) };
  try {
    checkPointedPaths(paths, parsed.data.map((file) => file.path));
  } catch (error) {
    if (!(error instanceof BundleLayoutError)) throw error;
    // The later of two entries that clash is the one at fault.
    const index = parsed.data.findLastIndex((file) => error.paths.includes(file.path));
    return { files: null, issues: [{ path: index >= 0 ? `/${index}/path` : "", message: error.message }] };
  }
  return { files: parsed.data, issues: null };
}
