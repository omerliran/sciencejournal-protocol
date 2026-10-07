import { z } from "zod";
import { BundleLayoutError, digestBundle, evidenceDigest } from "./bundle";
import { DigestSchema, type Digest } from "./hash";

// Mirrors: copies of the record that anyone can keep and serve. A mirror holds the log, which
// it audits as a monitor does, and every file the log's entries name by digest that a node
// serves: each open bundle's files, and the evidence verifiers, challengers, and checkers sent
// with their entries. Each file is checked against its own digest, and each entry's files, path
// by path, against the digest its signed entry names, so a copy from anywhere is as good as the
// node's. A withdrawal entry names a bundle no copy may serve any more, with the evidence of
// every entry about it. What a node keeps beside the log rather than on it, such as the words
// of ideas, forum posts, and addenda, is the node's, and a person there may remove it without
// an entry saying so, so a mirror holds none of it.

/** The most entries whose files a node lists in one page, as it serves log entries. */
export const FILES_PER_PAGE = 100;

const IndexSchema = z.number().int().nonnegative();

/**
 * One entry's files as a node serves them at GET /api/v1/files?start=&end=: each file's digest
 * by its path in the bundle or the evidence, and the bundle whose withdrawal stops serving them,
 * the bundle itself or the one the entry is about. A node that didn't keep an entry's paths when
 * it was logged lists its files' digests alone.
 */
export const ServedFilesSchema = z.union([
  z.strictObject({ index: IndexSchema, bundle: DigestSchema.optional(), files: z.record(z.string(), DigestSchema) }),
  z.strictObject({ index: IndexSchema, bundle: DigestSchema.optional(), digests: z.array(DigestSchema) }),
]);
export type ServedFiles = z.infer<typeof ServedFilesSchema>;

/** GET /api/v1/files?start=&end=: the entries in that range whose files the node serves, in log order. */
export const ServedFilesPageSchema = z.object({ entries: z.array(ServedFilesSchema) });

/** What an entry names that has files: a bundle, by its hash, or a verifier's evidence, by its digest. */
export interface NamedFiles {
  kind: "bundle" | "evidence";
  digest: Digest;
}

/** The files an entry names by digest, or null if it names none. */
export function namedFiles(entry: Record<string, unknown>): NamedFiles | null {
  const field = entry.type === "bundle" ? "bundle" : "evidence";
  const digest = DigestSchema.safeParse(entry[field]);
  return digest.success ? { kind: field, digest: digest.data } : null;
}

/** The bundle a withdrawal entry takes down, or null for any other entry. */
export function withdrawnBundle(entry: Record<string, unknown>): Digest | null {
  if (entry.type !== "withdrawal") return null;
  const bundle = DigestSchema.safeParse(entry.bundle);
  return bundle.success ? bundle.data : null;
}

/**
 * Why the files a node serves for an entry aren't the ones its signed entry names, or null if
 * they are: the paths must keep the layout's rules and hash to the bundle or evidence digest
 * the entry names, and the bundle they go with must be the one the entry names, when it names
 * one. A challenge names a claim rather than a bundle, so the node's word stands for which
 * bundle its evidence goes with. Files listed by digest alone can't be checked against the
 * entry, only each against its own digest.
 */
export function servedFilesProblem(served: ServedFiles, entry: Record<string, unknown>): string | null {
  const named = namedFiles(entry);
  if (!named) return `Entry ${served.index}, a ${String(entry.type)} entry, names no files, but the node serves files for it`;
  const own = entry.type === "bundle" ? named.digest : DigestSchema.safeParse(entry.bundle).data;
  if (own !== undefined && served.bundle !== own) {
    return `The node says entry ${served.index}'s files go with bundle ${served.bundle ?? "none"}, but the entry names ${own}`;
  }
  if (!("files" in served)) return null;
  let digest: Digest;
  try {
    digest = named.kind === "bundle" ? digestBundle(new Map(), new Map(Object.entries(served.files))).bundle : evidenceDigest(served.files);
  } catch (error) {
    if (!(error instanceof BundleLayoutError)) throw error;
    return `The files the node serves for entry ${served.index} have a path the protocol refuses: ${error.message}`;
  }
  return digest === named.digest
    ? null
    : `The files the node serves for entry ${served.index} hash to ${digest}, but the entry names ${named.kind} ${named.digest}`;
}
