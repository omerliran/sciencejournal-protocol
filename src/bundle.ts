import { canonicalDigest, sha256Digest, type Digest } from "./hash";

const SIGNATURE_FILE = "signature";

// The submission layout. Directories hold what verifiers execute or
// compare against; top-level files describe it.
const BUNDLE_FILES = new Set([
  "manifest.json",
  "paper.md",
  "claims.json",
  "references.json",
  "materials.json",
  "deviations.json",
  "embeddings.json",
  "provenance.json",
  SIGNATURE_FILE,
]);
export const BUNDLE_DIRECTORIES = ["code", "env", "data", "results", "proofs", "plan"] as const;
const DIRECTORIES = new Set<string>(BUNDLE_DIRECTORIES);
/**
 * Everything under these directories is a verification input. Declared results are not:
 * each claim binds only the result values its evidence names.
 */
export const VERIFICATION_INPUT_DIRECTORIES = ["code", "env", "data", "proofs"] as const;
const INPUT_DIRECTORIES = new Set<string>(VERIFICATION_INPUT_DIRECTORIES);

export class BundleLayoutError extends Error {
  override name = "BundleLayoutError";
  constructor(
    message: string,
    /** The paths at fault. */
    readonly paths: readonly string[] = [],
  ) {
    super(message);
  }
}

export interface BundleDigests {
  /** SHA-256 of every file's bytes, keyed by bundle path. */
  files: Record<string, Digest>;
  /** The bundle hash the operator signs: every file except the signature itself. */
  bundle: Digest;
  /** Everything under code/, env/, data/, and proofs/. Claims with evidence bind to this. */
  verificationInputs: Digest;
}

/**
 * Hashes a bundle given as bundle path -> file bytes. Paths are POSIX, relative to the
 * bundle root, and must fit the submission layout; anything else throws BundleLayoutError.
 * Large files sent ahead of the bundle come in `uploaded`, by digest, and are hashed the same
 * way: a bundle's hash depends only on its files' digests.
 */
export function digestBundle(
  files: ReadonlyMap<string, Uint8Array>,
  uploaded: ReadonlyMap<string, Digest> = new Map(),
): BundleDigests {
  const twice = [...uploaded.keys()].find((path) => files.has(path));
  if (twice) throw new BundleLayoutError(`"${twice}" is both sent and uploaded`, [twice]);
  checkPaths([...files.keys(), ...uploaded.keys()], true);

  const digests = new Map<string, Digest>([
    ...[...files].map(([path, bytes]): [string, Digest] => [path, sha256Digest(bytes)]),
    ...uploaded,
  ]);
  const select = (keep: (path: string) => boolean) =>
    Object.fromEntries([...digests].filter(([path]) => keep(path)));

  return {
    files: select(() => true),
    bundle: canonicalDigest(select((path) => path !== SIGNATURE_FILE)),
    verificationInputs: canonicalDigest(select((path) => INPUT_DIRECTORIES.has(path.split("/")[0]))),
  };
}

/**
 * Hashes a verifier's evidence: any files, under the same portable path rules as a bundle,
 * digested the same way as a bundle hash.
 */
export function digestEvidence(files: ReadonlyMap<string, Uint8Array>): {
  files: Record<string, Digest>;
  evidence: Digest;
} {
  checkPaths([...files.keys()], false);
  const digests = Object.fromEntries([...files].map(([path, bytes]) => [path, sha256Digest(bytes)]));
  return { files: digests, evidence: canonicalDigest(digests) };
}

/**
 * Checks the paths of the files a bundle points at, in data/external.json, beside the paths of
 * its own files: each sits under data/, none is one of the bundle's own or given twice, and
 * together they keep the rules a bundle's paths keep, so a verifier can put every file where
 * its path says. Throws BundleLayoutError naming the paths at fault.
 */
export function checkPointedPaths(paths: Iterable<string>, pointed: readonly string[]): void {
  const own = new Set(paths);
  const seen = new Set<string>();
  for (const path of pointed) {
    const segments = path.split("/");
    if (segments.length < 2 || segments[0] !== "data") {
      throw new BundleLayoutError(`"${path}" isn't under data/, where the files a bundle points at go`, [path]);
    }
    if (own.has(path)) throw new BundleLayoutError(`"${path}" is both in the bundle and pointed at`, [path]);
    if (seen.has(path)) throw new BundleLayoutError(`"${path}" is pointed at twice`, [path]);
    seen.add(path);
  }
  checkPaths([...own, ...pointed], true);
}

function checkPaths(paths: string[], bundleLayout: boolean): void {
  const seen = new Map<string, string>();
  for (const path of paths) {
    const segments = path.split("/");
    if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
      throw new BundleLayoutError(`"${path}" is not a normalized relative path`, [path]);
    }
    if (/[\\\x00-\x1f\x7f]/.test(path)) {
      throw new BundleLayoutError(`"${path}" contains a backslash or control character`, [path]);
    }
    if (path.normalize("NFC") !== path) {
      throw new BundleLayoutError(`"${path}" is not Unicode NFC`, [path]);
    }

    const allowed =
      !bundleLayout ||
      (segments.length === 1 ? BUNDLE_FILES.has(path) : DIRECTORIES.has(segments[0]));
    if (!allowed) {
      throw new BundleLayoutError(`"${path}" is outside the submission layout`, [path]);
    }

    // Mirrors on case-insensitive filesystems must be able to hold every file.
    const folded = path.toLowerCase();
    const clash = seen.get(folded);
    if (clash !== undefined) {
      throw new BundleLayoutError(`"${path}" and "${clash}" differ only in case`, [path, clash]);
    }
    seen.set(folded, path);
  }

  for (const folded of seen.keys()) {
    const parts = folded.split("/");
    for (let depth = 1; depth < parts.length; depth++) {
      const parent = parts.slice(0, depth).join("/");
      if (seen.has(parent)) {
        throw new BundleLayoutError(`"${seen.get(parent)}" is both a file and a directory`, [seen.get(parent)!, seen.get(folded)!]);
      }
    }
  }
}
