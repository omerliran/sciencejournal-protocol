import { canonicalDigest, sha256Digest, type Digest } from "./hash";

const SIGNATURE_FILE = "signature";

// The submission layout. Directories hold what verifiers execute or
// compare against; top-level files describe it.
const BUNDLE_FILES = new Set([
  "manifest.json",
  "paper.md",
  "claims.json",
  "references.json",
  "embeddings.json",
  "provenance.json",
  SIGNATURE_FILE,
]);
/** Everything under these directories is a verification input. */
export const BUNDLE_DIRECTORIES = ["code", "env", "data", "results", "proofs"] as const;
const DIRECTORIES = new Set<string>(BUNDLE_DIRECTORIES);

export class BundleLayoutError extends Error {
  override name = "BundleLayoutError";
}

export interface BundleDigests {
  /** SHA-256 of every file's bytes, keyed by bundle path. */
  files: Record<string, Digest>;
  /** The bundle hash the operator signs: every file except the signature itself. */
  bundle: Digest;
  /** Everything under the bundle's directories. Claims with evidence bind to this. */
  verificationInputs: Digest;
}

/**
 * Hashes a bundle given as bundle path -> file bytes. Paths are POSIX, relative to the
 * bundle root, and must fit the submission layout; anything else throws BundleLayoutError.
 */
export function digestBundle(files: ReadonlyMap<string, Uint8Array>): BundleDigests {
  checkPaths([...files.keys()], true);

  const digests = new Map([...files].map(([path, bytes]) => [path, sha256Digest(bytes)]));
  const select = (keep: (path: string) => boolean) =>
    Object.fromEntries([...digests].filter(([path]) => keep(path)));

  return {
    files: select(() => true),
    bundle: canonicalDigest(select((path) => path !== SIGNATURE_FILE)),
    // checkPaths has confirmed every nested path sits under one of BUNDLE_DIRECTORIES.
    verificationInputs: canonicalDigest(select((path) => path.includes("/"))),
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

function checkPaths(paths: string[], bundleLayout: boolean): void {
  const seen = new Map<string, string>();
  for (const path of paths) {
    const segments = path.split("/");
    if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
      throw new BundleLayoutError(`"${path}" is not a normalized relative path`);
    }
    if (/[\\\x00-\x1f\x7f]/.test(path)) {
      throw new BundleLayoutError(`"${path}" contains a backslash or control character`);
    }
    if (path.normalize("NFC") !== path) {
      throw new BundleLayoutError(`"${path}" is not Unicode NFC`);
    }

    const allowed =
      !bundleLayout ||
      (segments.length === 1 ? BUNDLE_FILES.has(path) : DIRECTORIES.has(segments[0]));
    if (!allowed) {
      throw new BundleLayoutError(`"${path}" is outside the submission layout`);
    }

    // Mirrors on case-insensitive filesystems must be able to hold every file.
    const folded = path.toLowerCase();
    const clash = seen.get(folded);
    if (clash !== undefined) {
      throw new BundleLayoutError(`"${path}" and "${clash}" differ only in case`);
    }
    seen.set(folded, path);
  }

  for (const folded of seen.keys()) {
    const parts = folded.split("/");
    for (let depth = 1; depth < parts.length; depth++) {
      const parent = parts.slice(0, depth).join("/");
      if (seen.has(parent)) {
        throw new BundleLayoutError(`"${seen.get(parent)}" is both a file and a directory`);
      }
    }
  }
}
