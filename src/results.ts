import { canonicalJson } from "./canonical";
import type { Digest } from "./hash";
import { parseJson } from "./json";

/**
 * Where a declared result lives: `R3.loss_delta` is the value at `loss_delta` in
 * `results/R3.json`, further dots go deeper, and a decimal key picks an array element.
 * Null for references of any other shape.
 */
export function resultLocation(reference: string): { path: string; keys: string[] } | null {
  const [name, ...keys] = reference.split(".");
  if (!name || name.includes("/") || keys.length === 0 || keys.some((key) => key === "")) return null;
  return { path: `results/${name}.json`, keys };
}

/**
 * Where paper.md puts a declared result: `{{R3.loss_delta}}` stands for that result's value,
 * so the prose and the claims read the same number. A reader shows the value in its place.
 */
export const RESULT_PLACEHOLDER = /\{\{\s*([^{}\s]+)\s*\}\}/g;

/** The results a paper's placeholders name, each once, in the order they first appear. */
export function resultsInPaper(markdown: string): string[] {
  return [...new Set(Array.from(markdown.matchAll(RESULT_PLACEHOLDER), (match) => match[1]))];
}

/** A result an evidence item names that the bundle doesn't declare. */
export class ResultError extends Error {
  override name = "ResultError";
}

/**
 * What a claim with evidence binds besides its own fields: the bundle's verification inputs
 * and the declared value of each result its evidence names.
 */
export interface BundleInputs {
  /** The digest of every file under code/, env/, data/, and proofs/, from digestBundle. */
  verificationInputs: Digest;
  /** The declared value of a result such as `R3.loss_delta`. Throws ResultError if there is none. */
  result(reference: string): unknown;
  /** Whether the bundle has a file at this path. Omitted when only the inputs are known. */
  has?(path: string): boolean;
}

/** The inputs claims bind to, read from a bundle's files. */
export function bundleInputs(
  files: ReadonlyMap<string, Uint8Array>,
  verificationInputs: Digest,
): BundleInputs {
  const parsed = new Map<string, unknown>();
  const read = (path: string): unknown => {
    if (!parsed.has(path)) {
      const bytes = files.get(path);
      if (!bytes) throw new ResultError(`There is no ${path}`);
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch {
        throw new ResultError(`${path} is not UTF-8`);
      }
      try {
        parsed.set(path, parseJson(text));
      } catch (error) {
        throw new ResultError(`${path} is not valid JSON: ${(error as Error).message}`);
      }
    }
    return parsed.get(path);
  };

  return {
    verificationInputs,
    result(reference) {
      const location = resultLocation(reference);
      if (!location) {
        throw new ResultError(`"${reference}" is not a result name such as R3.loss_delta`);
      }
      const value = valueAt(read(location.path), location.keys);
      if (value === undefined) {
        throw new ResultError(`${location.path} has no value at ${location.keys.join(".")}`);
      }
      return value;
    },
    has: (path) => files.has(path),
  };
}

/** Inputs given directly: the verification inputs digest and each result's declared value. */
export function declaredInputs(verificationInputs: Digest, results: Readonly<Record<string, unknown>>): BundleInputs {
  return {
    verificationInputs,
    result(reference) {
      if (!Object.hasOwn(results, reference)) throw new ResultError(`results has no "${reference}"`);
      return results[reference];
    },
  };
}

/**
 * Whether a result agrees with the value declared for it: a number within `tolerance` of the
 * declared number (equal to it when there is no tolerance), and any other value exactly equal,
 * as canonical JSON. Numbers are compared as the decimals canonical JSON writes them, the
 * shortest that read back as the same binary64 value, in exact arithmetic, so every
 * implementation agrees at the edge: 1.1 is within 0.1 of 1, though in binary64 the
 * difference is slightly more than 0.1.
 */
export function resultAgrees(produced: unknown, declared: unknown, tolerance?: number): boolean {
  if (produced === undefined || declared === undefined) return false;
  if (typeof produced !== "number" || typeof declared !== "number") {
    return canonicalJson(produced) === canonicalJson(declared);
  }
  const [p, d, t] = [produced, declared, tolerance ?? 0].map(decimal);
  const exponent = Math.min(p.exponent, d.exponent, t.exponent);
  const scaled = ({ units, exponent: e }: Decimal) => units * BigInt(10) ** BigInt(e - exponent);
  const difference = scaled(p) - scaled(d);
  return (difference < BigInt(0) ? -difference : difference) <= scaled(t);
}

type Decimal = { units: bigint; exponent: number };

/** A number as RFC 8785 writes it (ECMAScript's shortest round trip), as units times 10^exponent. */
function decimal(value: number): Decimal {
  const [mantissa, exponent = "0"] = String(value).split("e");
  const [whole, fraction = ""] = mantissa.split(".");
  return { units: BigInt(whole + fraction), exponent: Number(exponent) - fraction.length };
}

function valueAt(value: unknown, keys: readonly string[]): unknown {
  let current = value;
  for (const key of keys) {
    if (Array.isArray(current)) {
      if (!/^(0|[1-9][0-9]*)$/.test(key)) return undefined;
      current = current[Number(key)];
    } else if (typeof current === "object" && current !== null) {
      if (!Object.hasOwn(current, key)) return undefined;
      current = (current as Record<string, unknown>)[key];
    } else {
      return undefined;
    }
  }
  return current;
}
