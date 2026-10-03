import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { z } from "zod";
import { canonicalJson } from "./canonical";

/** A self-describing content hash, as the ledger stores it. */
export type Digest = `sha256:${string}`;

export const DigestSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/, "Expected a digest (sha256:<hex>)")
  .transform((digest) => digest as Digest);

export function sha256Hex(data: Uint8Array | string): string {
  return bytesToHex(sha256(typeof data === "string" ? utf8ToBytes(data) : data));
}

export function sha256Digest(data: Uint8Array | string): Digest {
  return `sha256:${sha256Hex(data)}`;
}

/** SHA-256 of the value's canonical JSON, as lowercase hex. */
export function hashCanonical(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}

export function canonicalDigest(value: unknown): Digest {
  return `sha256:${hashCanonical(value)}`;
}
