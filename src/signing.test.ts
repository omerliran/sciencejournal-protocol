import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import { sha256Digest } from "./hash";
import {
  generateKeyPair,
  keyDigest,
  PUBLIC_KEY_BYTES,
  publicKeyOf,
  SECRET_KEY_BYTES,
  sign,
  SIGNATURE_BYTES,
  verify,
} from "./signing";
import { SIGNATURE_ALGORITHM } from "./vocabulary";

const message = utf8ToBytes("sha256:5c1e");
const prefix = `${SIGNATURE_ALGORITHM}:`;
const keys = generateKeyPair();
const signature = sign(message, keys.secretKey);

describe("signing", () => {
  it("writes keys and signatures as the algorithm and both halves in hex", () => {
    expect(keys.publicKey).toMatch(new RegExp(`^${prefix}[0-9a-f]{${2 * PUBLIC_KEY_BYTES}}$`));
    expect(signature).toMatch(new RegExp(`^${prefix}[0-9a-f]{${2 * SIGNATURE_BYTES}}$`));
    expect(keys.secretKey).toHaveLength(SECRET_KEY_BYTES);
    expect(publicKeyOf(keys.secretKey)).toBe(keys.publicKey);
  });

  it("verifies a signature from the matching key", () => {
    expect(verify(signature, message, keys.publicKey)).toBe(true);
  });

  it("rejects a tampered message or a different key", () => {
    expect(verify(signature, utf8ToBytes("sha256:5c1f"), keys.publicKey)).toBe(false);
    expect(verify(signature, message, generateKeyPair().publicKey)).toBe(false);
  });

  it("needs both halves: Ed25519 alone or ML-DSA-44 alone doesn't verify", () => {
    const hex = signature.slice(prefix.length);
    const edHalf = hex.slice(0, 128);
    const mlHalf = hex.slice(128);
    const other = sign(message, generateKeyPair().secretKey).slice(prefix.length);
    // Each half from this key, the other half from another key's signature.
    expect(verify(`${prefix}${edHalf}${other.slice(128)}`, message, keys.publicKey)).toBe(false);
    expect(verify(`${prefix}${other.slice(0, 128)}${mlHalf}`, message, keys.publicKey)).toBe(false);
    expect(verify(`ed25519:${edHalf}`, message, keys.publicKey)).toBe(false);
  });

  it("is a plain Ed25519 signature and a plain ML-DSA-44 signature over the same bytes", () => {
    const publicHex = keys.publicKey.slice(prefix.length);
    const hex = signature.slice(prefix.length);
    const bytes = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
    expect(ed25519.verify(bytes(hex.slice(0, 128)), message, bytes(publicHex.slice(0, 64)))).toBe(true);
    expect(ml_dsa44.verify(bytes(hex.slice(128)), message, bytes(publicHex.slice(64)))).toBe(true);
    // The secret key is the two seeds.
    expect(bytesToHex(ed25519.getPublicKey(keys.secretKey.subarray(0, 32)))).toBe(publicHex.slice(0, 64));
    expect(bytesToHex(ml_dsa44.keygen(keys.secretKey.subarray(32)).publicKey)).toBe(publicHex.slice(64));
  });

  it("returns false for malformed input instead of throwing", () => {
    expect(verify("rsa:00", message, keys.publicKey)).toBe(false);
    expect(verify(`${prefix}zz`, message, keys.publicKey)).toBe(false);
    expect(verify(signature, message, `${prefix}00`)).toBe(false);
    expect(verify(signature.slice(0, -2), message, keys.publicKey)).toBe(false);
    // Parsed JSON can put anything where a signature or key belongs.
    expect(verify(123 as unknown as string, message, keys.publicKey)).toBe(false);
    expect(verify(signature, message, { key: keys.publicKey } as unknown as string)).toBe(false);
  });

  it("names a key by the SHA-256 of the key as written", () => {
    expect(keyDigest(keys.publicKey)).toBe(sha256Digest(keys.publicKey));
  });

  it("refuses a secret key of the wrong length", () => {
    expect(() => sign(message, new Uint8Array(32))).toThrow(/64 bytes/);
  });
});
