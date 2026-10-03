import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { sha256Digest, type Digest } from "./hash";
import { SIGNATURE_ALGORITHM } from "./vocabulary";

// Every key is a hybrid of Ed25519 and ML-DSA-44, and every signature holds one signature
// from each over the same bytes; it verifies only if both do. ML-DSA keeps signatures sound
// once a quantum computer can break Ed25519, and Ed25519 keeps them sound if a flaw turns up
// in ML-DSA, which is far younger. A key or signature is written as the algorithm's name, a
// colon, and its two parts in hex, Ed25519's first.

const ED25519 = { publicKey: 32, signature: 64 };
const ML_DSA_44 = { publicKey: 1312, signature: 2420 };

export const PUBLIC_KEY_BYTES = ED25519.publicKey + ML_DSA_44.publicKey;
export const SIGNATURE_BYTES = ED25519.signature + ML_DSA_44.signature;
/** A secret key is two 32-byte seeds: Ed25519's, then ML-DSA-44's (FIPS 204's ξ). */
export const SECRET_KEY_BYTES = 64;

export type PublicKey = `${typeof SIGNATURE_ALGORITHM}:${string}`;
export type Signature = `${typeof SIGNATURE_ALGORITHM}:${string}`;

/** A secret key, or a function that signs with one held elsewhere, such as in native code. */
export type SigningKey = Uint8Array | ((message: Uint8Array) => Signature);

export function generateKeyPair(): { secretKey: Uint8Array; publicKey: PublicKey } {
  const secretKey = randomBytes(SECRET_KEY_BYTES);
  return { secretKey, publicKey: publicKeyOf(secretKey) };
}

export function publicKeyOf(secretKey: Uint8Array): PublicKey {
  const { ed25519Seed, mlDsaSeed } = seeds(secretKey);
  return encode(concat(ed25519.getPublicKey(ed25519Seed), ml_dsa44.keygen(mlDsaSeed).publicKey));
}

export function sign(message: Uint8Array, key: SigningKey): Signature {
  if (typeof key === "function") return key(message);
  const { ed25519Seed } = seeds(key);
  return encode(concat(ed25519.sign(message, ed25519Seed), ml_dsa44.sign(message, expandedMlDsaKey(key))));
}

/** Returns false for malformed keys or signatures instead of throwing. */
export function verify(signature: string, message: Uint8Array, publicKey: string): boolean {
  const signatureBytes = decode(signature, SIGNATURE_BYTES);
  const publicKeyBytes = decode(publicKey, PUBLIC_KEY_BYTES);
  if (!signatureBytes || !publicKeyBytes) return false;
  try {
    return (
      ed25519.verify(
        signatureBytes.subarray(0, ED25519.signature),
        message,
        publicKeyBytes.subarray(0, ED25519.publicKey),
      ) &&
      ml_dsa44.verify(
        signatureBytes.subarray(ED25519.signature),
        message,
        publicKeyBytes.subarray(ED25519.publicKey),
      )
    );
  } catch {
    return false;
  }
}

/**
 * What a key is named by where the whole key won't fit or isn't needed: a DNS record, a
 * bundle's manifest, a task. It is the SHA-256 of the key as written.
 */
export function keyDigest(publicKey: string): Digest {
  return sha256Digest(publicKey);
}

function seeds(secretKey: Uint8Array) {
  if (secretKey.length !== SECRET_KEY_BYTES) {
    throw new Error(`A secret key is ${SECRET_KEY_BYTES} bytes: an Ed25519 seed, then an ML-DSA-44 seed`);
  }
  return { ed25519Seed: secretKey.subarray(0, 32), mlDsaSeed: secretKey.subarray(32) };
}

// Expanding an ML-DSA seed takes as long as a signature, so each key is expanded once.
const expanded = new WeakMap<Uint8Array, Uint8Array>();

function expandedMlDsaKey(secretKey: Uint8Array): Uint8Array {
  let key = expanded.get(secretKey);
  if (!key) {
    key = ml_dsa44.keygen(seeds(secretKey).mlDsaSeed).secretKey;
    expanded.set(secretKey, key);
  }
  return key;
}

function encode(bytes: Uint8Array): `${typeof SIGNATURE_ALGORITHM}:${string}` {
  return `${SIGNATURE_ALGORITHM}:${bytesToHex(bytes)}`;
}

function decode(value: string, length: number): Uint8Array | null {
  const prefix = `${SIGNATURE_ALGORITHM}:`;
  // Signatures often come straight from parsed JSON, where a malformed one may not be a string.
  if (typeof value !== "string" || !value.startsWith(prefix) || value.length !== prefix.length + 2 * length) return null;
  try {
    return hexToBytes(value.slice(prefix.length));
  } catch {
    return null;
  }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
