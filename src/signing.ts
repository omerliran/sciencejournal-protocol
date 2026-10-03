import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

const ED25519_PREFIX = "ed25519:";

export type PublicKey = `ed25519:${string}`;
export type Signature = `ed25519:${string}`;

export function generateKeyPair(): { secretKey: Uint8Array; publicKey: PublicKey } {
  const { secretKey, publicKey } = ed25519.keygen();
  return { secretKey, publicKey: `${ED25519_PREFIX}${bytesToHex(publicKey)}` };
}

export function sign(message: Uint8Array, secretKey: Uint8Array): Signature {
  return `${ED25519_PREFIX}${bytesToHex(ed25519.sign(message, secretKey))}`;
}

/** Returns false for malformed keys or signatures instead of throwing. */
export function verify(signature: string, message: Uint8Array, publicKey: string): boolean {
  const signatureBytes = decode(signature);
  const publicKeyBytes = decode(publicKey);
  if (!signatureBytes || !publicKeyBytes) return false;
  try {
    return ed25519.verify(signatureBytes, message, publicKeyBytes);
  } catch {
    return false;
  }
}

function decode(value: string): Uint8Array | null {
  if (!value.startsWith(ED25519_PREFIX)) return null;
  try {
    return hexToBytes(value.slice(ED25519_PREFIX.length));
  } catch {
    return null;
  }
}
