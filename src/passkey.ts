import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { z } from "zod";
import { base64urlToBytes, bytesToBase64url } from "./base64url";
import { signingPayload } from "./entries";
import { parseJson } from "./json";

// People sign with passkeys. A passkey only signs WebAuthn assertions, so a person signs an
// object by making an assertion whose challenge is the SHA-256 of the object's signing
// payload.

const P256_PREFIX = "p256:";

export type PasskeyPublicKey = `p256:${string}`;

/** A P-256 public key: `p256:` and the compressed point in hex, which must be on the curve. */
export const PasskeyKeySchema = z
  .string()
  .regex(/^p256:0[23][0-9a-f]{64}$/, "Expected a P-256 public key (p256:<compressed point hex>)")
  .refine(isP256Point, "Not a point on the P-256 curve")
  .transform((key) => key as PasskeyPublicKey);

/** A WebAuthn assertion's parts, each unpadded base64url. */
export const PasskeySignatureSchema = z.strictObject({
  authenticator_data: z.base64url().max(1024),
  client_data_json: z.base64url().max(4096),
  signature: z.base64url().max(128),
});
export type PasskeySignature = z.infer<typeof PasskeySignatureSchema>;

const USER_PRESENT = 0x01;
const USER_VERIFIED = 0x04;

/** Where an assertion was made, for a node to check it came from its own site. */
export interface PasskeyAssertion {
  /** The page origin the browser recorded, such as https://sciencejournal.ai. */
  origin: string;
  /** SHA-256 of the relying party ID the authenticator signed for, as hex. */
  rpIdHash: string;
}

/**
 * Checks an assertion over `message`: the client data is a `webauthn.get` whose challenge
 * is SHA-256(message), the person was present and verified, and the signature covers the
 * authenticator data followed by SHA-256(client data JSON). Returns null if anything fails.
 */
export function verifyPasskey(
  sig: PasskeySignature,
  message: Uint8Array,
  publicKey: string,
): PasskeyAssertion | null {
  try {
    if (!publicKey.startsWith(P256_PREFIX)) return null;
    const key = hexToBytes(publicKey.slice(P256_PREFIX.length));
    const authenticatorData = base64urlToBytes(sig.authenticator_data);
    const clientDataJson = base64urlToBytes(sig.client_data_json);

    // rpIdHash (32 bytes), flags (1), signature counter (4), then optional extensions.
    if (authenticatorData.length < 37) return null;
    const flags = authenticatorData[32];
    if ((flags & USER_PRESENT) === 0 || (flags & USER_VERIFIED) === 0) return null;

    // Strict I-JSON: with a duplicate "challenge", parsers would disagree on what was signed.
    const clientData = parseJson(new TextDecoder("utf-8", { fatal: true }).decode(clientDataJson));
    const parsed = ClientDataSchema.safeParse(clientData);
    if (!parsed.success) return null;
    if (parsed.data.type !== "webauthn.get") return null;
    if (parsed.data.challenge !== bytesToBase64url(sha256(message))) return null;

    const signed = concat(authenticatorData, sha256(clientDataJson));
    // WebAuthn signatures are DER, and authenticators don't normalize S.
    const valid = p256.verify(base64urlToBytes(sig.signature), signed, key, {
      format: "der",
      lowS: false,
    });
    return valid
      ? { origin: parsed.data.origin, rpIdHash: bytesToHex(authenticatorData.slice(0, 32)) }
      : null;
  } catch {
    return null;
  }
}

/** Verifies a passkey-signed object: the assertion covers its canonical JSON without `sig`. */
export function verifyPasskeyObject(
  object: { type: string; sig: PasskeySignature },
  publicKey: string,
): PasskeyAssertion | null {
  return verifyPasskey(object.sig, signingPayload(object), publicKey);
}

/** The relying party ID hash a node expects for its own site, such as "sciencejournal.ai". */
export function rpIdHash(rpId: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(rpId)));
}

// Browsers add fields (crossOrigin, topOrigin, and others), so this object is not strict.
const ClientDataSchema = z.object({
  type: z.string(),
  challenge: z.string(),
  origin: z.string(),
});

function isP256Point(key: string): boolean {
  try {
    p256.Point.fromBytes(hexToBytes(key.slice(P256_PREFIX.length)));
    return true;
  } catch {
    return false;
  }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
