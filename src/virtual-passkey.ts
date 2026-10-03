import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { bytesToBase64url } from "./base64url";
import { signingPayload } from "./entries";
import type { PasskeyPublicKey, PasskeySignature } from "./passkey";

/** What a browser and authenticator put in an assertion, overridable to test rejections. */
export interface AssertionOptions {
  origin?: string;
  rpId?: string;
  type?: string;
  flags?: number;
  /**
   * Replaces the client data JSON a browser would write, given the challenge it would hold.
   * A key holder driving an authenticator directly can sign any client data, so verifiers
   * must be tested against client data no browser would produce.
   */
  clientDataJson?: (challenge: string) => string;
}

/**
 * A software passkey for tests and scripts: it signs WebAuthn assertions the way a browser
 * and a platform authenticator do, so code that verifies people's signatures can be tested
 * without a browser.
 */
export function virtualPasskey(defaults: AssertionOptions = {}) {
  const { secretKey, publicKey } = p256.keygen();
  const credential = bytesToBase64url(randomBytes(16));
  let counter = 0;

  function sign<T extends { type: string }>(
    object: T,
    options: AssertionOptions = {},
  ): T & { sig: PasskeySignature } {
    const { origin = "https://sciencejournal.ai", type = "webauthn.get", flags = 0x05 } = {
      ...defaults,
      ...options,
    };
    const rpId = options.rpId ?? defaults.rpId ?? new URL(origin).hostname;
    const challenge = bytesToBase64url(sha256(signingPayload(object)));
    const clientDataJson = utf8ToBytes(
      options.clientDataJson?.(challenge) ??
        JSON.stringify({ type, challenge, origin, crossOrigin: false }),
    );
    counter += 1;
    const authenticatorData = new Uint8Array(37);
    authenticatorData.set(sha256(utf8ToBytes(rpId)), 0);
    authenticatorData[32] = flags;
    new DataView(authenticatorData.buffer).setUint32(33, counter);

    const signed = new Uint8Array(37 + 32);
    signed.set(authenticatorData, 0);
    signed.set(sha256(clientDataJson), 37);
    const signature = p256.sign(signed, secretKey, { format: "der" });
    return {
      ...object,
      sig: {
        authenticator_data: bytesToBase64url(authenticatorData),
        client_data_json: bytesToBase64url(clientDataJson),
        signature: bytesToBase64url(signature),
      },
    };
  }

  return {
    publicKey: `p256:${bytesToHex(publicKey)}` as PasskeyPublicKey,
    /** The credential ID a browser reports, which the node maps to the observer. */
    credential,
    sign,
  };
}
