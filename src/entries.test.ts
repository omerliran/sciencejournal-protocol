import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import {
  detachSignatures,
  KeyRecoveryEntrySchema,
  KeyRotationEntrySchema,
  keyRotationPayload,
  matchesLeafEntry,
  signatureDigest,
  signKeyRotation,
  signObject,
  verifyKeyRotation,
} from "./entries";
import { canonicalDigest } from "./hash";
import { LogLeafSchema } from "./leaves";
import { generateKeyPair, verify } from "./signing";

describe("key rotations", () => {
  const current = generateKeyPair();
  const next = generateKeyPair();
  const entry = signKeyRotation("op:12", next.secretKey, current.secretKey, next.publicKey);

  it("carry the new key's signature over the entry without either signature", () => {
    expect(new TextDecoder().decode(keyRotationPayload(entry))).toBe(
      canonicalJson({ type: "key_rotation", operator: "op:12", key: next.publicKey }),
    );
    expect(verify(entry.key_sig, keyRotationPayload(entry), next.publicKey)).toBe(true);
  });

  it("verify only with both keys' signatures, the current key's covering key_sig too", () => {
    expect(KeyRotationEntrySchema.safeParse(entry).success).toBe(true);
    expect(verifyKeyRotation(entry, current.publicKey)).toBe(true);
    expect(verifyKeyRotation(entry, next.publicKey)).toBe(false);
    const swapped = signObject({ ...entry, key_sig: signKeyRotation("op:13", next.secretKey, current.secretKey, next.publicKey).key_sig }, current.secretKey);
    expect(verifyKeyRotation(swapped, current.publicKey)).toBe(false);
  });

  it("are log leaves, with both signatures detached", () => {
    const leaf = { timestamp: "2026-10-03T00:00:00Z", operator: "op:12", entry: detachSignatures(entry) };
    expect(leaf.entry.key_sig).toBe(signatureDigest(entry.key_sig));
    expect(LogLeafSchema.safeParse(leaf).success).toBe(true);
    expect(LogLeafSchema.safeParse({ ...leaf, entry }).success).toBe(false);
  });
});

describe("key recoveries", () => {
  const next = generateKeyPair();
  it("are proven by a domain or by the log, and say where the old key stops counting", () => {
    const byDomain = signObject(
      { type: "key_recovery" as const, kind: "domain" as const, operator: "op:12", key: next.publicKey, domain: "lab.example.org", since: 40 },
      next.secretKey,
    );
    expect(KeyRecoveryEntrySchema.safeParse(byDomain).success).toBe(true);
    const leaf = { timestamp: "2026-10-03T00:00:00Z", operator: "op:12", entry: detachSignatures(byDomain) };
    expect(LogLeafSchema.safeParse(leaf).success).toBe(true);
    expect(KeyRecoveryEntrySchema.safeParse({ ...byDomain, kind: "invited" }).success).toBe(false);
    expect(KeyRecoveryEntrySchema.safeParse({ ...byDomain, since: -1 }).success).toBe(false);
  });
});

describe("signatures beside the log", () => {
  const keys = generateKeyPair();
  const entry = signObject({ type: "bundle" as const, bundle: `sha256:${"ab".repeat(32)}` as const }, keys.secretKey);

  it("replace each signature in a leaf with the digest of its canonical JSON", () => {
    const detached = detachSignatures(entry);
    expect(detached).toEqual({ type: "bundle", bundle: entry.bundle, sig: canonicalDigest(entry.sig) });
    // Passkey signatures are objects, digested the same way.
    const passkeySig = { authenticator_data: "AA", client_data_json: "AA", signature: "AA" };
    expect(detachSignatures({ type: "idea", sig: passkeySig }).sig).toBe(canonicalDigest(passkeySig));
  });

  it("match a signed entry to its leaf only with the very signature the leaf fixes", () => {
    expect(matchesLeafEntry(entry, detachSignatures(entry))).toBe(true);
    const resigned = signObject({ type: "bundle" as const, bundle: entry.bundle }, keys.secretKey);
    // ML-DSA signatures are randomized, so signing again gives a different signature.
    expect(resigned.sig).not.toBe(entry.sig);
    expect(matchesLeafEntry(resigned, detachSignatures(entry))).toBe(false);
  });
});
