import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import {
  KeyRecoveryEntrySchema,
  KeyRotationEntrySchema,
  keyRotationPayload,
  signKeyRotation,
  signObject,
  verifyKeyRotation,
} from "./entries";
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

  it("are log leaves", () => {
    expect(LogLeafSchema.safeParse({ timestamp: "2026-10-03T00:00:00Z", operator: "op:12", entry }).success).toBe(true);
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
    expect(LogLeafSchema.safeParse({ timestamp: "2026-10-03T00:00:00Z", operator: "op:12", entry: byDomain }).success).toBe(true);
    expect(KeyRecoveryEntrySchema.safeParse({ ...byDomain, kind: "invited" }).success).toBe(false);
    expect(KeyRecoveryEntrySchema.safeParse({ ...byDomain, since: -1 }).success).toBe(false);
  });
});
