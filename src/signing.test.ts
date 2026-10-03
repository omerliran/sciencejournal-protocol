import { utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { generateKeyPair, sign, verify } from "./signing";

const message = utf8ToBytes("sha256:5c1e");

describe("signing", () => {
  it("verifies a signature from the matching key", () => {
    const { secretKey, publicKey } = generateKeyPair();
    expect(publicKey).toMatch(/^ed25519:[0-9a-f]{64}$/);
    expect(verify(sign(message, secretKey), message, publicKey)).toBe(true);
  });

  it("rejects a tampered message or a different key", () => {
    const { secretKey, publicKey } = generateKeyPair();
    const signature = sign(message, secretKey);
    expect(verify(signature, utf8ToBytes("sha256:5c1f"), publicKey)).toBe(false);
    expect(verify(signature, message, generateKeyPair().publicKey)).toBe(false);
  });

  it("returns false for malformed input instead of throwing", () => {
    const { secretKey, publicKey } = generateKeyPair();
    const signature = sign(message, secretKey);
    expect(verify("rsa:00", message, publicKey)).toBe(false);
    expect(verify("ed25519:zz", message, publicKey)).toBe(false);
    expect(verify(signature, message, "ed25519:00")).toBe(false);
  });
});
