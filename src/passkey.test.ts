import { describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2.js";
import { base64urlToBytes, bytesToBase64url } from "./base64url";
import { signingPayload } from "./entries";
import { rpIdHash, verifyPasskeyObject } from "./passkey";
import { virtualPasskey } from "./virtual-passkey";

const entry = { type: "observer_key" as const, name: "Ada" };

describe("base64url", () => {
  it("round-trips every byte value without padding", () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
    for (const length of [0, 1, 2, 3, 255, 256]) {
      const encoded = bytesToBase64url(bytes.slice(0, length));
      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(base64urlToBytes(encoded)).toEqual(bytes.slice(0, length));
    }
  });
});

describe("passkey signatures", () => {
  it("verify, and report where the assertion was made", () => {
    const passkey = virtualPasskey();
    const signed = passkey.sign({ ...entry, key: passkey.publicKey });
    expect(verifyPasskeyObject(signed, passkey.publicKey)).toEqual({
      origin: "https://sciencejournal.ai",
      rpIdHash: rpIdHash("sciencejournal.ai"),
    });
  });

  it("cover the whole object except sig", () => {
    const passkey = virtualPasskey();
    const signed = passkey.sign({ ...entry, key: passkey.publicKey });
    const renamed = { ...signed, name: "Eve" };
    expect(verifyPasskeyObject(renamed, passkey.publicKey)).toBeNull();
    expect(verifyPasskeyObject({ ...signed, type: "observation" }, passkey.publicKey)).toBeNull();
  });

  it("fail against another key", () => {
    const signed = virtualPasskey().sign(entry);
    expect(verifyPasskeyObject(signed, virtualPasskey().publicKey)).toBeNull();
  });

  it.each([
    ["a registration rather than an assertion", { type: "webauthn.create" }],
    ["no user verification", { flags: 0x01 }],
    ["no user presence", { flags: 0x04 }],
  ])("reject %s", (_, options) => {
    const passkey = virtualPasskey();
    expect(verifyPasskeyObject(passkey.sign(entry, options), passkey.publicKey)).toBeNull();
  });

  it("reject an assertion moved onto another object", () => {
    const passkey = virtualPasskey();
    const { sig } = passkey.sign(entry);
    const moved = { ...entry, name: "Grace", sig };
    expect(verifyPasskeyObject(moved, passkey.publicKey)).toBeNull();
  });

  it("reject malformed parts and keys instead of throwing", () => {
    const passkey = virtualPasskey();
    const signed = passkey.sign(entry);
    const broken = (sig: Partial<typeof signed.sig>) => ({ ...signed, sig: { ...signed.sig, ...sig } });
    expect(verifyPasskeyObject(broken({ signature: "AAAA" }), passkey.publicKey)).toBeNull();
    expect(verifyPasskeyObject(broken({ authenticator_data: "AAAA" }), passkey.publicKey)).toBeNull();
    expect(verifyPasskeyObject(broken({ client_data_json: bytesToBase64url(new Uint8Array([0xff])) }), passkey.publicKey)).toBeNull();
    expect(verifyPasskeyObject(signed, `ed25519:${"0".repeat(64)}`)).toBeNull();
    expect(verifyPasskeyObject(signed, "p256:02zz")).toBeNull();
  });

  it("reject client data that parsers could read two ways", () => {
    // Parsers disagree on which duplicate name wins, so a second challenge could make one
    // signature verify for a different object under a different verifier.
    const passkey = virtualPasskey();
    const other = { ...entry, name: "Grace" };
    const otherChallenge = bytesToBase64url(sha256(signingPayload(other)));
    const signed = passkey.sign(entry, {
      clientDataJson: (challenge) =>
        `{"type":"webauthn.get","challenge":"${challenge}","challenge":"${otherChallenge}","origin":"https://sciencejournal.ai"}`,
    });
    expect(verifyPasskeyObject(signed, passkey.publicKey)).toBeNull();
    expect(verifyPasskeyObject({ ...other, sig: signed.sig }, passkey.publicKey)).toBeNull();
  });

  it("carry the origin and relying party a node checks", () => {
    const passkey = virtualPasskey();
    const elsewhere = passkey.sign(entry, { origin: "https://evil.example" });
    expect(verifyPasskeyObject(elsewhere, passkey.publicKey)).toEqual({
      origin: "https://evil.example",
      rpIdHash: rpIdHash("evil.example"),
    });
  });
});
