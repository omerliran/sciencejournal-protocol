import { describe, expect, it } from "vitest";
import { AddendumEntrySchema, AddendumScreenSchema, addendumWordsDigest, AddendumWordsSchema } from "./addenda";
import { canonicalJson } from "./canonical";
import { sha256Digest } from "./hash";
import { signObject } from "./entries";
import { generateKeyPair } from "./signing";

const keys = generateKeyPair();

const screen = (fields: Record<string, unknown>) =>
  signObject(
    { type: "addendum_screen", screener: `op:${"a".repeat(64)}`, addendum: 12, model_family: "claude", model: "claude-opus-5-5", ...fields },
    keys.secretKey,
  );

describe("addenda on the wire", () => {
  it("commits to the canonical JSON of its words, which it keeps exactly as written", () => {
    const words = { text: "A note.", nonce: "0".repeat(32) };
    expect(addendumWordsDigest(words)).toBe(sha256Digest(canonicalJson(words)));
    expect(AddendumWordsSchema.parse(words)).toEqual(words);
    expect(AddendumWordsSchema.safeParse({ ...words, text: "A note. " }).success).toBe(false);
    expect(AddendumWordsSchema.safeParse({ ...words, text: "x".repeat(10_001) }).success).toBe(false);
  });

  it("names its publisher, the bundle, and its words' digest, and leaves the model to the node", () => {
    const entry = signObject(
      { type: "addendum", publisher: `op:${"b".repeat(64)}`, bundle: `sha256:${"c".repeat(64)}`, words: `sha256:${"d".repeat(64)}` },
      keys.secretKey,
    );
    expect(AddendumEntrySchema.safeParse(entry).success).toBe(true);
    expect(AddendumEntrySchema.safeParse({ ...entry, text: "words" }).success).toBe(false);
  });

  it("takes an ok only with no hazard and no reason, and a block only with one or the other", () => {
    const valid = (fields: Record<string, unknown>) => AddendumScreenSchema.safeParse(screen(fields)).success;
    expect(valid({ hazard: "none", verdict: "ok" })).toBe(true);
    expect(valid({ hazard: "cyber", verdict: "ok" })).toBe(false);
    expect(valid({ hazard: "none", verdict: "ok", reason: "abuse" })).toBe(false);
    expect(valid({ hazard: "none", verdict: "block" })).toBe(false);
    expect(valid({ hazard: "none", verdict: "block", reason: "new_work" })).toBe(true);
    expect(valid({ hazard: "private_data", verdict: "block" })).toBe(true);
    expect(valid({ hazard: "biological", verdict: "block", reason: "instructions" })).toBe(true);
    expect(valid({ hazard: "none", verdict: "block", reason: "dull" })).toBe(false);
    // The model is named on every screen, since screens aren't logged.
    expect(AddendumScreenSchema.safeParse({ ...screen({ hazard: "none", verdict: "ok" }), model: undefined }).success).toBe(false);
  });
});
