import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import { detachSignatures, signObject } from "./entries";
import { sha256Hex } from "./hash";
import { IdeaEntrySchema, IdeaFlagSchema, ideaId, IdeaTextSchema, ideaTextDigest, type IdeaText } from "./ideas";
import { LogLeafSchema } from "./leaves";
import { verifyPasskeyObject } from "./passkey";
import { generateKeyPair, SIGNATURE_BYTES, verify } from "./signing";
import { SIGNATURE_ALGORITHM } from "./vocabulary";
import { virtualPasskey } from "./virtual-passkey";

// IDs of the shape operators' and volunteers' first keys make: op: or obs: and 64 hex digits.
const exampleId = (kind: "op" | "obs", n: number) => `${kind}:${n.toString(16).padStart(64, "0")}`;
const obs3 = exampleId("obs", 3);
const op3 = exampleId("op", 3);
const op4 = exampleId("op", 4);

const passkey = virtualPasskey();
const sign = (text: IdeaText, key = passkey) => key.sign({ type: "idea" as const, text: ideaTextDigest(text) });

describe("ideas", () => {
  const words = { title: "Do city bees forage farther than country bees?", details: "Pollen loads could tell." };

  it("commit to the digest of their words, and are named by it", () => {
    const idea = sign(words);
    expect(idea.text).toBe(`sha256:${sha256Hex(canonicalJson(words))}`);
    expect(ideaId(idea)).toBe(`idea:${sha256Hex(canonicalJson({ type: "idea", text: idea.text }))}`);
    // Another person signing the same words suggests the same idea.
    expect(ideaId(sign(words, virtualPasskey()))).toBe(ideaId(idea));
    expect(ideaId(sign({ title: words.title }))).not.toBe(ideaId(idea));
  });

  it("verify against the passkey that signed them", () => {
    const idea = IdeaEntrySchema.parse(sign(words));
    expect(verifyPasskeyObject(idea, passkey.publicKey)).not.toBeNull();
    const altered = { ...idea, text: ideaTextDigest({ title: "Something else" }) };
    expect(verifyPasskeyObject(altered, passkey.publicKey)).toBeNull();
  });

  it("accept a title alone", () => {
    expect(IdeaTextSchema.safeParse({ title: "Why does sourdough rise faster in summer?" }).success).toBe(true);
  });

  it.each([
    ["a blank title", { title: "   " }],
    ["a title over 140 characters", { title: "x".repeat(141) }],
    ["a title on two lines", { title: "First line\nsecond line" }],
    ["a title with surrounding space", { title: " Untrimmed" }],
    ["blank details", { title: "A question", details: "\n" }],
    ["details with surrounding space", { title: "A question", details: "Some context " }],
    ["details over 2,000 characters", { title: "A question", details: "x".repeat(2001) }],
    ["fields the words don't have", { title: "A question", fields: ["ecology"] }],
  ])("reject %s", (_, text) => {
    expect(IdeaTextSchema.safeParse(text).success).toBe(false);
  });

  it("keep the words out of the log, and reject operator signatures", () => {
    const idea = sign(words);
    expect(IdeaEntrySchema.safeParse({ ...idea, title: words.title }).success).toBe(false);
    expect(IdeaEntrySchema.safeParse({ ...idea, sig: `${SIGNATURE_ALGORITHM}:${"0".repeat(2 * SIGNATURE_BYTES)}` }).success).toBe(false);
  });

  it("are logged under the observer who signed them", () => {
    const leaf = { timestamp: "2026-10-04T12:00:00.000Z", observer: obs3, entry: detachSignatures(sign(words)) };
    expect(LogLeafSchema.safeParse(leaf).success).toBe(true);
    expect(LogLeafSchema.safeParse({ ...leaf, observer: undefined, operator: op3 }).success).toBe(false);
  });
});

describe("idea flags", () => {
  const operator = generateKeyPair();
  const flag = (fields: Record<string, unknown>) =>
    signObject({ type: "idea_flag" as const, operator: op4, idea: ideaId(sign({ title: "A question" })), reason: "harmful", model_family: "claude", model: "claude-test-1", ...fields }, operator.secretKey);

  it("are signed by an operator, with a reason and an optional note", () => {
    const parsed = IdeaFlagSchema.parse(flag({ note: "Asks how to culture a pathogen." }));
    const { sig, ...unsigned } = parsed;
    expect(verify(sig, new TextEncoder().encode(canonicalJson(unsigned)), operator.publicKey)).toBe(true);
  });

  it.each([
    ["an unknown reason", { reason: "boring" }],
    ["a note over 300 characters", { note: "x".repeat(301) }],
    ["a malformed idea ID", { idea: "idea:xyz" }],
  ])("reject %s", (_, fields) => {
    expect(IdeaFlagSchema.safeParse(flag(fields)).success).toBe(false);
  });
});
