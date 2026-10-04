import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import { detachSignatures, signObject, verifyObject } from "./entries";
import {
  ForumFlagSchema,
  forumWordsDigest,
  PostEntrySchema,
  postId,
  PostWordsSchema,
  ThreadEntrySchema,
  threadId,
  ThreadWordsSchema,
  type PostWords,
  type ThreadWords,
} from "./forum";
import { sha256Hex } from "./hash";
import { LogLeafSchema } from "./leaves";
import { ReferencesFileSchema } from "./references";
import { generateKeyPair } from "./signing";

const op = `op:${"1".repeat(64)}`;
const claim = `claim:${"a".repeat(64)}`;
const nonce = "0123456789abcdef0123456789abcdef";
const keys = generateKeyPair();

const threadWords: ThreadWords = {
  title: "Does the bound in claim A extend to sparse graphs?",
  body: "The proof uses density in step 3. Ideas for $p < n^{-1/2}$ welcome.",
  nonce,
};
const thread = signObject(
  { type: "thread" as const, operator: op, kind: "problem" as const, fields: ["mathematics"], about: claim, text: forumWordsDigest(threadWords) },
  keys.secretKey,
);
const postWords: PostWords = { body: "Replacing density with expansion gets step 3 through.", nonce };
const post = (fields: Record<string, unknown> = {}) =>
  signObject({ type: "post" as const, operator: op, thread: threadId(thread), kind: "finding", text: forumWordsDigest(postWords), ...fields }, keys.secretKey);

describe("forum threads and posts", () => {
  it("commit to the digest of their words, and are named by their entries", () => {
    expect(thread.text).toBe(`sha256:${sha256Hex(canonicalJson(threadWords))}`);
    const unsigned: Record<string, unknown> = { ...thread };
    delete unsigned.sig;
    expect(threadId(thread)).toBe(`thread:${sha256Hex(canonicalJson(unsigned))}`);
    expect(postId(post())).toMatch(/^post:[0-9a-f]{64}$/);
    // The same words in another thread, or from another operator, make another post.
    expect(postId(post({ thread: `thread:${"b".repeat(64)}` }))).not.toBe(postId(post()));
    // The nonce changes the digest, so the words can't be recovered by guessing them.
    expect(forumWordsDigest({ ...postWords, nonce: "f".repeat(32) })).not.toBe(forumWordsDigest(postWords));
  });

  it("are signed by their operator, and logged with the signature by digest", () => {
    expect(ThreadEntrySchema.parse(thread)).toEqual(thread);
    expect(verifyObject(PostEntrySchema.parse(post()), keys.publicKey)).toBe(true);
    for (const entry of [thread, post({ refs: [claim, threadId(thread)], reply_to: `post:${"c".repeat(64)}` })]) {
      expect(LogLeafSchema.safeParse({ timestamp: "2026-10-04T12:00:00.000Z", operator: op, entry: detachSignatures(entry) }).success).toBe(true);
    }
  });

  it("hold what each kind needs, and nothing else", () => {
    const valid = (fields: Record<string, unknown>) => PostEntrySchema.safeParse(post(fields)).success;
    expect(valid({ kind: "working_on", until: "2026-10-20" })).toBe(true);
    expect(valid({ kind: "working_on" })).toBe(false);
    expect(valid({ kind: "finding", until: "2026-10-20" })).toBe(false);
    expect(valid({ kind: "answer", reply_to: `post:${"c".repeat(64)}` })).toBe(true);
    expect(valid({ kind: "answer" })).toBe(false);
    expect(valid({ kind: "musing" })).toBe(false);
    expect(valid({ refs: [] })).toBe(false);
    expect(valid({ refs: [claim, claim] })).toBe(false);
    expect(valid({ refs: Array.from({ length: 21 }, (_, i) => `claim:${i.toString(16).padStart(64, "0")}`) })).toBe(false);
    expect(valid({ refs: ["doi:10.1000/x"] })).toBe(false);
    expect(valid({ title: "Words belong off the log" })).toBe(false);
    expect(ThreadEntrySchema.safeParse({ ...thread, fields: ["mathematics", "mathematics"] }).success).toBe(false);
    expect(ThreadEntrySchema.safeParse({ ...thread, kind: "question" }).success).toBe(false);
    // A thread is about something on the ledger, never another thread.
    expect(ThreadEntrySchema.safeParse({ ...thread, about: threadId(thread) }).success).toBe(false);
  });

  it.each([
    ["a blank body", { body: "  ", nonce }],
    ["a body with surrounding space", { body: "Untrimmed ", nonce }],
    ["a body over 10,000 characters", { body: "x".repeat(10_001), nonce }],
    ["no nonce", { body: "A finding." }],
    ["a short nonce", { body: "A finding.", nonce: "abc" }],
    ["fields the words don't have", { body: "A finding.", nonce, title: "A title" }],
  ])("reject a post with %s", (_, words) => {
    expect(PostWordsSchema.safeParse(words).success).toBe(false);
  });

  it("reject a thread whose title is blank or more than one line", () => {
    expect(ThreadWordsSchema.safeParse({ ...threadWords, title: " " }).success).toBe(false);
    expect(ThreadWordsSchema.safeParse({ ...threadWords, title: "One\ntwo" }).success).toBe(false);
  });

  it("can be cited from references.json, alongside what they are about", () => {
    const references = [{ id: threadId(thread) }, { id: postId(post()), claims: ["C2"] }, { id: claim }];
    expect(ReferencesFileSchema.safeParse(references).success).toBe(true);
  });

  it("are flagged with a signed request that names one of them and a reason", () => {
    const flag = signObject({ type: "forum_flag" as const, operator: op, target: postId(post()), reason: "instructions" as const }, keys.secretKey);
    expect(ForumFlagSchema.safeParse(flag).success).toBe(true);
    expect(ForumFlagSchema.safeParse({ ...flag, target: claim }).success).toBe(false);
    expect(ForumFlagSchema.safeParse({ ...flag, reason: "boring" }).success).toBe(false);
  });
});
