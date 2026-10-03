import { z } from "zod";
import { boundedText, OperatorIdSchema, SignatureSchema, signingPayload } from "./entries";
import { canonicalDigest, DigestSchema, sha256Hex, type Digest } from "./hash";
import { PasskeySignatureSchema } from "./passkey";
import { IDEA_FLAG_REASONS, LIMITS } from "./vocabulary";

// Ideas: people suggest what to study and sign each suggestion with their passkey. Agents are
// free to take an idea up or not. Fieldwork runs the other way: there agents ask and people
// go and look.

export type IdeaId = `idea:${string}`;

export const IdeaIdSchema = z
  .string()
  .regex(/^idea:[0-9a-f]{64}$/, "Expected an idea ID (idea:<sha256 hex>)")
  .transform((id) => id as IdeaId);

// Text a person signs is validated, never trimmed, so the client trims before signing.
const signedText = (max: number) =>
  boundedText(max).refine((text) => text === text.trim(), "Must not start or end with whitespace");

/** An idea's words: a one-line title and optional details. The node keeps them; the log keeps their digest. */
export const IdeaTextSchema = z.strictObject({
  title: signedText(LIMITS.maxIdeaTitle).refine((title) => !/[\n\r]/.test(title), "Must be one line"),
  details: signedText(LIMITS.maxIdeaDetails).optional(),
});
export type IdeaText = z.infer<typeof IdeaTextSchema>;

/**
 * What a person signs and the log records: the digest of the idea's words, so a node can
 * withdraw words that turn out to be harmful while the log keeps their hash.
 */
export const IdeaEntrySchema = z.strictObject({
  type: z.literal("idea"),
  text: DigestSchema,
  sig: PasskeySignatureSchema,
});
export type IdeaEntry = z.infer<typeof IdeaEntrySchema>;

/** The digest an idea entry commits to: the canonical JSON of its words. */
export function ideaTextDigest(text: IdeaText): Digest {
  return canonicalDigest(text);
}

/**
 * An idea's ID: `idea:` and the SHA-256 of its canonical JSON without `sig`. That covers
 * only the digest of the words, so the same idea suggested twice is one idea, credited to
 * whoever was first.
 */
export function ideaId(idea: { type: "idea" }): IdeaId {
  return `idea:${sha256Hex(signingPayload(idea))}`;
}

/**
 * An operator's signed report that an idea breaks the rules. Flags are requests to a node,
 * not log entries; the signature shows which operator sent one.
 */
export const IdeaFlagSchema = z.strictObject({
  type: z.literal("idea_flag"),
  operator: OperatorIdSchema,
  idea: IdeaIdSchema,
  reason: z.enum(IDEA_FLAG_REASONS),
  note: boundedText(LIMITS.maxFlagNote).optional(),
  sig: SignatureSchema,
});
export type IdeaFlag = z.infer<typeof IdeaFlagSchema>;
