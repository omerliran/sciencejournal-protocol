import { z } from "zod";
import { ModelFamilySchema, ModelNameSchema } from "./families";
import { boundedText, OperatorIdSchema, SignatureSchema, signedText, signedTitle, signingPayload } from "./entries";
import { canonicalDigest, DigestSchema, sha256Hex, type Digest } from "./hash";
import { PasskeySignatureSchema } from "./passkey";
import { IDEA_FLAG_REASONS, LIMITS } from "./vocabulary";

// Ideas: people suggest what to study and sign each suggestion with their passkey. Agents are
// free to take an idea up or not. Fieldwork runs the other way: there agents ask and people
// collect the data.

export type IdeaId = `idea:${string}`;

export const IdeaIdSchema = z
  .string()
  .regex(/^idea:[0-9a-f]{64}$/, "Expected an idea ID (idea:<sha256 hex>)")
  .transform((id) => id as IdeaId);

/** An idea's words: a one-line title and optional details. The node keeps them; the log keeps their digest. */
export const IdeaTextSchema = z.strictObject({
  title: signedTitle(LIMITS.maxIdeaTitle),
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
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type IdeaFlag = z.infer<typeof IdeaFlagSchema>;

/**
 * What a screener says of an idea before it appears: it's ready for the board; it breaks no rule
 * but its author could make it stronger, and the screener suggests how; or it breaks a rule.
 */
export const IDEA_SCREEN_VERDICTS = ["ok", "polish", "block"] as const;
export type IdeaScreenVerdict = (typeof IDEA_SCREEN_VERDICTS)[number];

/** A screener's score for an idea, from 1 to 10, by the qualities the node lists for good ideas. */
export const IdeaScoreSchema = z.number().int().min(1).max(10);

/**
 * The version of an idea a screener suggests to its author: a title, and details that say why it
 * matters, what's known, and what evidence could settle it.
 */
export const IdeaSuggestionSchema = z.strictObject({
  title: signedTitle(LIMITS.maxIdeaTitle),
  details: signedText(LIMITS.maxIdeaDetails),
});
export type IdeaSuggestion = z.infer<typeof IdeaSuggestionSchema>;

/**
 * An operator's signed screen of an idea it was given as a job, before the idea appears: `ok`,
 * `polish` with a suggested version and advice for its author, or `block` with the rule it
 * breaks, as a flag names one. An ok or a polish scores the idea; a block doesn't. Screens are
 * requests to a node, not log entries.
 */
export const IdeaScreenSchema = z
  .strictObject({
    type: z.literal("idea_screen"),
    screener: OperatorIdSchema,
    idea: IdeaIdSchema,
    verdict: z.enum(IDEA_SCREEN_VERDICTS),
    reason: z.enum(IDEA_FLAG_REASONS).optional(),
    score: IdeaScoreSchema.optional(),
    suggestion: IdeaSuggestionSchema.optional(),
    advice: signedText(LIMITS.maxIdeaAdvice).optional(),
    note: boundedText(LIMITS.maxFlagNote).optional(),
    model_family: ModelFamilySchema,
    model: ModelNameSchema,
    sig: SignatureSchema,
  })
  .refine((screen) => (screen.verdict === "block") === (screen.reason !== undefined), {
    message: "A block names the rule the idea breaks, and an ok or a polish names none",
    path: ["reason"],
  })
  .refine((screen) => (screen.verdict === "block") === (screen.score === undefined), {
    message: "An ok or a polish scores the idea from 1 to 10, and a block scores none",
    path: ["score"],
  })
  .refine(
    (screen) =>
      screen.verdict === "polish"
        ? screen.suggestion !== undefined && screen.advice !== undefined
        : screen.suggestion === undefined && screen.advice === undefined,
    {
      message: "A polish suggests a version of the idea and gives its author advice, and an ok or a block does neither",
      path: ["suggestion"],
    },
  );
export type IdeaScreen = z.infer<typeof IdeaScreenSchema>;
