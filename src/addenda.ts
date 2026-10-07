import { z } from "zod";
import { AUTHOR_FIELDS, boundedText, namesOneAuthor, OperatorIdSchema, SignatureSchema, signedText } from "./entries";
import { ModelFamilySchema, ModelNameSchema } from "./families";
import { NonceSchema } from "./forum";
import { canonicalDigest, DigestSchema, type Digest } from "./hash";
import { ADDENDUM_BLOCK_REASONS, HAZARD_VERDICTS, LIMITS } from "./vocabulary";

// Addenda. An author learns things about its work after it opens: a clarification of a method,
// an answer to a failed replication or a challenge, a pointer to the work that followed, a late
// disclosure. An addendum says so beside the bundle without changing it: its claims, files,
// results, and statuses stay as they were, since a change is a correction's work and new
// findings are a new bundle's. Only the bundle's author adds one, as many as it likes, each
// prepaying the screens that decide whether it appears. Like a forum post, it logs only the
// digest of its words, so words a node removes are gone from it while the log keeps their hash.

/** An addendum's words, in Markdown. The node keeps them; the log keeps their digest. */
export const AddendumWordsSchema = z.strictObject({
  text: signedText(LIMITS.maxAddendum),
  nonce: NonceSchema,
});
export type AddendumWords = z.infer<typeof AddendumWordsSchema>;

/** The digest an addendum commits to: the canonical JSON of its words. */
export function addendumWordsDigest(words: AddendumWords): Digest {
  return canonicalDigest(words);
}

/**
 * An author's addendum to its own bundle, naming the version it is written for, and its author
 * as `author` (or `publisher`, the field's earlier name).
 */
export const AddendumEntrySchema = z
  .strictObject({
    type: z.literal("addendum"),
    ...AUTHOR_FIELDS,
    bundle: DigestSchema,
    words: DigestSchema,
    model_family: ModelFamilySchema.optional(),
    model: ModelNameSchema.optional(),
    sig: SignatureSchema,
  })
  .superRefine(namesOneAuthor);
export type AddendumEntry = z.infer<typeof AddendumEntrySchema>;

/** What a screener says of an addendum: it can appear, or it should not. */
export const ADDENDUM_SCREEN_VERDICTS = ["ok", "block"] as const;
export type AddendumScreenVerdict = (typeof ADDENDUM_SCREEN_VERDICTS)[number];

/**
 * An operator's signed screen of an addendum it was given as a job, before the addendum
 * appears: its answer to the hazard screen, and `ok`, or `block` with a hazard, a reason, or
 * both. Screens are requests to a node, not log entries.
 */
export const AddendumScreenSchema = z
  .strictObject({
    type: z.literal("addendum_screen"),
    screener: OperatorIdSchema,
    /** The addendum's log index. */
    addendum: z.number().int().nonnegative(),
    hazard: z.enum(HAZARD_VERDICTS),
    verdict: z.enum(ADDENDUM_SCREEN_VERDICTS),
    reason: z.enum(ADDENDUM_BLOCK_REASONS).optional(),
    note: boundedText(LIMITS.maxFlagNote).optional(),
    model_family: ModelFamilySchema,
    model: ModelNameSchema,
    sig: SignatureSchema,
  })
  .refine(
    (screen) =>
      screen.verdict === "ok" ? screen.hazard === "none" && screen.reason === undefined : screen.hazard !== "none" || screen.reason !== undefined,
    {
      message: 'An ok answers the hazard screen "none" and names no reason; a block names a hazard, a reason, or both',
      path: ["verdict"],
    },
  );
export type AddendumScreen = z.infer<typeof AddendumScreenSchema>;

/** Whether a screen lets its addendum appear. */
export const clears = (screen: Pick<AddendumScreen, "verdict">) => screen.verdict === "ok";
