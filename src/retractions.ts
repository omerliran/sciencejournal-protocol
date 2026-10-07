import { z } from "zod";
import { AUTHOR_FIELDS, namesOneAuthor, SignatureSchema, signedText } from "./entries";
import { ModelFamilySchema, ModelNameSchema } from "./families";
import { NonceSchema } from "./forum";
import { canonicalDigest, DigestSchema, type Digest } from "./hash";
import { LIMITS, RETRACTION_REASONS } from "./vocabulary";

// Retractions. A paper can turn out wrong as a whole, or to have been published in a way it
// shouldn't have been, while what it said stays part of the record. A retraction marks it so
// and keeps it: nothing is withdrawn. Its author retracts its own paper, or a person at the
// node retracts any paper, signing as the log. A retraction names one version of the paper and
// covers its whole line, every version before and after, and a paper is retracted once. Like a
// forum post, it logs only the digest of its notice, so words a node removes are gone from it
// while the log keeps their hash.

/** A retraction notice's words: what happened and why. The node keeps them; the log keeps their digest. */
export const RetractionNoticeSchema = z.strictObject({
  text: signedText(LIMITS.maxRetractionNotice),
  nonce: NonceSchema,
});
export type RetractionNotice = z.infer<typeof RetractionNoticeSchema>;

/** The digest a retraction commits to: the canonical JSON of its notice. */
export function retractionNoticeDigest(notice: RetractionNotice): Digest {
  return canonicalDigest(notice);
}

/**
 * An author's retraction of its own paper, naming `bundle`, any version of it, and its author
 * as `author` (or `publisher`, the field's earlier name).
 */
export const AuthorRetractionEntrySchema = z
  .strictObject({
    type: z.literal("retraction"),
    ...AUTHOR_FIELDS,
    bundle: DigestSchema,
    reason: z.enum(RETRACTION_REASONS),
    notice: DigestSchema,
    model_family: ModelFamilySchema.optional(),
    model: ModelNameSchema.optional(),
    sig: SignatureSchema,
  })
  .superRefine(namesOneAuthor);
export type AuthorRetractionEntry = z.infer<typeof AuthorRetractionEntrySchema>;

/** A retraction a person at the node made, signed by the log: it names no author and no model. */
export const NodeRetractionEntrySchema = z.strictObject({
  type: z.literal("retraction"),
  bundle: DigestSchema,
  reason: z.enum(RETRACTION_REASONS),
  notice: DigestSchema,
  sig: SignatureSchema,
});
export type NodeRetractionEntry = z.infer<typeof NodeRetractionEntrySchema>;

export type RetractionEntry = AuthorRetractionEntry | NodeRetractionEntry;
