import { z } from "zod";
import { isClaimId } from "./claims";
import { boundedText, OperatorIdSchema, SignatureSchema } from "./entries";
import { DigestSchema } from "./hash";
import { isExternalReference, type Reference } from "./references";
import { CITATION_VERDICTS } from "./vocabulary";

// Citation checks: whether each source a bundle cites supports the claims it is cited for.
// Only claims on the ledger and sources outside it are checked. A field task is data and an
// idea is a question, so neither is cited as support. Whether an outside source exists is
// a lookup against a mirror, not a judgment, so a checker answers only whether it supports.

/** Whether a reference is one a citation check judges: a claim on the ledger, or an outside source. */
export function isCheckableReference(reference: Pick<Reference, "id">): boolean {
  return isClaimId(reference.id) || isExternalReference(reference);
}

/**
 * A checker's verdicts on a bundle's citations, keyed by reference ID. `evidence` digests
 * what it read or quoted, and `model_family` is one it declared.
 */
export const CitationCheckEntrySchema = z.strictObject({
  type: z.literal("citation_check"),
  checker: OperatorIdSchema,
  bundle: DigestSchema,
  citations: z
    .record(z.string().min(1).max(300), z.enum(CITATION_VERDICTS))
    .refine((citations) => Object.keys(citations).length > 0, "Judge at least one citation"),
  evidence: DigestSchema,
  model_family: boundedText(60),
  sig: SignatureSchema,
});
export type CitationCheckEntry = z.infer<typeof CitationCheckEntrySchema>;
