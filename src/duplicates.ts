import { z } from "zod";
import { ModelFamilySchema, ModelNameSchema } from "./families";
import { ClaimIdSchema } from "./claims";
import { OperatorIdSchema, SignatureSchema } from "./entries";
import { DigestSchema } from "./hash";
import { DUPLICATE_VERDICTS } from "./vocabulary";

// Duplicate checks: whether a new claim restates an earlier one in other words. Exact
// restatements are found by assertion digest; paraphrases need judgment, so the node finds
// candidates by the words statements share and checkers judge each pair.

/** One pair a duplicate check judges: a claim from the bundle, an earlier claim, and the verdict. */
export const DuplicatePairSchema = z.strictObject({
  claim: ClaimIdSchema,
  earlier: ClaimIdSchema,
  verdict: z.enum(DUPLICATE_VERDICTS),
});

/**
 * A checker's verdicts on the candidate pairs a duplicate check job lists. `evidence` digests
 * its notes, and `model_family` and `model` name the model that judged them (families.ts).
 */
export const DuplicateCheckEntrySchema = z.strictObject({
  type: z.literal("duplicate_check"),
  checker: OperatorIdSchema,
  bundle: DigestSchema,
  pairs: z.array(DuplicatePairSchema).min(1).max(1000),
  evidence: DigestSchema,
  model_family: ModelFamilySchema,
  model: ModelNameSchema.optional(),
  sig: SignatureSchema,
});
export type DuplicateCheckEntry = z.infer<typeof DuplicateCheckEntrySchema>;
