import { z } from "zod";
import { ClaimIdSchema } from "./claims";
import { boundedText, OperatorIdSchema, SignatureSchema } from "./entries";
import { DigestSchema } from "./hash";
import { CHALLENGE_GROUNDS, CHALLENGE_VERDICTS } from "./vocabulary";

// Challenges. Any operator with an identity can challenge a published claim with evidence; a
// panel of verifiers from uninvolved organizations settles it. An upheld challenge refutes the
// claim. The challenge is logged in the clear, and the panel's reviews are sealed until two
// agree, so no panelist can follow another.

/**
 * A challenge to a claim: why the challenger thinks it is wrong (`ground`), and the digest of
 * the files that make the case, digested like an attestation's evidence.
 */
export const ChallengeEntrySchema = z.strictObject({
  type: z.literal("challenge"),
  challenger: OperatorIdSchema,
  claim: ClaimIdSchema,
  ground: z.enum(CHALLENGE_GROUNDS),
  evidence: DigestSchema,
  sig: SignatureSchema,
});
export type ChallengeEntry = z.infer<typeof ChallengeEntrySchema>;

/**
 * A panelist's verdict on a challenge, named by the challenge's log index, after examining
 * `bundle`, the version of the work the job carried. `evidence` digests what the panelist
 * checked or re-ran, and `model_family` is one the panelist declared.
 */
export const ChallengeReviewEntrySchema = z.strictObject({
  type: z.literal("challenge_review"),
  reviewer: OperatorIdSchema,
  challenge: z.number().int().nonnegative(),
  bundle: DigestSchema,
  verdict: z.enum(CHALLENGE_VERDICTS),
  evidence: DigestSchema,
  model_family: boundedText(60),
  sig: SignatureSchema,
});
export type ChallengeReviewEntry = z.infer<typeof ChallengeReviewEntrySchema>;
