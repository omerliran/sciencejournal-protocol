import { z } from "zod";
import { OperatorIdSchema, SignatureSchema } from "./entries";
import { canonicalDigest, DigestSchema, type Digest } from "./hash";
import { HAZARD_CATEGORIES, HAZARD_VERDICTS, WITHDRAWAL_REASONS } from "./vocabulary";

// Sealed rounds. A new bundle isn't public at first: the log records only a commitment to it,
// which fixes priority without revealing anything, and blind verification jobs run while it
// is sealed. What those jobs produce is committed the same way. When the round closes, each
// committed entry is logged in full with the salt that opens its commitment, so anyone can
// check that the record was fixed before the verdicts were known. Canaries hide among the
// sealed bundles, and look the same in the log until they are revealed.

/** The commitment to an entry: the digest of `{"entry", "salt"}`, with a random 32-byte salt. */
export function sealCommitment<T extends { type: string }>(entry: T, salt: string): Digest {
  return canonicalDigest({ entry, salt });
}

export const SaltSchema = z.string().regex(/^[0-9a-f]{64}$/, "Expected 32 bytes in hex");

/** In a revealed entry's leaf: the sealed entry it opens, and the salt that opens it. */
export const SealRevealSchema = z.strictObject({
  index: z.number().int().nonnegative(),
  salt: SaltSchema,
});
export type SealReveal = z.infer<typeof SealRevealSchema>;

/** The log's commitment to an entry it will reveal when the entry's round closes. */
export const SealedEntrySchema = z.strictObject({
  type: z.literal("sealed"),
  commitment: DigestSchema,
  sig: SignatureSchema,
});
export type SealedEntry = z.infer<typeof SealedEntrySchema>;

/**
 * A canary, revealed: a sealed bundle the node made from another (`source`) by changing one
 * declared result beyond its tolerance, so an honest reproduction reports a mismatch. Signed
 * by the log. `pointer` is a JSON Pointer into the results file at `path`.
 */
export const CanaryEntrySchema = z.strictObject({
  type: z.literal("canary"),
  bundle: DigestSchema,
  source: DigestSchema,
  mutation: z.strictObject({
    path: z.string(),
    pointer: z.string(),
    from: z.number(),
    to: z.number(),
  }),
  sig: SignatureSchema,
});
export type CanaryEntry = z.infer<typeof CanaryEntrySchema>;

/** A panelist's signed verdict on a hazard concern about a bundle. */
export const HazardReviewEntrySchema = z.strictObject({
  type: z.literal("hazard_review"),
  reviewer: OperatorIdSchema,
  bundle: DigestSchema,
  verdict: z.enum(HAZARD_VERDICTS),
  sig: SignatureSchema,
});
export type HazardReviewEntry = z.infer<typeof HazardReviewEntrySchema>;

/** An operator's signed concern about a published bundle, which sends it to a panel. */
export const HazardFlagEntrySchema = z.strictObject({
  type: z.literal("hazard_flag"),
  operator: OperatorIdSchema,
  bundle: DigestSchema,
  concern: z.enum(HAZARD_CATEGORIES),
  sig: SignatureSchema,
});
export type HazardFlagEntry = z.infer<typeof HazardFlagEntrySchema>;

/**
 * Content the node stopped serving, signed by the log. The hash stays as a tombstone.
 * `sealed` is set when the bundle never opened: the index of the commitment this closes.
 */
export const WithdrawalEntrySchema = z.strictObject({
  type: z.literal("withdrawal"),
  bundle: DigestSchema,
  reason: z.enum(WITHDRAWAL_REASONS),
  sealed: z.number().int().nonnegative().optional(),
  sig: SignatureSchema,
});
export type WithdrawalEntry = z.infer<typeof WithdrawalEntrySchema>;

/**
 * A verifier asking for work. Signed, and fresh: the node accepts it only within a few minutes
 * of `time`, so only the key holder can receive the sealed files a job carries.
 */
export const JobRequestSchema = z.strictObject({
  type: z.literal("job_request"),
  operator: OperatorIdSchema,
  time: z.iso.datetime(),
  sig: SignatureSchema,
});
export type JobRequest = z.infer<typeof JobRequestSchema>;
