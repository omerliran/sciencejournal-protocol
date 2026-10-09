import { z } from "zod";
import { ModelFamilySchema, ModelNameSchema } from "./families";
import { OperatorIdSchema, requireFindingWithCopyright, SignatureSchema } from "./entries";
import { canonicalDigest, DigestSchema, type Digest } from "./hash";
import { SoftwareTagSchema } from "./manifest";
import { FLAG_CONCERNS, HAZARD_VERDICTS, WITHDRAWAL_REASONS } from "./vocabulary";

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

/**
 * A screener's or panelist's signed hazard verdict on a bundle, with the digest of its finding,
 * sent beside it, when the verdict is "copyright".
 */
export const HazardReviewEntrySchema = z
  .strictObject({
    type: z.literal("hazard_review"),
    reviewer: OperatorIdSchema,
    bundle: DigestSchema,
    verdict: z.enum(HAZARD_VERDICTS),
    copyright: DigestSchema.optional(),
    model_family: ModelFamilySchema.optional(),
    model: ModelNameSchema.optional(),
    sig: SignatureSchema,
  })
  .superRefine((entry, ctx) => requireFindingWithCopyright(entry.verdict, entry.copyright, "verdict", ctx));
export type HazardReviewEntry = z.infer<typeof HazardReviewEntrySchema>;

/**
 * An operator's signed concern about a published bundle, which sends it to a panel. Copyright
 * isn't one: its holder sends the node a notice.
 */
export const HazardFlagEntrySchema = z.strictObject({
  type: z.literal("hazard_flag"),
  operator: OperatorIdSchema,
  bundle: DigestSchema,
  concern: z.enum(FLAG_CONCERNS),
  model_family: ModelFamilySchema.optional(),
  model: ModelNameSchema.optional(),
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
 * What a verifier can run now: the most minutes it will spend on a job, whether it has a GPU,
 * how many megabytes it can download, and the licensed software it has. Without it, a
 * verifier gets only work that takes an hour or less on a CPU, downloads 100 MB or less, and
 * needs no licensed software. A verifier that can't run code says 0 minutes, and gets only
 * work it reads. One that says `ideas` may also be given ideas from people to screen. Every
 * verifier may be given claims to rate for importance when nothing else fits, unless it says
 * `importance: false`.
 */
export const CapabilitiesSchema = z.strictObject({
  minutes: z.number().nonnegative().max(7 * 24 * 60),
  gpu: z.boolean(),
  download_mb: z.number().positive().max(10_000_000),
  software: z.array(SoftwareTagSchema).max(50),
  /** Whether it screens ideas from people before they appear, a job of judgment that runs nothing. */
  ideas: z.boolean().optional(),
  /** Whether it rates how important published claims are when no other job fits, another job of judgment that runs nothing: true unless it says false. */
  importance: z.boolean().optional(),
});
export type Capabilities = z.infer<typeof CapabilitiesSchema>;

/**
 * A verifier asking for work. Signed, and fresh: the node accepts it only within a few minutes
 * of `time`, so only the key holder can receive the sealed files a job carries.
 */
export const JobRequestSchema = z.strictObject({
  type: z.literal("job_request"),
  operator: OperatorIdSchema,
  time: z.iso.datetime(),
  can: CapabilitiesSchema.optional(),
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type JobRequest = z.infer<typeof JobRequestSchema>;

/** The most files one upload request may name; more go in further requests. */
export const UPLOAD_FILES_PER_REQUEST = 100;

/**
 * An operator asking to send large files ahead of a bundle: each file's digest and size.
 * Signed and fresh, like a job request, so only the key holder spends its upload allowance.
 */
export const UploadRequestSchema = z.strictObject({
  type: z.literal("upload_request"),
  operator: OperatorIdSchema,
  time: z.iso.datetime(),
  files: z
    .array(z.strictObject({ digest: DigestSchema, bytes: z.number().int().positive() }))
    .min(1)
    .max(UPLOAD_FILES_PER_REQUEST),
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type UploadRequest = z.infer<typeof UploadRequestSchema>;

/**
 * An author asking for more reproductions of its published bundle after a claim's
 * reproduction failed, before the claim is refuted: it prepays them, and they go to
 * organizations not yet involved with the bundle. Signed and fresh, like a job request, so only
 * the key holder spends its credit.
 */
export const AppealRequestSchema = z.strictObject({
  type: z.literal("appeal_request"),
  operator: OperatorIdSchema,
  bundle: DigestSchema,
  time: z.iso.datetime(),
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type AppealRequest = z.infer<typeof AppealRequestSchema>;
