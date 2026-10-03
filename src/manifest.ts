import { z } from "zod";
import { boundedText } from "./entries";
import { DigestSchema } from "./hash";
import { WORK_KINDS } from "./vocabulary";
import { WRITTEN_BY } from "./vocabulary";

// An SPDX license identifier's shape, such as "CC-BY-4.0" or "MIT".
const LicenseIdSchema = z
  .string()
  .regex(/^[A-Za-z0-9.+-]{1,64}$/, "Expected an SPDX license identifier, such as CC-BY-4.0");

/**
 * What one independent replication of the work's measurements takes: hands-on hours of each
 * kind of work, and how many days it takes from start to finish. A wet-lab replication might
 * be 40 lab hours over 30 days. Its publisher prepays a bounty for it.
 */
export const ReplicationSchema = z.strictObject({
  needs: z
    .array(z.strictObject({ kind: z.enum(WORK_KINDS), hours: z.number().positive().max(100_000) }))
    .min(1)
    .max(WORK_KINDS.length)
    .refine((needs) => new Set(needs.map((need) => need.kind)).size === needs.length, "List each kind once"),
  days: z.number().positive().max(3650),
});
export type Replication = z.infer<typeof ReplicationSchema>;

/** Licensed software a computation needs, such as "matlab" or "stata". */
export const SoftwareTagSchema = z
  .string()
  .regex(/^[a-z0-9]+(-[a-z0-9]+)*$/, "Expected a lowercase software tag, such as matlab")
  .max(40);

// A field tag such as "machine-learning": lowercase words joined by hyphens.
export const FieldSchema = z
  .string()
  .regex(/^[a-z0-9]+(-[a-z0-9]+)*$/, "Expected a lowercase field tag, such as machine-learning")
  .max(40);

/**
 * manifest.json: who publishes the bundle, under what licenses, and what reproducing it takes.
 * The publisher is named by the digest of its public key, which is the same on every log,
 * where operator IDs are not.
 */
export const ManifestSchema = z.strictObject({
  operator_key_digest: DigestSchema,
  fields: z.array(FieldSchema).min(1).max(5),
  license: z.strictObject({
    prose: LicenseIdSchema,
    code: LicenseIdSchema.optional(),
    data: z.string().trim().min(1).max(200).optional(),
  }),
  /**
   * What re-running the work's computations takes: minutes of machine time, whether it needs
   * a GPU, and any licensed software it needs, as lowercase tags such as "matlab". Jobs go to
   * verifiers that say they can run it.
   */
  compute: z.strictObject({
    minutes: z.number().positive().max(7 * 24 * 60),
    gpu: z.boolean(),
    software: z.array(SoftwareTagSchema).max(10).optional(),
  }),
  /**
   * Who wrote the work, when people did: "person", or "both" for people and agents together.
   * Without it the bundle is labeled as an agent's.
   */
  written_by: z.enum(WRITTEN_BY).optional(),
  /** Set when this bundle corrects an earlier one by the same operator. */
  replaces: DigestSchema.optional(),
  /** What replicating its measurements takes; required exactly when a claim has a measurement. */
  replication: ReplicationSchema.optional(),
  /**
   * The publisher's own hazard screen: the digest of the rubric it applied and the model that
   * applied it. A publisher submits only work its screen answered "none" for.
   */
  hazard_screen: z
    .strictObject({ rubric: DigestSchema, model: boundedText(100) })
    .optional(),
});
export type Manifest = z.infer<typeof ManifestSchema>;
