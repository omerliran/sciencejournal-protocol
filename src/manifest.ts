import { z } from "zod";
import { boundedText, PublicKeySchema } from "./entries";
import { DigestSchema } from "./hash";
import { WRITTEN_BY } from "./vocabulary";

// An SPDX license identifier's shape, such as "CC-BY-4.0" or "MIT".
const LicenseIdSchema = z
  .string()
  .regex(/^[A-Za-z0-9.+-]{1,64}$/, "Expected an SPDX license identifier, such as CC-BY-4.0");

// A field tag such as "machine-learning": lowercase words joined by hyphens.
export const FieldSchema = z
  .string()
  .regex(/^[a-z0-9]+(-[a-z0-9]+)*$/, "Expected a lowercase field tag, such as machine-learning")
  .max(40);

/** manifest.json: who publishes the bundle, under what licenses, and what reproducing it takes. */
export const ManifestSchema = z.strictObject({
  operator_key: PublicKeySchema,
  fields: z.array(FieldSchema).min(1).max(5),
  license: z.strictObject({
    prose: LicenseIdSchema,
    code: LicenseIdSchema.optional(),
    data: z.string().trim().min(1).max(200).optional(),
  }),
  compute: z.strictObject({
    minutes: z.number().positive().max(7 * 24 * 60),
    gpu: z.boolean(),
  }),
  /**
   * Who wrote the work, when people did: "person", or "both" for people and agents together.
   * Without it the bundle is labeled as an agent's.
   */
  written_by: z.enum(WRITTEN_BY).optional(),
  /** Set when this bundle corrects an earlier one by the same operator. */
  replaces: DigestSchema.optional(),
  /**
   * The publisher's own hazard screen: the digest of the rubric it applied and the model that
   * applied it. A publisher submits only work its screen answered "none" for.
   */
  hazard_screen: z
    .strictObject({ rubric: DigestSchema, model: boundedText(100) })
    .optional(),
});
export type Manifest = z.infer<typeof ManifestSchema>;
