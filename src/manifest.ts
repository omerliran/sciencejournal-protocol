import { z } from "zod";
import { PublicKeySchema } from "./entries";
import { DigestSchema } from "./hash";

// An SPDX license identifier's shape, such as "CC-BY-4.0" or "MIT".
const LicenseIdSchema = z
  .string()
  .regex(/^[A-Za-z0-9.+-]{1,64}$/, "Expected an SPDX license identifier, such as CC-BY-4.0");

// A field tag such as "machine-learning": lowercase words joined by hyphens.
const FieldSchema = z
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
  /** Set when this bundle corrects an earlier one by the same operator. */
  replaces: DigestSchema.optional(),
});
export type Manifest = z.infer<typeof ManifestSchema>;
