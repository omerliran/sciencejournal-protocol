import { z } from "zod";
import { OperatorIdSchema, SignatureSchema, signingPayload } from "./entries";
import { canonicalDigest, DigestSchema, sha256Hex, type Digest } from "./hash";

// Pre-registration: an analysis plan committed by hash before the work runs. The log holds
// only the commitment, so the plan stays private until the bundle that reports the work
// carries it under plan/, where its files must digest to what was registered.

/** Where a bundle carries the plan it reports. */
export const PLAN_DIRECTORY = "plan";

export type PreregistrationId = `prereg:${string}`;

export const PreregistrationIdSchema = z
  .string()
  .regex(/^prereg:[0-9a-f]{64}$/, "Expected a pre-registration ID (prereg:<sha256 hex>)")
  .transform((id) => id as PreregistrationId);

/**
 * A plan committed before the work: the digest of its files, digested like evidence with
 * paths relative to the plan, and the date (UTC) its author expects to report by.
 */
export const PreregistrationEntrySchema = z.strictObject({
  type: z.literal("preregistration"),
  operator: OperatorIdSchema,
  plan: DigestSchema,
  report_by: z.iso.date(),
  sig: SignatureSchema,
});
export type PreregistrationEntry = z.infer<typeof PreregistrationEntrySchema>;

/** A registration's ID: `prereg:` and the SHA-256 of its entry without the signature. */
export function preregistrationId(entry: { type: "preregistration" }): PreregistrationId {
  return `prereg:${sha256Hex(signingPayload(entry))}`;
}

/**
 * The plan a bundle carries, digested as it was registered: its files under plan/, by their
 * paths within it. Null when the bundle carries no plan.
 */
export function planDigest(fileDigests: Readonly<Record<string, string>>): Digest | null {
  const prefix = `${PLAN_DIRECTORY}/`;
  const plan = Object.fromEntries(
    Object.entries(fileDigests)
      .filter(([path]) => path.startsWith(prefix))
      .map(([path, digest]) => [path.slice(prefix.length), digest]),
  );
  return Object.keys(plan).length > 0 ? canonicalDigest(plan) : null;
}
