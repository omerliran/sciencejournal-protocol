import { z } from "zod";
import { DomainSchema, OperatorIdSchema, SignatureSchema, signingPayload } from "./entries";
import { ObserverIdSchema } from "./fieldwork";
import { PasskeySignatureSchema, verifyPasskey, type PasskeyAssertion } from "./passkey";

/**
 * A GitHub repository, as `owner/name`: the owner a user or an organization, and the name as
 * GitHub allows it.
 */
export const RepositorySchema = z
  .string()
  .max(140)
  .regex(
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/,
    "Expected a GitHub repository as owner/name, such as example-lab/agents",
  );

/**
 * How an operator's identity was established, each way recorded in the log:
 *
 * - a domain whose DNS names the operator's key, signed by the operator;
 * - a public GitHub repository whose `.sciencejournal` file names the operator's key, signed
 *   by the operator;
 * - a vouch from an approved volunteer: the volunteer's passkey signs the entry without either
 *   signature, in `voucher_sig`, and the operator countersigns everything but `sig`, so the
 *   log alone shows both agreed;
 * - an invitation from the node, signed by the log's own key.
 */
export const IdentityEntrySchema = z.discriminatedUnion("kind", [
  z.strictObject({
    type: z.literal("identity"),
    kind: z.literal("domain"),
    operator: OperatorIdSchema,
    domain: DomainSchema,
    sig: SignatureSchema,
  }),
  z.strictObject({
    type: z.literal("identity"),
    kind: z.literal("github"),
    operator: OperatorIdSchema,
    repository: RepositorySchema,
    sig: SignatureSchema,
  }),
  z.strictObject({
    type: z.literal("identity"),
    kind: z.literal("vouched"),
    operator: OperatorIdSchema,
    observer: ObserverIdSchema,
    voucher_sig: PasskeySignatureSchema,
    sig: SignatureSchema,
  }),
  z.strictObject({
    type: z.literal("identity"),
    kind: z.literal("invited"),
    operator: OperatorIdSchema,
    sig: SignatureSchema,
  }),
]);
export type IdentityEntry = z.infer<typeof IdentityEntrySchema>;
export type VouchedIdentityEntry = Extract<IdentityEntry, { kind: "vouched" }>;

/** A volunteer's vouch before the operator countersigns it: the entry without `sig`. */
export const VouchSchema = IdentityEntrySchema.options[2].omit({ sig: true });
export type Vouch = z.infer<typeof VouchSchema>;

/** The bytes a volunteer's passkey signs to vouch: the entry without `sig` or `voucher_sig`. */
export function vouchPayload(entry: Pick<Vouch, "operator" | "observer">): Uint8Array {
  const unsigned = { type: "identity", kind: "vouched", operator: entry.operator, observer: entry.observer };
  return signingPayload(unsigned);
}

/** Checks a vouch's passkey signature against the volunteer's key; null if it fails. */
export function verifyVouch(entry: Vouch, observerKey: string): PasskeyAssertion | null {
  return verifyPasskey(entry.voucher_sig, vouchPayload(entry), observerKey);
}
