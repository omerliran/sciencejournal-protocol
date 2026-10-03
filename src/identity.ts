import { z } from "zod";
import { DomainSchema, OperatorIdSchema, PublicKeySchema, SignatureSchema, signingPayload } from "./entries";
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

// --- Recovering a lost key ---------------------------------------------------------------

const recovery = {
  type: z.literal("key_recovery"),
  operator: OperatorIdSchema,
  key: PublicKeySchema,
  /** The log index from which nothing the lost key signed counts, or the log's size for nothing. */
  since: z.number().int().nonnegative(),
};

/**
 * An operator taking its ID back with a new key after losing the old one, proven by the
 * identity it counts as, since a stolen key could rotate itself first:
 *
 * - its domain, whose record now names the new key, which signs the entry;
 * - its GitHub repository, whose `.sciencejournal` file now names the new key, which signs it;
 * - the volunteer who vouched for it: their passkey approves the entry without either
 *   signature, in `voucher_sig`, and the new key countersigns everything but `sig`, as in a
 *   vouch, so the log alone shows both agreed;
 * - the log, for an invited operator, on a reviewer's word.
 *
 * Nothing the old key signed from log index `since` on counts.
 */
export const KeyRecoveryEntrySchema = z.discriminatedUnion("kind", [
  z.strictObject({ ...recovery, kind: z.literal("domain"), domain: DomainSchema, sig: SignatureSchema }),
  z.strictObject({ ...recovery, kind: z.literal("github"), repository: RepositorySchema, sig: SignatureSchema }),
  z.strictObject({
    ...recovery,
    kind: z.literal("vouched"),
    observer: ObserverIdSchema,
    voucher_sig: PasskeySignatureSchema,
    sig: SignatureSchema,
  }),
  z.strictObject({ ...recovery, kind: z.literal("invited"), sig: SignatureSchema }),
]);
export type KeyRecoveryEntry = z.infer<typeof KeyRecoveryEntrySchema>;
export type VouchedRecoveryEntry = Extract<KeyRecoveryEntry, { kind: "vouched" }>;

/**
 * A vouched operator asking its volunteer to approve a new key: the recovery without
 * `voucher_sig`, signed by the new key over everything but `sig`, which proves the operator
 * holds it. It waits at the node for the volunteer, and isn't logged.
 */
export const VouchedRecoveryRequestSchema = KeyRecoveryEntrySchema.options[2].omit({ voucher_sig: true });
export type VouchedRecoveryRequest = z.infer<typeof VouchedRecoveryRequestSchema>;

/** A vouched recovery without either signature: what the volunteer approves and the new key first signs. */
export function unsignedRecovery(entry: Pick<VouchedRecoveryEntry, "operator" | "key" | "observer" | "since">) {
  const { operator, key, observer, since } = entry;
  return { type: "key_recovery" as const, kind: "vouched" as const, operator, key, observer, since };
}

/** The bytes a volunteer's passkey signs to approve a recovery: the entry without `sig` or `voucher_sig`. */
export function recoveryApprovalPayload(
  entry: Pick<VouchedRecoveryEntry, "operator" | "key" | "observer" | "since">,
): Uint8Array {
  return signingPayload(unsignedRecovery(entry));
}

/** Checks a vouched recovery's passkey approval against the volunteer's key; null if it fails. */
export function verifyRecoveryApproval(
  entry: Pick<VouchedRecoveryEntry, "operator" | "key" | "observer" | "since" | "voucher_sig">,
  observerKey: string,
): PasskeyAssertion | null {
  return verifyPasskey(entry.voucher_sig, recoveryApprovalPayload(entry), observerKey);
}
