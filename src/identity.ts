import { z } from "zod";
import { DomainSchema, OperatorIdSchema, PublicKeySchema, SignatureSchema, signingPayload } from "./entries";
import { sign, verify, type SigningKey } from "./signing";

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
 * A GitHub account as an organization: `github:` and the account's numeric ID, which GitHub
 * never changes or gives to another account, unlike its login.
 */
export const GithubAccountSchema = z
  .string()
  .regex(/^github:[1-9][0-9]{0,15}$/, "Expected a GitHub account as github:<numeric ID>");

/**
 * Who vouched for an operator: the GitHub account a person signed in with on the node's site
 * to vouch for it.
 */
export const VoucherSchema = GithubAccountSchema;

/**
 * How an operator's identity was established, each way recorded in the log:
 *
 * - a domain whose DNS names the operator's key, signed by the operator;
 * - a public GitHub repository whose `.sciencejournal` file names the operator's key, signed
 *   by the operator;
 * - a vouch from a GitHub account: its holder signs in with it on the node's site, the log
 *   attests that in `voucher_sig`, signing the entry without either signature, and the
 *   operator countersigns everything but `sig`, so the log alone shows both agreed;
 * - an invitation from the node, signed by the log's own key.
 */
const VouchedIdentityEntrySchema = z.strictObject({
  type: z.literal("identity"),
  kind: z.literal("vouched"),
  operator: OperatorIdSchema,
  voucher: VoucherSchema,
  voucher_sig: SignatureSchema,
  sig: SignatureSchema,
});

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
  VouchedIdentityEntrySchema,
  z.strictObject({
    type: z.literal("identity"),
    kind: z.literal("invited"),
    operator: OperatorIdSchema,
    sig: SignatureSchema,
  }),
]);
export type IdentityEntry = z.infer<typeof IdentityEntrySchema>;
export type VouchedIdentityEntry = z.infer<typeof VouchedIdentityEntrySchema>;

/** A vouch before the operator countersigns it: the entry without `sig`. */
export const VouchSchema = VouchedIdentityEntrySchema.omit({ sig: true });
export type Vouch = z.infer<typeof VouchSchema>;

/** The bytes the log signs to attest a vouch: the entry without `sig` or `voucher_sig`. */
export function vouchPayload(entry: Pick<Vouch, "operator" | "voucher">): Uint8Array {
  const unsigned = { type: "identity", kind: "vouched", operator: entry.operator, voucher: entry.voucher };
  return signingPayload(unsigned);
}

/** A vouch the log attests, once the voucher's holder has signed in: what the operator countersigns. */
export function attestVouch(entry: Pick<Vouch, "operator" | "voucher">, logKey: SigningKey): Vouch {
  const { operator, voucher } = entry;
  return { type: "identity", kind: "vouched", operator, voucher, voucher_sig: sign(vouchPayload(entry), logKey) };
}

/** Whether a log key attested the vouch. */
export function verifyVouch(entry: Vouch, logKey: string): boolean {
  return verify(entry.voucher_sig, vouchPayload(entry), logKey);
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
 * - the GitHub account that vouched for it: its holder signs in again to approve, the log
 *   attests that in `voucher_sig`, signing the entry without either signature, and the new key
 *   countersigns everything but `sig`, as in a vouch, so the log alone shows both agreed;
 * - the log, for an invited operator, on a reviewer's word.
 *
 * Nothing the old key signed from log index `since` on counts.
 */
const VouchedRecoveryEntrySchema = z.strictObject({
  ...recovery,
  kind: z.literal("vouched"),
  voucher: VoucherSchema,
  voucher_sig: SignatureSchema,
  sig: SignatureSchema,
});

export const KeyRecoveryEntrySchema = z.discriminatedUnion("kind", [
  z.strictObject({ ...recovery, kind: z.literal("domain"), domain: DomainSchema, sig: SignatureSchema }),
  z.strictObject({ ...recovery, kind: z.literal("github"), repository: RepositorySchema, sig: SignatureSchema }),
  VouchedRecoveryEntrySchema,
  z.strictObject({ ...recovery, kind: z.literal("invited"), sig: SignatureSchema }),
]);
export type KeyRecoveryEntry = z.infer<typeof KeyRecoveryEntrySchema>;
export type VouchedRecoveryEntry = z.infer<typeof VouchedRecoveryEntrySchema>;

/**
 * A vouched operator asking the account that vouched for it to approve a new key: the
 * recovery without `voucher_sig`, signed by the new key over everything but `sig`, which
 * proves the operator holds it. It waits at the node for the account's holder, and isn't logged.
 */
export const VouchedRecoveryRequestSchema = VouchedRecoveryEntrySchema.omit({ voucher_sig: true });
export type VouchedRecoveryRequest = z.infer<typeof VouchedRecoveryRequestSchema>;

type RecoveryFields = Pick<VouchedRecoveryEntry, "operator" | "key" | "voucher" | "since">;

/** A vouched recovery without either signature: what the log attests and the new key first signs. */
export function unsignedRecovery(entry: RecoveryFields) {
  const { operator, key, voucher, since } = entry;
  return { type: "key_recovery" as const, kind: "vouched" as const, operator, key, voucher, since };
}

/** The bytes the log signs to attest a recovery's approval: the entry without `sig` or `voucher_sig`. */
export function recoveryApprovalPayload(entry: RecoveryFields): Uint8Array {
  return signingPayload(unsignedRecovery(entry));
}

/** The log's attestation that the account that vouched approved the recovery, for `voucher_sig`. */
export function attestRecoveryApproval(entry: RecoveryFields, logKey: SigningKey) {
  return sign(recoveryApprovalPayload(entry), logKey);
}

/** Whether a log key attested the recovery's approval. */
export function verifyRecoveryApproval(entry: RecoveryFields & Pick<VouchedRecoveryEntry, "voucher_sig">, logKey: string): boolean {
  return verify(entry.voucher_sig, recoveryApprovalPayload(entry), logKey);
}
