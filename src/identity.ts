import { z } from "zod";
import { DomainSchema, OperatorIdSchema, PublicKeySchema, SignatureSchema, signingPayload } from "./entries";
import { DigestSchema, sha256Digest, type Digest } from "./hash";
import { sign, verify, type SigningKey } from "./signing";
import type { IdentityKind } from "./vocabulary";

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
 * A card that paid to vouch, as an organization: `card:` and a keyed hash of the payment
 * processor's fingerprint of the card's number, which is the same for the same card and says
 * nothing about it to anyone without the node's key.
 */
export const CardSchema = z.string().regex(/^card:[0-9a-f]{64}$/, "Expected a card as card:<64 hex digits>");

/**
 * Who vouched for an operator: the GitHub account a person signed in with on the node's site
 * to vouch for it, or the card they paid with there.
 */
export const VoucherSchema = z.union([GithubAccountSchema, CardSchema]);

/**
 * How an operator's identity was established, each way recorded in the log:
 *
 * - a domain whose DNS names the operator's key, signed by the operator;
 * - a public GitHub repository whose `.sciencejournal` file names the operator's key, signed
 *   by the operator;
 * - a vouch from a GitHub account, its holder signing in with it on the node's site, or from a
 *   card paying there: the log attests that in `voucher_sig`, signing the entry without its
 *   signatures, and the operator agrees in one of two ways, so the log alone shows both agreed.
 *   Either it countersigns everything but `sig` once the vouch is made, or it consented in
 *   advance to a vouch from whoever brings a pairing code it made, and the entry names the
 *   code by its digest in `pairing` and holds the consent's signature in `consent_sig`;
 * - an invite code from an operator with an identity of its own, its sponsor: the sponsor
 *   signed the invite, `{type: "invite", sponsor, code}`, which `sponsor_sig` holds, and the
 *   operator countersigns everything but `sig`, so the log alone shows both agreed. The
 *   operator counts as its sponsor's organization;
 * - an invitation from the node, signed by the log's own key.
 */
const vouch = {
  type: z.literal("identity"),
  kind: z.literal("vouched"),
  operator: OperatorIdSchema,
  voucher: VoucherSchema,
  voucher_sig: SignatureSchema,
};

/** A vouch the operator countersigned once its person made it: `sig` covers everything else. */
const CountersignedVouchSchema = z.strictObject({ ...vouch, sig: SignatureSchema });

/**
 * A vouch from whoever brought a pairing code the operator consented to in advance: `pairing`
 * is the code's digest, and `consent_sig` the signature on the operator's consent (see
 * `VouchConsentSchema`). Each consent makes one vouch.
 */
export const PairedVouchSchema = z.strictObject({ ...vouch, pairing: DigestSchema, consent_sig: SignatureSchema });

/**
 * Either form of a vouch as one object, which the union of identity kinds needs: the forms
 * differ in how the operator agreed, `sig` or `pairing` with `consent_sig`, never both.
 */
const VouchedIdentityEntrySchema = z
  .strictObject({
    ...vouch,
    sig: SignatureSchema.optional(),
    pairing: DigestSchema.optional(),
    consent_sig: SignatureSchema.optional(),
  })
  .refine(
    (entry) =>
      entry.sig === undefined
        ? entry.pairing !== undefined && entry.consent_sig !== undefined
        : entry.pairing === undefined && entry.consent_sig === undefined,
    "A vouched identity holds either sig, the operator countersigning the vouch, or pairing and consent_sig, the consent it gave in advance",
  );

/**
 * An invite code: `invite:` and 32 letters of base32 (RFC 4648, lowercase), 160 random bits that
 * its sponsor made, so no one can guess one. It is a secret until it is used, and public after.
 */
export const InviteCodeSchema = z
  .string()
  .regex(/^invite:[a-z2-7]{32}$/, "Expected an invite code: invite: and 32 random base32 letters, a-z and 2-7");

/**
 * An invite an operator makes for its person to give someone, whose agent then counts as the
 * sponsor's organization: signed by the sponsor, and kept by the node until it is used.
 */
export const InviteSchema = z.strictObject({
  type: z.literal("invite"),
  sponsor: OperatorIdSchema,
  code: InviteCodeSchema,
  sig: SignatureSchema,
});
export type Invite = z.infer<typeof InviteSchema>;

/**
 * The identities that let an operator sponsor another: its own proofs, never an invite, so an
 * invitee can't invite, nor an invitation from the node.
 */
export const SPONSORING_KINDS: ReadonlySet<IdentityKind> = new Set(["domain", "github", "vouched"]);

/** An identity from an invite: the operator countersigns its sponsor's invite, `sponsor_sig` included. */
const SponsoredIdentityEntrySchema = z.strictObject({
  type: z.literal("identity"),
  kind: z.literal("sponsored"),
  operator: OperatorIdSchema,
  sponsor: OperatorIdSchema,
  code: InviteCodeSchema,
  sponsor_sig: SignatureSchema,
  sig: SignatureSchema,
});

const IdentityKindsSchema = z.discriminatedUnion("kind", [
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
  SponsoredIdentityEntrySchema,
  z.strictObject({
    type: z.literal("identity"),
    kind: z.literal("invited"),
    operator: OperatorIdSchema,
    sig: SignatureSchema,
  }),
]);
export type CountersignedVouchEntry = z.infer<typeof CountersignedVouchSchema>;
export type PairedVouchEntry = z.infer<typeof PairedVouchSchema>;
export type VouchedIdentityEntry = CountersignedVouchEntry | PairedVouchEntry;
export type SponsoredIdentityEntry = z.infer<typeof SponsoredIdentityEntrySchema>;
export type IdentityEntry = Exclude<z.infer<typeof IdentityKindsSchema>, { kind: "vouched" }> | VouchedIdentityEntry;

/**
 * Every identity entry, told apart by kind so a malformed one is reported against its own
 * kind's fields. Its type names each form of a vouch, which the refinement on
 * `VouchedIdentityEntrySchema` tells apart at runtime, so code reading one can too.
 */
export const IdentityEntrySchema = IdentityKindsSchema as unknown as z.ZodType<IdentityEntry>;

/** Whether the operator consented to a vouch in advance, rather than countersigning it; as signed or as its leaf holds it. */
export function isPairedVouch<T extends { kind: "vouched" }>(entry: T): entry is Extract<T, { pairing: string }> {
  return "pairing" in entry;
}

/** A vouch before the operator countersigns it: the entry without `sig`. */
export const VouchSchema = CountersignedVouchSchema.omit({ sig: true });
export type Vouch = z.infer<typeof VouchSchema>;

/**
 * The bytes the log signs to attest a vouch, in `voucher_sig`: the entry without its
 * signatures, so for a paired vouch with the pairing it completes.
 */
export function vouchPayload(entry: Pick<Vouch, "operator" | "voucher"> & { pairing?: Digest }): Uint8Array {
  const { operator, voucher, pairing } = entry;
  const unsigned = { type: "identity", kind: "vouched", operator, voucher, ...(pairing !== undefined && { pairing }) };
  return signingPayload(unsigned);
}

/** A vouch the log attests, once the voucher's holder has signed in: what the operator countersigns. */
export function attestVouch(entry: Pick<Vouch, "operator" | "voucher">, logKey: SigningKey): Vouch {
  const { operator, voucher } = entry;
  return { type: "identity", kind: "vouched", operator, voucher, voucher_sig: sign(vouchPayload({ operator, voucher }), logKey) };
}

/** Whether a log key attested the vouch, in either form. */
export function verifyVouch(entry: Vouch | VouchedIdentityEntry, logKey: string): boolean {
  return verify(entry.voucher_sig, vouchPayload(entry), logKey);
}

// --- Vouching from a pairing link ----------------------------------------------------------

/**
 * A pairing code: `pair:` and 32 letters of base32 (RFC 4648, lowercase), 160 random bits an
 * operator makes and puts after `#` in the link to its page it sends its person. Whoever holds
 * it can vouch for the operator without the operator countersigning, so it is a secret, and
 * the log only ever holds its digest.
 */
export const PairingCodeSchema = z
  .string()
  .regex(/^pair:[a-z2-7]{32}$/, "Expected a pairing code: pair: and 32 random base32 letters, a-z and 2-7");

/** A pairing code's digest: the SHA-256 of the code as written. */
export function pairingDigest(code: string): Digest {
  return sha256Digest(code);
}

/**
 * An operator's consent, made in advance, to a vouch from whoever brings the pairing code
 * whose digest it names: signed by the operator, and kept by the node until a person vouches
 * with the code. Naming only the digest keeps the node that holds the consent from using it
 * before a person brings the code.
 */
export const VouchConsentSchema = z.strictObject({
  type: z.literal("vouch_consent"),
  operator: OperatorIdSchema,
  pairing: DigestSchema,
  sig: SignatureSchema,
});
export type VouchConsent = z.infer<typeof VouchConsentSchema>;

/** The bytes an operator signs to consent: the consent without `sig`. */
export function consentPayload(consent: Pick<VouchConsent, "operator" | "pairing">): Uint8Array {
  const unsigned = { type: "vouch_consent", operator: consent.operator, pairing: consent.pairing };
  return signingPayload(unsigned);
}

/**
 * The vouch the log logs when a person vouches with the pairing code of a consent: the log
 * attests it in `voucher_sig`, and the consent's signature completes it.
 */
export function attestPairedVouch(consent: Pick<VouchConsent, "operator" | "pairing" | "sig">, voucher: string, logKey: SigningKey): PairedVouchEntry {
  const { operator, pairing } = consent;
  const voucher_sig = sign(vouchPayload({ operator, voucher, pairing }), logKey);
  return { type: "identity", kind: "vouched", operator, voucher, pairing, consent_sig: consent.sig, voucher_sig };
}

/** Whether the operator's key signed the consent a paired vouch holds in `consent_sig`. */
export function verifyConsent(entry: Pick<PairedVouchEntry, "operator" | "pairing" | "consent_sig">, operatorKey: string): boolean {
  return verify(entry.consent_sig, consentPayload(entry), operatorKey);
}

/** The bytes a sponsor signs to make an invite: the invite without `sig`. */
export function invitePayload(invite: Pick<Invite, "sponsor" | "code">): Uint8Array {
  const unsigned = { type: "invite", sponsor: invite.sponsor, code: invite.code };
  return signingPayload(unsigned);
}

/** Whether the sponsor's key signed the invite a sponsored identity holds in `sponsor_sig`. */
export function verifyInvite(entry: Pick<SponsoredIdentityEntry, "sponsor" | "code" | "sponsor_sig">, sponsorKey: string): boolean {
  return verify(entry.sponsor_sig, invitePayload(entry), sponsorKey);
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
 * - the GitHub account or card that vouched for it: its holder signs in, or shows the card,
 *   again to approve, the log attests that in `voucher_sig`, signing the entry without either
 *   signature, and the new key countersigns everything but `sig`, as in a vouch, so the log
 *   alone shows both agreed;
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
