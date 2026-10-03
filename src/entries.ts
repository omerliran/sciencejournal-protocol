import { utf8ToBytes } from "@noble/hashes/utils.js";
import { z } from "zod";
import { canonicalJson } from "./canonical";
import { DigestSchema, type Digest } from "./hash";
import { ATTESTATION_JOBS, HAZARD_VERDICTS } from "./vocabulary";
import { sign, verify, type PublicKey, type Signature } from "./signing";

export const PublicKeySchema = z
  .string()
  .regex(/^ed25519:[0-9a-f]{64}$/, "Expected an Ed25519 public key (ed25519:<64 hex>)")
  .transform((key) => key as PublicKey);

export const SignatureSchema = z
  .string()
  .regex(/^ed25519:[0-9a-f]{128}$/, "Expected an Ed25519 signature (ed25519:<128 hex>)")
  .transform((signature) => signature as Signature);

export const OperatorIdSchema = z.string().regex(/^op:[1-9][0-9]*$/, "Expected an operator ID (op:<n>)");

/**
 * The bytes a signature covers: the object's canonical JSON without its `sig` field. Every
 * signed object has a `type`, so a signature made for one kind of object can't be replayed
 * as another.
 */
export function signingPayload(object: { type: string }): Uint8Array {
  const unsigned: Record<string, unknown> = { ...object };
  delete unsigned.sig;
  return utf8ToBytes(canonicalJson(unsigned));
}

export function signObject<T extends { type: string }>(
  object: T,
  secretKey: Uint8Array,
): T & { sig: Signature } {
  return { ...object, sig: sign(signingPayload(object), secretKey) };
}

export function verifyObject(object: { type: string; sig: string }, publicKey: string): boolean {
  return verify(object.sig, signingPayload(object), publicKey);
}

// --- Entries an operator signs -------------------------------------------------------

// Signed objects are validated, never rewritten: trimming or normalizing a field would change
// the bytes its signature covers.
export const boundedText = (max: number) => z.string().max(max).regex(/\S/, "Must not be blank");

/** An operator's request to publish: its key, name, and the model families it runs. */
export const KeyEntrySchema = z.strictObject({
  type: z.literal("key"),
  key: PublicKeySchema,
  name: boundedText(100),
  model_families: z.array(boundedText(60)).min(1).max(10),
  sig: SignatureSchema,
});
export type KeyEntry = z.infer<typeof KeyEntrySchema>;

/** What the bundle's `signature` file signs: the bundle hash, tagged with its type. */
export function bundleSigningObject(bundle: Digest) {
  return { type: "bundle" as const, bundle };
}

export const BundleEntrySchema = z.strictObject({
  type: z.literal("bundle"),
  bundle: DigestSchema,
  sig: SignatureSchema,
});
export type BundleEntry = z.infer<typeof BundleEntrySchema>;

/**
 * A verifier's signed verdicts on claims from one bundle. `evidence` is the digest of the
 * files that back the verdicts (code, outputs, a report), stored next to the log. `hazard` is
 * the verifier's hazard screen of the bundle; attestations from assigned jobs must give it.
 */
export const AttestationEntrySchema = z
  .strictObject({
    type: z.literal("attestation"),
    job: z.enum(Object.keys(ATTESTATION_JOBS) as [keyof typeof ATTESTATION_JOBS]),
    verifier: OperatorIdSchema,
    bundle: DigestSchema,
    claims: z
      .record(
        z.string().regex(/^claim:[0-9a-f]{64}$/, "Expected a global claim ID (claim:<sha256 hex>)"),
        z.enum(Object.values(ATTESTATION_JOBS).flat() as [string, ...string[]]),
      )
      .refine((claims) => Object.keys(claims).length > 0, "List at least one claim"),
    evidence: DigestSchema,
    model_family: boundedText(60),
    harness: boundedText(200),
    hazard: z.enum(HAZARD_VERDICTS).optional(),
    /**
     * The work took more than the bundle declared, so the verifier stopped. If two
     * organizations say so, the publisher pays again and they are paid for their time.
     */
    over_budget: z.literal(true).optional(),
    sig: SignatureSchema,
  })
  .superRefine((entry, ctx) => {
    // Each job has its own verdicts: a reproduction can't come back "matched".
    const allowed: readonly string[] = ATTESTATION_JOBS[entry.job];
    for (const [claim, verdict] of Object.entries(entry.claims)) {
      if (!allowed.includes(verdict)) {
        ctx.addIssue({ code: "custom", path: ["claims", claim], message: `A ${entry.job} verdict is one of ${allowed.join(", ")}` });
      }
    }
  });
export type AttestationEntry = z.infer<typeof AttestationEntrySchema>;

const DomainSchema = z
  .string()
  .max(253)
  .regex(/^(?=.*\.)[a-z0-9-]+(\.[a-z0-9-]+)+$/, "Expected a lowercase domain name, such as example.org");

/**
 * How an operator's identity was established. A domain identity is signed by the operator
 * and checked by the node over DNS; an invitation is signed by the log's own key.
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
    kind: z.literal("invited"),
    operator: OperatorIdSchema,
    sig: SignatureSchema,
  }),
]);
export type IdentityEntry = z.infer<typeof IdentityEntrySchema>;

// --- Changing keys ---------------------------------------------------------------------

/**
 * An operator moving to a new key while it still holds the old one. The new key signs the
 * entry without either signature, in `key_sig`, which proves the operator holds it; the
 * current key then signs everything but `sig`, `key_sig` included. The operator keeps its ID,
 * identity, credit, and record, and the old key can sign nothing after this entry.
 */
export const KeyRotationEntrySchema = z.strictObject({
  type: z.literal("key_rotation"),
  operator: OperatorIdSchema,
  key: PublicKeySchema,
  key_sig: SignatureSchema,
  sig: SignatureSchema,
});
export type KeyRotationEntry = z.infer<typeof KeyRotationEntrySchema>;

/** The bytes the new key signs in a rotation: the entry without `sig` or `key_sig`. */
export function keyRotationPayload(entry: Pick<KeyRotationEntry, "operator" | "key">): Uint8Array {
  const unsigned = { type: "key_rotation", operator: entry.operator, key: entry.key };
  return signingPayload(unsigned);
}

/** Signs a rotation from `currentSecret`'s key to `newSecret`'s, for `operator`. */
export function signKeyRotation(operator: string, newSecret: Uint8Array, currentSecret: Uint8Array, key: PublicKey) {
  const key_sig = sign(keyRotationPayload({ operator, key }), newSecret);
  return signObject({ type: "key_rotation" as const, operator, key, key_sig }, currentSecret);
}

/** Whether the new key countersigned the rotation and `currentKey` signed it. */
export function verifyKeyRotation(entry: KeyRotationEntry, currentKey: string): boolean {
  return verify(entry.key_sig, keyRotationPayload(entry), entry.key) && verifyObject(entry, currentKey);
}

/**
 * An operator taking its ID back with a new key after losing the old one, proven by whatever
 * gave it its identity: its domain, whose record now names the new key, which signs the entry;
 * or the log, for an invited operator. Nothing the old key signed from log index `since` on
 * counts.
 */
export const KeyRecoveryEntrySchema = z.discriminatedUnion("kind", [
  z.strictObject({
    type: z.literal("key_recovery"),
    kind: z.literal("domain"),
    operator: OperatorIdSchema,
    key: PublicKeySchema,
    domain: DomainSchema,
    since: z.number().int().nonnegative(),
    sig: SignatureSchema,
  }),
  z.strictObject({
    type: z.literal("key_recovery"),
    kind: z.literal("invited"),
    operator: OperatorIdSchema,
    key: PublicKeySchema,
    since: z.number().int().nonnegative(),
    sig: SignatureSchema,
  }),
]);
export type KeyRecoveryEntry = z.infer<typeof KeyRecoveryEntrySchema>;
