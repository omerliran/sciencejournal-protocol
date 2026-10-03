import { utf8ToBytes } from "@noble/hashes/utils.js";
import { z } from "zod";
import { canonicalJson } from "./canonical";
import { ClaimIdSchema } from "./claims";
import { DigestSchema, type Digest } from "./hash";
import { ATTESTATION_JOBS } from "./vocabulary";
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
const Text = (max: number) => z.string().max(max).regex(/\S/, "Must not be blank");

/** An operator's request to publish: its key, name, and the model families it runs. */
export const KeyEntrySchema = z.strictObject({
  type: z.literal("key"),
  key: PublicKeySchema,
  name: Text(100),
  model_families: z.array(Text(60)).min(1).max(10),
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
 * files that back the verdicts (code, outputs, a report), stored next to the log.
 */
export const AttestationEntrySchema = z.strictObject({
  type: z.literal("attestation"),
  job: z.enum(Object.keys(ATTESTATION_JOBS) as [keyof typeof ATTESTATION_JOBS]),
  verifier: OperatorIdSchema,
  bundle: DigestSchema,
  claims: z
    .record(
      z.string().regex(/^claim:[0-9a-f]{64}$/, "Expected a global claim ID (claim:<sha256 hex>)"),
      z.enum(ATTESTATION_JOBS.reproduction),
    )
    .refine((claims) => Object.keys(claims).length > 0, "List at least one claim"),
  evidence: DigestSchema,
  model_family: Text(60),
  harness: Text(200),
  sig: SignatureSchema,
});
export type AttestationEntry = z.infer<typeof AttestationEntrySchema>;

/**
 * How an operator's identity was established. A domain identity is signed by the operator
 * and checked by the node over DNS; an invitation is signed by the log's own key.
 */
export const IdentityEntrySchema = z.discriminatedUnion("kind", [
  z.strictObject({
    type: z.literal("identity"),
    kind: z.literal("domain"),
    operator: OperatorIdSchema,
    domain: z
      .string()
      .max(253)
      .regex(/^(?=.*\.)[a-z0-9-]+(\.[a-z0-9-]+)+$/, "Expected a lowercase domain name, such as example.org"),
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

// --- What the log adds ---------------------------------------------------------------

/**
 * A log leaf: the signed entry, plus what the log attests about it. The timestamp settles
 * priority; for bundles, the claim IDs and fields are derived from the bundle's contents, so
 * anyone holding the bundle can check them.
 */
export const LogLeafSchema = z.union([
  z.strictObject({
    timestamp: z.iso.datetime(),
    operator: OperatorIdSchema,
    entry: KeyEntrySchema,
  }),
  z.strictObject({
    timestamp: z.iso.datetime(),
    operator: OperatorIdSchema,
    entry: BundleEntrySchema,
    claims: z.array(ClaimIdSchema),
    fields: z.array(z.string()),
    /** The bundle this one corrects, from its manifest. */
    replaces: DigestSchema.optional(),
  }),
  z.strictObject({
    timestamp: z.iso.datetime(),
    operator: OperatorIdSchema,
    entry: AttestationEntrySchema,
  }),
  z.strictObject({
    timestamp: z.iso.datetime(),
    operator: OperatorIdSchema,
    entry: IdentityEntrySchema,
    /** The organization the identity counts as: the registrable domain, or the operator. */
    organization: z.string(),
  }),
]);
export type LogLeaf = z.infer<typeof LogLeafSchema>;

/** A leaf's bytes in the Merkle tree. */
export function leafBytes(leaf: LogLeaf): Uint8Array {
  return utf8ToBytes(canonicalJson(leaf));
}

/** The log's signed commitment to its first `size` entries. */
export const TreeHeadSchema = z.strictObject({
  type: z.literal("tree_head"),
  log: z.string(),
  size: z.number().int().nonnegative(),
  root: z.string().regex(/^[0-9a-f]{64}$/),
  timestamp: z.iso.datetime(),
  sig: SignatureSchema,
});
export type TreeHead = z.infer<typeof TreeHeadSchema>;
