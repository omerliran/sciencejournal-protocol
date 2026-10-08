import { utf8ToBytes } from "@noble/hashes/utils.js";
import { ModelFamilySchema, ModelNameSchema } from "./families";
import { z } from "zod";
import { canonicalJson } from "./canonical";
import { canonicalDigest, DigestSchema, sha256Hex, type Digest } from "./hash";
import { ATTESTATION_JOBS, HAZARD_VERDICTS, REVIEW_JOBS, SIGNATURE_ALGORITHM, SIGNIFICANCE_RATINGS } from "./vocabulary";
import {
  PUBLIC_KEY_BYTES,
  sign,
  SIGNATURE_BYTES,
  verify,
  type PublicKey,
  type Signature,
  type SigningKey,
} from "./signing";

const hexOf = (bytes: number) => new RegExp(`^${SIGNATURE_ALGORITHM}:[0-9a-f]{${2 * bytes}}$`);

export const PublicKeySchema = z
  .string()
  .regex(
    hexOf(PUBLIC_KEY_BYTES),
    `Expected a public key: ${SIGNATURE_ALGORITHM}: and ${PUBLIC_KEY_BYTES} bytes in lowercase hex`,
  )
  .transform((key) => key as PublicKey);

export const SignatureSchema = z
  .string()
  .regex(
    hexOf(SIGNATURE_BYTES),
    `Expected a signature: ${SIGNATURE_ALGORITHM}: and ${SIGNATURE_BYTES} bytes in lowercase hex`,
  )
  .transform((signature) => signature as Signature);

/**
 * An operator's ID: `op:` and the hex SHA-256 of the first key it registered, as written, the
 * way a log's ID comes from its key. No log assigns it, so every log, monitor, and reader
 * derives the same ID from the key entry, and an agent knows its own before registering
 * anywhere. Rotating or recovering the key keeps it.
 */
export const OperatorIdSchema = z
  .string()
  .regex(/^op:[0-9a-f]{64}$/, "Expected an operator ID: op: and the SHA-256 of its first key, in lowercase hex");

/** The ID of the operator whose first key is `firstKey`. */
export function operatorId(firstKey: string): string {
  return `op:${sha256Hex(firstKey)}`;
}

/**
 * Where a retraction or an addendum names the operator that wrote the bundle: `author`, or
 * `publisher`, the field's earlier name, which entries signed before the rename carry and
 * which means the same. An entry names it once, in one of them.
 */
export const AUTHOR_FIELDS = { author: OperatorIdSchema.optional(), publisher: OperatorIdSchema.optional() };

/** Refines a schema built with AUTHOR_FIELDS so the entry names its author exactly once. */
export function namesOneAuthor(entry: { author?: string; publisher?: string }, ctx: z.RefinementCtx) {
  if (entry.author === undefined && entry.publisher === undefined) {
    ctx.addIssue({ code: "custom", path: ["author"], message: "Name the bundle's author, your operator ID, as author" });
  } else if (entry.author !== undefined && entry.publisher !== undefined) {
    ctx.addIssue({ code: "custom", path: ["publisher"], message: "Say author alone; publisher is its earlier name" });
  }
}

/** The operator an entry built with AUTHOR_FIELDS names as the bundle's author, and the field it uses. */
export function namedAuthor(entry: { author?: string; publisher?: string }): { field: "author" | "publisher"; operator: string } {
  if (entry.author !== undefined) return { field: "author", operator: entry.author };
  if (entry.publisher !== undefined) return { field: "publisher", operator: entry.publisher };
  throw new Error("The entry names no author");
}

/**
 * An entry's digest as signed: the SHA-256 of its canonical JSON, signatures included. Every
 * log that holds an entry gives it the same digest, whatever its index there, so two logs are
 * compared entry by entry through it.
 */
export function entryDigest(entry: { type: string }): Digest {
  return canonicalDigest(entry);
}

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

export function signObject<T extends { type: string }>(object: T, key: SigningKey): T & { sig: Signature } {
  return { ...object, sig: sign(signingPayload(object), key) };
}

export function verifyObject(object: { type: string; sig: string }, publicKey: string): boolean {
  return verify(object.sig, signingPayload(object), publicKey);
}

// --- Signatures beside the log ---------------------------------------------------------

/**
 * The fields of a signed entry that hold signatures. A log leaf holds each as its digest,
 * and the node keeps the signatures beside the log: they are most of an entry's size, and
 * only someone checking who signed it needs them. The leaf hash still fixes each signature.
 */
export const SIGNATURE_FIELDS = ["sig", "key_sig", "voucher_sig", "sponsor_sig", "consent_sig"] as const;
type SignatureField = (typeof SIGNATURE_FIELDS)[number];

/** A signed entry as its log leaf holds it: each signature replaced by its digest. */
export type Detached<T> = T extends unknown
  ? { [K in keyof T]: K extends SignatureField ? Digest : T[K] }
  : never;

/** A signature's digest: the SHA-256 of its canonical JSON, which covers passkey signatures too. */
export function signatureDigest(signature: unknown): Digest {
  return canonicalDigest(signature);
}

export function detachSignatures<T extends object>(entry: T): Detached<T> {
  const detached: Record<string, unknown> = { ...(entry as Record<string, unknown>) };
  for (const field of SIGNATURE_FIELDS) {
    if (field in detached) detached[field] = signatureDigest(detached[field]);
  }
  return detached as Detached<T>;
}

/** Whether `signed` is the entry a leaf holds, signatures and all. */
export function matchesLeafEntry(signed: object, leafEntry: object): boolean {
  return canonicalJson(detachSignatures(signed)) === canonicalJson(leafEntry);
}

// --- Entries an operator signs -------------------------------------------------------

// Signed objects are validated, never rewritten: trimming or normalizing a field would change
// the bytes its signature covers.
export const boundedText = (max: number) => z.string().max(max).regex(/\S/, "Must not be blank");

/** Text a person or agent writes and signs: the writer trims it before signing, since the node can't. */
export const signedText = (max: number) =>
  boundedText(max).refine((text) => text === text.trim(), "Must not start or end with whitespace");

/** A signed title: one line of signed text. */
export const signedTitle = (max: number) =>
  signedText(max).refine((title) => !/[\n\r]/.test(title), "Must be one line");

/**
 * An operator registering: its key, its name, and the model registering it, by family and in its
 * own words. Which model holds a key can change at any time, so every later call names its own.
 */
export const KeyEntrySchema = z.strictObject({
  type: z.literal("key"),
  key: PublicKeySchema,
  name: boundedText(100),
  model_families: z.array(ModelFamilySchema).min(1).max(10),
  /** The model registering, in its own words (see families.ts); keys registered before it was asked name none. */
  model: ModelNameSchema.optional(),
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

const GlobalClaimIdSchema = z.string().regex(/^claim:[0-9a-f]{64}$/, "Expected a global claim ID (claim:<sha256 hex>)");

/** The most a copyright finding's `source` may say. */
export const COPYRIGHT_SOURCE_CHARS = 1000;

/**
 * Where a screener found a copy of someone else's work with nothing showing it may be shared
 * (the hazard rubric's third question): the bundle's files that hold it, and the work they copy,
 * in the screener's words. It goes with a "copyright" hazard answer and no other; the node shows
 * it to the person asked to confirm the rights.
 */
export const CopyrightFindingSchema = z.strictObject({
  paths: z.array(boundedText(500)).min(1).max(20),
  source: signedText(COPYRIGHT_SOURCE_CHARS),
});
export type CopyrightFinding = z.infer<typeof CopyrightFindingSchema>;

/** Checks that a copyright finding comes with a "copyright" answer, and only with one. */
export function requireFindingWithCopyright(answer: string | undefined, finding: CopyrightFinding | undefined, field: string, ctx: z.RefinementCtx) {
  if (answer === "copyright" && finding === undefined) {
    ctx.addIssue({ code: "custom", path: ["copyright"], message: `With "${field}": "copyright", name the files and the work they copy as "copyright": {"paths": [...], "source": "..."}` });
  }
  if (answer !== "copyright" && finding !== undefined) {
    ctx.addIssue({ code: "custom", path: ["copyright"], message: `Give "copyright" only with "${field}": "copyright"` });
  }
}

/**
 * A verifier's signed verdicts on claims from one bundle. `evidence` is the digest of the
 * files that back the verdicts (code, outputs, a report), stored next to the log. `hazard` is
 * the verifier's hazard screen of the bundle; attestations from assigned jobs must give it.
 * A review also rates each claim it judges for `significance`, and no other job does; a review
 * says `knew_author` when something in the work told the reviewer whose it was, or
 * `knew_publisher`, its earlier name, which reviews already on the ledger carry.
 */
export const AttestationEntrySchema = z
  .strictObject({
    type: z.literal("attestation"),
    job: z.enum(Object.keys(ATTESTATION_JOBS) as [keyof typeof ATTESTATION_JOBS]),
    verifier: OperatorIdSchema,
    bundle: DigestSchema,
    claims: z
      .record(GlobalClaimIdSchema, z.enum(Object.values(ATTESTATION_JOBS).flat() as [string, ...string[]]))
      .refine((claims) => Object.keys(claims).length > 0, "List at least one claim"),
    significance: z.record(GlobalClaimIdSchema, z.enum(SIGNIFICANCE_RATINGS)).optional(),
    evidence: DigestSchema,
    model_family: ModelFamilySchema,
    model: ModelNameSchema.optional(),
    harness: boundedText(200),
    hazard: z.enum(HAZARD_VERDICTS).optional(),
    /** With a "copyright" hazard answer, the files that copy someone else's work and the work they copy. */
    copyright: CopyrightFindingSchema.optional(),
    /**
     * The work took more than the bundle declared, so the verifier stopped. If two
     * organizations say so, the author pays again and they are paid for their time.
     */
    over_budget: z.literal(true).optional(),
    /**
     * Something in the work told the reviewer who wrote it, such as a byline, an address, or a
     * repository, so the review wasn't blind.
     */
    knew_author: z.literal(true).optional(),
    knew_publisher: z.literal(true).optional(),
    sig: SignatureSchema,
  })
  .superRefine((entry, ctx) => {
    requireFindingWithCopyright(entry.hazard, entry.copyright, "hazard", ctx);
    // Each job has its own verdicts: a reproduction can't come back "matched".
    const allowed: readonly string[] = ATTESTATION_JOBS[entry.job];
    for (const [claim, verdict] of Object.entries(entry.claims)) {
      if (!allowed.includes(verdict)) {
        ctx.addIssue({ code: "custom", path: ["claims", claim], message: `A ${entry.job} verdict is one of ${allowed.join(", ")}` });
      }
    }
    // A review rates exactly the claims it gives verdicts on; nothing else rates any.
    if (!(REVIEW_JOBS as readonly string[]).includes(entry.job)) {
      if (entry.significance !== undefined) {
        ctx.addIssue({ code: "custom", path: ["significance"], message: `Only a review rates significance, not a ${entry.job}` });
      }
      for (const knew of ["knew_author", "knew_publisher"] as const) {
        if (entry[knew] !== undefined) {
          ctx.addIssue({ code: "custom", path: [knew], message: `Only a review says whether it knew whose work it judged, not a ${entry.job}` });
        }
      }
      return;
    }
    if (entry.knew_author !== undefined && entry.knew_publisher !== undefined) {
      ctx.addIssue({ code: "custom", path: ["knew_publisher"], message: "Say knew_author alone; knew_publisher is its earlier name" });
    }
    if (entry.significance === undefined) {
      ctx.addIssue({ code: "custom", path: ["significance"], message: "A review rates the significance of each claim it gives a verdict on" });
      return;
    }
    for (const claim of Object.keys(entry.claims)) {
      if (!Object.hasOwn(entry.significance, claim)) {
        ctx.addIssue({ code: "custom", path: ["significance", claim], message: "Rate the significance of every claim the review gives a verdict on" });
      }
    }
    for (const claim of Object.keys(entry.significance)) {
      if (!Object.hasOwn(entry.claims, claim)) {
        ctx.addIssue({ code: "custom", path: ["significance", claim], message: "Rate only the claims the review gives a verdict on" });
      }
    }
  });
export type AttestationEntry = z.infer<typeof AttestationEntrySchema>;

export const DomainSchema = z
  .string()
  .max(253)
  .regex(/^(?=.*\.)[a-z0-9-]+(\.[a-z0-9-]+)+$/, "Expected a lowercase domain name, such as example.org");


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
export function signKeyRotation(operator: string, newSecret: SigningKey, currentSecret: SigningKey, key: PublicKey) {
  const key_sig = sign(keyRotationPayload({ operator, key }), newSecret);
  return signObject({ type: "key_rotation" as const, operator, key, key_sig }, currentSecret);
}

/** Whether the new key countersigned the rotation and `currentKey` signed it. */
export function verifyKeyRotation(entry: KeyRotationEntry, currentKey: string): boolean {
  return verify(entry.key_sig, keyRotationPayload(entry), entry.key) && verifyObject(entry, currentKey);
}
