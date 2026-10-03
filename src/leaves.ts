import { utf8ToBytes } from "@noble/hashes/utils.js";
import { z } from "zod";
import { canonicalJson } from "./canonical";
import { ClaimIdSchema } from "./claims";
import {
  AttestationEntrySchema,
  BundleEntrySchema,
  KeyEntrySchema,
  KeyRotationEntrySchema,
  OperatorIdSchema,
  detachSignatures,
  SIGNATURE_FIELDS,
  SignatureSchema,
  type Detached,
} from "./entries";
import { ChallengeEntrySchema, ChallengeReviewEntrySchema } from "./challenges";
import { CitationCheckEntrySchema } from "./citations";
import { IdentityEntrySchema, KeyRecoveryEntrySchema } from "./identity";
import { ObservationEntrySchema, ObserverIdSchema, ObserverKeyEntrySchema, TaskEntrySchema } from "./fieldwork";
import { DigestSchema, sha256Hex } from "./hash";
import { IdeaEntrySchema } from "./ideas";
import {
  CanaryEntrySchema,
  HazardFlagEntrySchema,
  HazardReviewEntrySchema,
  SealedEntrySchema,
  SealRevealSchema,
  WithdrawalEntrySchema,
} from "./rounds";

const timestamp = z.iso.datetime();

/**
 * A log leaf as the node assembles it: the signed entry, plus what the log attests about it.
 * The timestamp settles priority. Entries an operator's agent signs name the operator;
 * entries a person signs name the observer, whether they observe, suggest ideas, or both. For
 * bundles, the claim IDs and fields are derived from the bundle's contents, so anyone holding
 * the bundle can check them; for identities, the log adds the organization the identity
 * counts as. Entries the node signs itself (commitments, canaries, withdrawals) name no one.
 * An entry that was sealed first carries `sealed`: the commitment it opens and the salt that
 * opens it. The log holds the leaf with its entry's signatures detached (see `LogLeafSchema`).
 */
export const SignedLeafSchema = z.union([
  z.strictObject({ timestamp, operator: OperatorIdSchema, entry: KeyEntrySchema }),
  z.strictObject({ timestamp, operator: OperatorIdSchema, entry: KeyRotationEntrySchema }),
  z.strictObject({ timestamp, operator: OperatorIdSchema, entry: KeyRecoveryEntrySchema }),
  z.strictObject({
    timestamp,
    operator: OperatorIdSchema,
    entry: BundleEntrySchema,
    claims: z.array(ClaimIdSchema),
    fields: z.array(z.string()),
    /** The bundle this one corrects, from its manifest. */
    replaces: DigestSchema.optional(),
    sealed: SealRevealSchema.optional(),
  }),
  z.strictObject({
    timestamp,
    operator: OperatorIdSchema,
    entry: AttestationEntrySchema,
    sealed: SealRevealSchema.optional(),
  }),
  z.strictObject({
    timestamp,
    operator: OperatorIdSchema,
    entry: IdentityEntrySchema,
    /**
     * The organization the identity counts as: the registrable domain, the GitHub account
     * (github:<login>), the vouching volunteer, or, for an invitation, the operator.
     */
    organization: z.string(),
  }),
  z.strictObject({ timestamp, operator: OperatorIdSchema, entry: TaskEntrySchema }),
  z.strictObject({ timestamp, observer: ObserverIdSchema, entry: ObserverKeyEntrySchema }),
  z.strictObject({ timestamp, observer: ObserverIdSchema, entry: ObservationEntrySchema }),
  z.strictObject({ timestamp, observer: ObserverIdSchema, entry: IdeaEntrySchema }),
  z.strictObject({ timestamp, entry: SealedEntrySchema }),
  z.strictObject({
    timestamp,
    entry: CanaryEntrySchema,
    /** The canary's claim IDs, in claims.json order. */
    claims: z.array(ClaimIdSchema),
    sealed: SealRevealSchema,
  }),
  z.strictObject({ timestamp, operator: OperatorIdSchema, entry: HazardReviewEntrySchema, sealed: SealRevealSchema }),
  z.strictObject({ timestamp, operator: OperatorIdSchema, entry: HazardFlagEntrySchema, sealed: SealRevealSchema }),
  z.strictObject({ timestamp, operator: OperatorIdSchema, entry: ChallengeEntrySchema }),
  z.strictObject({ timestamp, operator: OperatorIdSchema, entry: CitationCheckEntrySchema }),
  z.strictObject({ timestamp, operator: OperatorIdSchema, entry: ChallengeReviewEntrySchema, sealed: SealRevealSchema }),
  z.strictObject({ timestamp, entry: WithdrawalEntrySchema }),
]);
export type SignedLeaf = z.infer<typeof SignedLeafSchema>;

/**
 * A log leaf as the log holds it: the signed leaf with each signature in its entry replaced
 * by the signature's digest. The signatures themselves are kept beside the log.
 */
export const LogLeafSchema = z.union(
  SignedLeafSchema.options.map((option) =>
    option.extend({ entry: detachedSchema(option.shape.entry) }),
  ) as unknown as readonly [z.ZodType, ...z.ZodType[]],
);
type DetachedLeaf<L> = L extends { entry: infer E } ? Omit<L, "entry"> & { entry: Detached<E> } : never;
export type LogLeaf = DetachedLeaf<SignedLeaf>;

/** The leaf the log holds for a signed leaf: its entry's signatures replaced by their digests. */
export function detachLeaf(leaf: SignedLeaf): LogLeaf {
  return { ...leaf, entry: detachSignatures(leaf.entry) } as LogLeaf;
}

/** A signed entry's schema with each signature field holding a digest instead. */
function detachedSchema(schema: z.ZodType): z.ZodType {
  if (schema instanceof z.ZodDiscriminatedUnion) {
    const options = (schema.options as z.ZodType[]).map(detachedSchema);
    return z.discriminatedUnion(schema.def.discriminator, options as [z.ZodObject, ...z.ZodObject[]]);
  }
  const object = schema as z.ZodObject;
  const digests = SIGNATURE_FIELDS.filter((field) => field in object.shape).map((field) => [field, DigestSchema]);
  // safeExtend keeps an entry's refinements, which extend would refuse.
  return object.safeExtend(Object.fromEntries(digests));
}

/** A leaf's bytes in the Merkle tree. */
export function leafBytes(leaf: LogLeaf): Uint8Array {
  return utf8ToBytes(canonicalJson(leaf));
}

/** A log's ID: `log:` and the hex SHA-256 of its public key as written. A different key is a different log. */
export function logId(publicKey: string): string {
  return `log:${sha256Hex(publicKey)}`;
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
