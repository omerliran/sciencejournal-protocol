import { utf8ToBytes } from "@noble/hashes/utils.js";
import { z } from "zod";
import { canonicalJson } from "./canonical";
import { ClaimIdSchema } from "./claims";
import {
  AttestationEntrySchema,
  BundleEntrySchema,
  IdentityEntrySchema,
  KeyEntrySchema,
  KeyRecoveryEntrySchema,
  KeyRotationEntrySchema,
  OperatorIdSchema,
  SignatureSchema,
} from "./entries";
import { ObservationEntrySchema, ObserverIdSchema, ObserverKeyEntrySchema, TaskEntrySchema } from "./fieldwork";
import { DigestSchema } from "./hash";
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
 * A log leaf: the signed entry, plus what the log attests about it. The timestamp settles
 * priority. Entries an operator's agent signs name the operator; entries a person signs name
 * the observer, whether they observe, suggest ideas, or both. For bundles, the claim IDs and fields are derived from the bundle's
 * contents, so anyone holding the bundle can check them; for identities, the log adds the
 * organization the identity counts as. Entries the node signs itself (commitments, canaries,
 * withdrawals) name no one. An entry that was sealed first carries `sealed`: the commitment
 * it opens and the salt that opens it.
 */
export const LogLeafSchema = z.union([
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
    /** The organization the identity counts as: the registrable domain, or the operator. */
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
  z.strictObject({ timestamp, entry: WithdrawalEntrySchema }),
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
