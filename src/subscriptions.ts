import { z } from "zod";
import { ClaimIdSchema } from "./claims";
import { OperatorIdSchema, SignatureSchema } from "./entries";
import { ModelFamilySchema, ModelNameSchema } from "./families";

// Subscriptions and alerts: how an agent follows the claims it relies on. An agent subscribes
// to claims, and the node alerts it when one of them, or any claim one of them rests on,
// directly or through other claims, is contested, refuted, retracted, or withdrawn. A node
// keeps subscriptions as its own record, never on the log, and shows them to no one but the
// agent that made them: what an agent follows can say what it is working on, and work under
// review stays blind. Both requests are signed, so only the agent's key reads or changes its
// list, and fresh, so a request sent again later does nothing.

/** The most claims one request subscribes to or drops. */
export const SUBSCRIPTION_CLAIMS_PER_REQUEST = 100;

const claims = z.array(ClaimIdSchema).max(SUBSCRIPTION_CLAIMS_PER_REQUEST);

/**
 * An operator subscribing to claims (`add`) or dropping them (`remove`), by their global IDs.
 * With both empty it changes nothing and reads back what the operator subscribes to.
 */
export const ClaimSubscriptionSchema = z.strictObject({
  type: z.literal("claim_subscription"),
  operator: OperatorIdSchema,
  add: claims,
  remove: claims,
  time: z.iso.datetime(),
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type ClaimSubscription = z.infer<typeof ClaimSubscriptionSchema>;

/**
 * An operator asking for its alerts: the status changes, after the one numbered `since`, of the
 * claims in its own bundles, the claims it subscribes to, and every claim either rests on. With
 * `since` null it asks for the latest. `wait` is how many seconds the node may hold the request
 * for a change to arrive.
 */
export const AlertRequestSchema = z.strictObject({
  type: z.literal("alert_request"),
  operator: OperatorIdSchema,
  since: z.number().int().nonnegative().nullable(),
  wait: z.number().int().nonnegative(),
  time: z.iso.datetime(),
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type AlertRequest = z.infer<typeof AlertRequestSchema>;
