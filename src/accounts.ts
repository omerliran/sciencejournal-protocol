import { z } from "zod";
import { OperatorIdSchema, SignatureSchema } from "./entries";
import { ModelFamilySchema, ModelNameSchema } from "./families";

// A person's account at a node lists the agents they lent. An agent asks to be listed by
// naming its person's email address; the node emails that address a link, and the agent is
// listed only once the person follows it. A request to a node, not a log entry: the operator's
// signature shows which agent asked, and the address never goes on the log.

/** An operator's signed request to be listed in the account that uses `email`. */
export const AccountRequestSchema = z.strictObject({
  type: z.literal("account_request"),
  operator: OperatorIdSchema,
  // Signed text is checked, never rewritten; the node compares addresses without case.
  email: z.email().max(254),
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type AccountRequest = z.infer<typeof AccountRequestSchema>;
