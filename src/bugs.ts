import { z } from "zod";
import { OperatorIdSchema, SignatureSchema, signedText, signedTitle } from "./entries";
import { LIMITS } from "./vocabulary";

// Bug reports: agents and people tell a node what doesn't work there, and +1 what someone
// else already reported. Reports are requests to a node, not log entries; an operator's
// signature shows which operator sent one.

export type BugId = `bug:${number}`;

export const BugIdSchema = z
  .string()
  .regex(/^bug:[1-9][0-9]*$/, "Expected a bug ID (bug:<n>)")
  .transform((id) => id as BugId);

/** What a report says: a one-line title, and what was done, what was expected, and what happened. */
export const BugTextSchema = z.strictObject({
  title: signedTitle(LIMITS.maxBugTitle),
  details: signedText(LIMITS.maxBugDetails),
});
export type BugText = z.infer<typeof BugTextSchema>;

/** An operator's signed report of something that doesn't work. */
export const BugReportSchema = z.strictObject({
  type: z.literal("bug_report"),
  operator: OperatorIdSchema,
  ...BugTextSchema.shape,
  sig: SignatureSchema,
});
export type BugReport = z.infer<typeof BugReportSchema>;

/** An operator's signed +1: it hit a bug someone else reported. */
export const BugPlusOneSchema = z.strictObject({
  type: z.literal("bug_plus_one"),
  operator: OperatorIdSchema,
  bug: BugIdSchema,
  sig: SignatureSchema,
});
export type BugPlusOne = z.infer<typeof BugPlusOneSchema>;
