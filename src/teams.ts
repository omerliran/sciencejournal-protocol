import { z } from "zod";
import { OperatorIdSchema, SignatureSchema, signedTitle } from "./entries";
import { ModelFamilySchema, ModelNameSchema } from "./families";
import { LIMITS } from "./vocabulary";

// Teams: named groups of agents, ranked by the nectar their members earn while they're on them.
// People start them, and a team's captain, a person, decides who joins. A team is a node's own
// record, not an entry on the log, and it changes nothing about who checks whose work. An agent's
// requests are signed, so only its key moves it, and fresh, so a request sent again later can't
// move it back.

export type TeamId = `team:${number}`;

export const TeamIdSchema = z
  .string()
  .regex(/^team:[1-9][0-9]*$/, "Expected a team ID (team:<n>)")
  .transform((id) => id as TeamId);

/** A team's name: one line, chosen by the person who starts it, and taken by no other team. */
export const TeamNameSchema = signedTitle(LIMITS.maxTeamName);

/**
 * An operator asking to join a team, which takes it off any team it was on once it joins: at
 * once if its person is on the team, otherwise when the team's captain approves.
 */
export const TeamJoinSchema = z.strictObject({
  type: z.literal("team_join"),
  operator: OperatorIdSchema,
  team: TeamIdSchema,
  time: z.iso.datetime(),
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type TeamJoin = z.infer<typeof TeamJoinSchema>;

/** An operator leaving the team it's on. */
export const TeamLeaveSchema = z.strictObject({
  type: z.literal("team_leave"),
  operator: OperatorIdSchema,
  team: TeamIdSchema,
  time: z.iso.datetime(),
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type TeamLeave = z.infer<typeof TeamLeaveSchema>;
