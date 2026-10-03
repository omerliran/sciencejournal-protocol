import { z } from "zod";
import { ClaimIdSchema, isClaimId, LocalClaimIdSchema, type Claim } from "./claims";
import { PreregistrationIdSchema } from "./preregistration";
import { DEVIATION_KINDS, LIMITS } from "./vocabulary";

// deviations.json: how the work departed from what it follows. A replication follows the claim
// it replicates, and pre-registered work follows its plan. Each entry names what it departed
// from, says whether the work did something other than what was stated (changed) or something
// that was never stated (unstated), and says what. When a replication doesn't match, these
// tell a real difference in the world from a detail the original left out, and an unstated one
// shows the original's publisher what its Methods should have said. An empty list says the work
// followed exactly. Validated and never transformed, and not a verification input, like
// materials.json.

export const DeviationSchema = z.strictObject({
  /** What the work departed from: a claim one of its replication claims depends on, or the plan its references cite. */
  from: z.union([ClaimIdSchema, PreregistrationIdSchema]),
  kind: z.enum(DEVIATION_KINDS),
  /** What was done, and for a change, what was stated instead. */
  detail: z.string().min(1).max(2000),
  /** The bundle's claims it bears on, by local ID. Absent: every claim that follows what `from` names. */
  claims: z.array(LocalClaimIdSchema).min(1).max(LIMITS.maxClaimsPerBundle).optional(),
});
export type Deviation = z.infer<typeof DeviationSchema>;

export const DeviationsFileSchema = z.array(DeviationSchema).max(LIMITS.maxDeviations);

/**
 * What a bundle's work follows, so deviations.json can depart from it: the claims on the
 * ledger its replication claims depend on, and the pre-registrations its references cite.
 */
export function followed(claims: readonly Pick<Claim, "type" | "depends_on">[], references: readonly { id: string }[]): Set<string> {
  return new Set([
    ...claims.filter((claim) => claim.type === "replication").flatMap((claim) => claim.depends_on.filter(isClaimId)),
    ...references.map((reference) => reference.id).filter((id) => PreregistrationIdSchema.safeParse(id).success),
  ]);
}

/** deviations.json as JSON Schema. Whether `from` and `claims` name what the bundle has needs its claims and references too. */
export function deviationsFileJsonSchema() {
  return z.toJSONSchema(DeviationsFileSchema, { io: "input" });
}
