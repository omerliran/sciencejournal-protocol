import { z } from "zod";
import { canonicalDigest, hashCanonical, type Digest } from "./hash";
import { CLAIM_TYPES, LIMITS } from "./vocabulary";

export type ClaimId = `claim:${string}`;

// A plain pattern rather than a custom check, so it carries over into the published JSON
// Schema.
export const ClaimIdSchema = z
  .string()
  .regex(/^claim:[0-9a-f]{64}$/, "Expected a global claim ID (claim:<sha256 hex>)")
  .transform((id) => id as ClaimId);

export function isClaimId(value: unknown): value is ClaimId {
  return ClaimIdSchema.safeParse(value).success;
}

// A bundle-scoped label such as "C3". Colons are excluded so a local ID can never be
// mistaken for a global claim ID.
export const LocalClaimIdSchema = z.string().regex(/^[A-Za-z][A-Za-z0-9_-]*$/);

// Strict objects: every field a claim carries is part of its ID, so unknown fields are
// rejected rather than silently dropped.
export const EvidenceSchema = z.strictObject({
  result: z.string().min(1),
  produced_by: z.string().min(1),
  tolerance: z.number().nonnegative().optional(),
});

export const ClaimSchema = z
  .strictObject({
    local_id: LocalClaimIdSchema,
    type: z.enum(CLAIM_TYPES),
    core: z.boolean(),
    statement: z.string().min(1),
    evidence: z.array(EvidenceSchema),
    depends_on: z.array(z.union([ClaimIdSchema, LocalClaimIdSchema])),
    falsified_if: z.string().min(1).optional(),
    confidence: z.number().min(0).max(1),
  })
  .refine((claim) => claim.type !== "empirical" || claim.evidence.length > 0, {
    message: "Empirical claims need at least one evidence item, or they can never be reproduced",
    path: ["evidence"],
  });
export type Claim = z.infer<typeof ClaimSchema>;

/**
 * claims.json as JSON Schema. It describes the shape; the dependency graph and the
 * empirical-evidence rule can only be checked by ClaimsFileSchema itself.
 */
export function claimsFileJsonSchema() {
  return z.toJSONSchema(ClaimsFileSchema, { io: "input" });
}

/** The contents of claims.json. */
export const ClaimsFileSchema = z
  .array(ClaimSchema)
  .min(1)
  .max(LIMITS.maxClaimsPerBundle)
  .superRefine((claims, ctx) => {
    try {
      orderClaims(claims);
    } catch (error) {
      if (!(error instanceof ClaimGraphError)) throw error;
      ctx.addIssue({ code: "custom", message: error.message });
    }
  });

export class ClaimGraphError extends Error {
  override name = "ClaimGraphError";
}

/**
 * Returns the claims with every claim after its local dependencies. Throws ClaimGraphError
 * on duplicate local IDs, unknown local dependencies, or cycles.
 */
export function orderClaims(claims: readonly Claim[]): Claim[] {
  const byLocalId = new Map<string, Claim>();
  for (const claim of claims) {
    if (byLocalId.has(claim.local_id)) {
      throw new ClaimGraphError(`Duplicate local_id "${claim.local_id}"`);
    }
    byLocalId.set(claim.local_id, claim);
  }

  const ordered: Claim[] = [];
  const done = new Set<string>();
  const visiting = new Set<string>();

  const visit = (claim: Claim) => {
    if (done.has(claim.local_id)) return;
    if (visiting.has(claim.local_id)) {
      throw new ClaimGraphError(`Dependency cycle through "${claim.local_id}"`);
    }
    visiting.add(claim.local_id);
    for (const dependency of claim.depends_on) {
      if (isClaimId(dependency)) continue;
      const local = byLocalId.get(dependency);
      if (!local) {
        throw new ClaimGraphError(
          `"${claim.local_id}" depends on unknown local claim "${dependency}"`,
        );
      }
      visit(local);
    }
    visiting.delete(claim.local_id);
    done.add(claim.local_id);
    ordered.push(claim);
  };

  for (const claim of claims) visit(claim);
  return ordered;
}

/**
 * Returns each claim's global ID, keyed by local_id. `verificationInputs` is the bundle's
 * digest from digestBundle, which claims with evidence bind to.
 *
 * The ID hashes the whole claim except its local_id, with local dependencies resolved to
 * global IDs. A claim with evidence also binds the verification inputs, so changing the
 * code, data, or declared results gives it a new ID and it has to be verified again. See
 * "Claim IDs" in https://sciencejournal.ai/llms.txt.
 */
export function assignClaimIds(
  claims: readonly Claim[],
  verificationInputs: Digest,
): Map<string, ClaimId> {
  return computeClaimIds(claims, verificationInputs);
}

/**
 * Claim IDs for a claims file whose bundle hasn't been hashed yet. Claims that bind the
 * verification inputs, directly through evidence or through a local dependency, get null.
 */
export function assignClaimIdsWithoutInputs(claims: readonly Claim[]): Map<string, ClaimId | null> {
  const bound = new Set<string>();
  for (const claim of orderClaims(claims)) {
    const dependsOnBound = claim.depends_on.some((dependency) => bound.has(dependency));
    if (claim.evidence.length > 0 || dependsOnBound) bound.add(claim.local_id);
  }
  const ids = computeClaimIds(
    claims.filter((claim) => !bound.has(claim.local_id)),
    undefined,
  );
  return new Map(claims.map((claim) => [claim.local_id, ids.get(claim.local_id) ?? null]));
}

function computeClaimIds(
  claims: readonly Claim[],
  verificationInputs: Digest | undefined,
): Map<string, ClaimId> {
  const ids = new Map<string, ClaimId>();
  for (const claim of orderClaims(claims)) {
    const dependsOn = claim.depends_on.map((dependency) =>
      isClaimId(dependency) ? dependency : ids.get(dependency)!,
    );
    const content: Partial<Claim> = { ...claim };
    delete content.local_id;
    if (claim.evidence.length > 0 && !verificationInputs) {
      throw new Error(`"${claim.local_id}" has evidence, so its ID needs the verification inputs`);
    }
    const id: ClaimId = `claim:${hashCanonical({
      ...content,
      depends_on: [...new Set(dependsOn)].sort(),
      ...(claim.evidence.length > 0 && { verification_inputs: verificationInputs }),
    })}`;
    ids.set(claim.local_id, id);
  }
  return ids;
}

/**
 * A lookup key for claims that assert the same thing, whatever their bundle or evidence.
 * It feeds duplicate matching; it is never an identity.
 */
export function assertionDigest(claim: Pick<Claim, "type" | "statement">): Digest {
  return canonicalDigest({ type: claim.type, statement: claim.statement });
}
