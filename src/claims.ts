import { z } from "zod";
import { canonicalDigest, hashCanonical, type Digest } from "./hash";
import type { BundleInputs } from "./results";
import { CLAIM_TYPES, LIMITS, PROOF_CHECKERS } from "./vocabulary";

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

// A declared result, named by its file under results/ and its key: R3.loss_delta is the
// value at loss_delta in results/R3.json. Plain patterns carry over into the JSON Schema.
const ResultNameSchema = z
  .string()
  .regex(/^[^./]+(\.[^.]+)+$/, "Expected a result name such as R3.loss_delta");
// [\s\S] rather than ".", which misses U+2028 and U+2029, characters a bundle path may hold.
const pathUnder = (directory: string) =>
  z.string().regex(new RegExp(`^${directory}/[\\s\\S]`), `Expected a path under ${directory}/`);
const ToleranceSchema = z.number().nonnegative().optional();

// Each kind of evidence says how it can be checked. Strict objects: every field a claim
// carries is part of its ID, so unknown fields are rejected rather than silently dropped,
// and no item can be read as two kinds at once.

/** A result the code writes, which verifiers check by re-running it. */
export const ComputationEvidenceSchema = z.strictObject({
  result: ResultNameSchema,
  produced_by: pathUnder("code"),
  tolerance: ToleranceSchema,
});
/** A result read from a raw record, which a new measurement checks by replicating it. */
export const MeasurementEvidenceSchema = z.strictObject({
  result: ResultNameSchema,
  measured: pathUnder("data"),
  tolerance: ToleranceSchema,
});
/** A theorem in a proof file, which a proof checker checks. */
export const ProofEvidenceSchema = z.strictObject({
  proof: pathUnder("proofs"),
  theorem: z.string().min(1).max(500),
  checker: z.enum(PROOF_CHECKERS),
});
export const EvidenceSchema = z.union([ComputationEvidenceSchema, MeasurementEvidenceSchema, ProofEvidenceSchema]);
export type Evidence = z.infer<typeof EvidenceSchema>;
export type Computation = z.infer<typeof ComputationEvidenceSchema>;

export function isComputation(evidence: Evidence): evidence is Computation {
  return "produced_by" in evidence;
}

/** Whether a claim's evidence includes a computation, which reproduction jobs re-run. */
export function needsReproduction(claim: Pick<Claim, "evidence">): boolean {
  return claim.evidence.some(isComputation);
}

/** The results a claim's evidence names, each once, in the order they first appear. */
export function resultsNamed(claim: Pick<Claim, "evidence">): string[] {
  return [...new Set(claim.evidence.flatMap((item) => ("result" in item ? [item.result] : [])))];
}

/** The bundle paths a claim's evidence names, with where each sits in the evidence item. */
export function evidencePaths(claim: Pick<Claim, "evidence">): { index: number; field: string; path: string }[] {
  return claim.evidence.map((item, index) =>
    "produced_by" in item
      ? { index, field: "produced_by", path: item.produced_by }
      : "measured" in item
        ? { index, field: "measured", path: item.measured }
        : { index, field: "proof", path: item.proof },
  );
}

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
 * Returns each claim's global ID, keyed by local_id. `inputs` is what claims with evidence
 * bind to: the bundle's verification inputs and the declared results.
 *
 * The ID hashes the whole claim except its local_id, with local dependencies resolved to
 * global IDs. A claim with evidence also binds the verification inputs and the value of
 * each result it names, so changing the code, data, or proofs, or one of its results, gives
 * it a new ID and it has to be verified again. Throws ResultError when a named result
 * doesn't exist. See "Claim IDs" in https://sciencejournal.ai/llms.txt.
 */
export function assignClaimIds(claims: readonly Claim[], inputs: BundleInputs): Map<string, ClaimId> {
  return computeClaimIds(claims, inputs);
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

function computeClaimIds(claims: readonly Claim[], inputs: BundleInputs | undefined): Map<string, ClaimId> {
  const ids = new Map<string, ClaimId>();
  for (const claim of orderClaims(claims)) {
    const dependsOn = claim.depends_on.map((dependency) =>
      isClaimId(dependency) ? dependency : ids.get(dependency)!,
    );
    const content: Partial<Claim> = { ...claim };
    delete content.local_id;
    if (claim.evidence.length > 0 && !inputs) {
      throw new Error(`"${claim.local_id}" has evidence, so its ID needs the verification inputs`);
    }
    const results = resultsNamed(claim);
    const id: ClaimId = `claim:${hashCanonical({
      ...content,
      depends_on: [...new Set(dependsOn)].sort(),
      ...(inputs && claim.evidence.length > 0 && { verification_inputs: inputs.verificationInputs }),
      ...(inputs &&
        results.length > 0 && {
          results: Object.fromEntries(results.map((name) => [name, inputs.result(name)])),
        }),
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
