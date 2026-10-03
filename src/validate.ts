import type { z } from "zod";
import {
  assertionDigest,
  assignClaimIds,
  assignClaimIdsWithoutInputs,
  ClaimsFileSchema,
  evidencePaths,
  resultsNamed,
  type Claim,
  type ClaimId,
} from "./claims";
import type { Digest } from "./hash";
import { ResultError, type BundleInputs } from "./results";

export interface Issue {
  /** JSON Pointer to the offending value, "" for the document itself. */
  path: string;
  message: string;
}

export type ClaimsCheck =
  | {
      valid: true;
      claims: {
        local_id: string;
        /** null when the claim binds verification inputs that weren't supplied. */
        claim_id: ClaimId | null;
        assertion_digest: Digest;
      }[];
    }
  | { valid: false; issues: Issue[] };

/**
 * Validates the contents of a claims.json and returns each claim's global ID. With the
 * bundle's inputs, every result the evidence names must be declared, and every file it names
 * must exist when the inputs can tell. Without them, claims that bind to them get a null ID.
 */
export function checkClaims(input: unknown, inputs?: BundleInputs): ClaimsCheck {
  const parsed = ClaimsFileSchema.safeParse(input);
  if (!parsed.success) return { valid: false, issues: toIssues(parsed.error) };

  const claims = parsed.data;
  if (inputs) {
    const issues = evidenceIssues(claims, inputs);
    if (issues.length > 0) return { valid: false, issues };
  }
  const ids: Map<string, ClaimId | null> = inputs
    ? assignClaimIds(claims, inputs)
    : assignClaimIdsWithoutInputs(claims);
  return {
    valid: true,
    claims: claims.map((claim) => ({
      local_id: claim.local_id,
      claim_id: ids.get(claim.local_id) ?? null,
      assertion_digest: assertionDigest(claim),
    })),
  };
}

/** Results the evidence names that aren't declared, and files it names that aren't there. */
function evidenceIssues(claims: readonly Claim[], inputs: BundleInputs): Issue[] {
  const issues: Issue[] = [];
  claims.forEach((claim, i) => {
    const named = new Set(resultsNamed(claim));
    claim.evidence.forEach((item, j) => {
      if (!("result" in item) || !named.delete(item.result)) return;
      try {
        inputs.result(item.result);
      } catch (error) {
        if (!(error instanceof ResultError)) throw error;
        issues.push({ path: pointer([i, "evidence", j, "result"]), message: error.message });
      }
    });
    if (!inputs.has) return;
    for (const { index, field, path } of evidencePaths(claim)) {
      if (!inputs.has(path)) {
        issues.push({ path: pointer([i, "evidence", index, field]), message: `The bundle has no ${path}` });
      }
    }
  });
  return issues;
}

export function toIssues(error: z.ZodError): Issue[] {
  return error.issues.map((issue) => ({ path: pointer(issue.path), message: issue.message }));
}

function pointer(segments: readonly PropertyKey[]): string {
  return segments.map((segment) => `/${String(segment).replaceAll("~", "~0").replaceAll("/", "~1")}`).join("");
}
