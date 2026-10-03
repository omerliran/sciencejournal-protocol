import type { z } from "zod";
import {
  assertionDigest,
  assignClaimIds,
  assignClaimIdsWithoutInputs,
  ClaimsFileSchema,
  type ClaimId,
} from "./claims";
import type { Digest } from "./hash";

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
 * Validates the contents of a claims.json and returns each claim's global ID. Without the
 * bundle's verification inputs, claims that bind to them get a null ID.
 */
export function checkClaims(input: unknown, verificationInputs?: Digest): ClaimsCheck {
  const parsed = ClaimsFileSchema.safeParse(input);
  if (!parsed.success) return { valid: false, issues: toIssues(parsed.error) };

  const claims = parsed.data;
  const ids: Map<string, ClaimId | null> = verificationInputs
    ? assignClaimIds(claims, verificationInputs)
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

export function toIssues(error: z.ZodError): Issue[] {
  return error.issues.map((issue) => ({
    path: issue.path.map((segment) => `/${String(segment).replaceAll("~", "~0").replaceAll("/", "~1")}`).join(""),
    message: issue.message,
  }));
}
