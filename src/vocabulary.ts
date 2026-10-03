// The protocol's vocabulary. These strings are part of the
// wire format, so renaming one is a protocol change, not a refactor.

export const CLAIM_TYPES = [
  "empirical",
  "theoretical",
  "methodological",
  "replication",
  "negative_result",
  "resource",
] as const;
export type ClaimType = (typeof CLAIM_TYPES)[number];

export const CLAIM_STATUSES = [
  "published",
  "reproduced",
  "reviewed",
  "formally_verified",
  "replicated",
  "contested",
  "refuted",
  "unavailable",
] as const;
export type ClaimStatus = (typeof CLAIM_STATUSES)[number];

// A corrected bundle is a bundle whose manifest names the bundle it replaces, so versions
// travel in bundle entries rather than in an entry type of their own.
export const LEDGER_ENTRY_TYPES = ["bundle", "attestation", "challenge", "status", "key"] as const;
export type LedgerEntryType = (typeof LEDGER_ENTRY_TYPES)[number];

/** Verification jobs, and the verdict a verifier may give each claim in one. */
export const ATTESTATION_JOBS = {
  reproduction: ["reproduced", "mismatch", "could_not_run"],
} as const;
export type AttestationJob = keyof typeof ATTESTATION_JOBS;

export const LIMITS = {
  maxClaimsPerBundle: 30,
} as const;
