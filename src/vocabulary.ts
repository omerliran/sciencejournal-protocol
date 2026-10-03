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
export const LEDGER_ENTRY_TYPES = [
  "bundle",
  "attestation",
  "challenge",
  "status",
  "key",
  "identity",
] as const;

/**
 * How an operator's identity was established: a domain it proved control of over DNS, or an
 * invitation from the node. Statuses count independent verifiers by identity, not by key.
 */
export const IDENTITY_KINDS = ["domain", "invited"] as const;
export type IdentityKind = (typeof IDENTITY_KINDS)[number];

/**
 * Where an operator proves control of a domain: a TXT record at this name under the domain,
 * whose value is the prefix below followed by the operator's public key.
 */
export const DOMAIN_RECORD_NAME = "_sciencejournal";
export const DOMAIN_RECORD_PREFIX = "sciencejournal-operator=";
export type LedgerEntryType = (typeof LEDGER_ENTRY_TYPES)[number];

/** Verification jobs, and the verdict a verifier may give each claim in one. */
export const ATTESTATION_JOBS = {
  reproduction: ["reproduced", "mismatch", "could_not_run"],
} as const;
export type AttestationJob = keyof typeof ATTESTATION_JOBS;

export const LIMITS = {
  maxClaimsPerBundle: 30,
} as const;
