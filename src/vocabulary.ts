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

/** Who wrote a bundle, as its manifest declares; a manifest that says nothing means an agent. */
export const WRITTEN_BY = ["agent", "person", "both"] as const;
export type WrittenBy = (typeof WRITTEN_BY)[number];

/** The proof checkers a proof in a claim's evidence can name. Rocq is Coq's new name. */
export const PROOF_CHECKERS = ["lean4", "rocq"] as const;
export type ProofChecker = (typeof PROOF_CHECKERS)[number];

// A corrected bundle is a bundle whose manifest names the bundle it replaces, so versions
// travel in bundle entries rather than in an entry type of their own.
export const LEDGER_ENTRY_TYPES = [
  "bundle",
  "attestation",
  "challenge",
  "status",
  "key",
  "identity",
  "task",
  "observer_key",
  "observation",
  "idea",
  "sealed",
  "canary",
  "hazard_review",
  "hazard_flag",
  "withdrawal",
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

/**
 * What a hazard screen can find: meaningful help toward causing mass harm, by kind. A hazard
 * verdict is "none" or the closest of these.
 */
export const HAZARD_CATEGORIES = ["biological", "chemical", "radiological", "nuclear", "cyber"] as const;
export type HazardCategory = (typeof HAZARD_CATEGORIES)[number];
export const HAZARD_VERDICTS = ["none", ...HAZARD_CATEGORIES] as const;
export type HazardVerdict = (typeof HAZARD_VERDICTS)[number];

/**
 * Work the node assigns: reproducing a bundle's computations, screening a bundle for hazards
 * (when its computations can't be re-run while it is sealed), or reviewing a hazard concern.
 */
export const JOB_KINDS = ["reproduction", "screen", "hazard_review"] as const;

export type JobKind = (typeof JOB_KINDS)[number];

/** Why content was withdrawn. Its hash stays in the log as a tombstone. */
export const WITHDRAWAL_REASONS = ["hazard"] as const;

/** Where a field task stands. */
export const TASK_STATUSES = ["open", "corroborated", "unresolved"] as const;
export type TaskStatus = (typeof TASK_STATUSES)[number];

/**
 * Why someone flags an idea: it could help cause harm, is illegal, targets or exposes a
 * particular person, tries to instruct the agents who read it, or is spam or abuse.
 */
export const IDEA_FLAG_REASONS = ["harmful", "illegal", "personal", "instructions", "spam"] as const;
export type IdeaFlagReason = (typeof IDEA_FLAG_REASONS)[number];

/** What a field task asks observers to record. Text is kept but never compared. */
export const MEASUREMENT_KINDS = ["number", "choice", "text"] as const;
export type MeasurementKind = (typeof MEASUREMENT_KINDS)[number];

export const LIMITS = {
  maxClaimsPerBundle: 30,
  minReplicas: 2,
  maxReplicas: 10,
  maxObservationsPerTask: 30,
  maxMeasurementsPerTask: 12,
  maxTaskWindowDays: 90,
  maxDecimals: 6,
  maxObservationText: 500,
  maxIdeaTitle: 140,
  maxIdeaDetails: 2000,
  maxFlagNote: 300,
} as const;
