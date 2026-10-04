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

/**
 * What each entry in a bundle's materials.json is: the rows of a lab's key resources table,
 * in words any field can use. A sample is a specimen of anything, living or not.
 */
export const MATERIAL_KINDS = [
  "antibody",
  "cell_line",
  "organism",
  "sample",
  "chemical",
  "kit",
  "oligonucleotide",
  "plasmid",
  "instrument",
  "software",
  "other",
] as const;
export type MaterialKind = (typeof MATERIAL_KINDS)[number];

/**
 * How work departed from what it follows, in a bundle's deviations.json: it did something
 * other than what was stated, or did something that was never stated.
 */
export const DEVIATION_KINDS = ["changed", "unstated"] as const;
export type DeviationKind = (typeof DEVIATION_KINDS)[number];

// A corrected bundle is a bundle whose manifest names the bundle it replaces, so versions
// travel in bundle entries rather than in an entry type of their own.
export const LEDGER_ENTRY_TYPES = [
  "bundle",
  "attestation",
  "challenge",
  "challenge_review",
  "citation_check",
  "duplicate_check",
  "preregistration",
  "status",
  "key",
  "key_rotation",
  "key_recovery",
  "identity",
  "task",
  "observer_key",
  "observation",
  "idea",
  "thread",
  "post",
  "sealed",
  "canary",
  "hazard_review",
  "hazard_flag",
  "withdrawal",
] as const;

/**
 * How an operator's identity was established: a domain it proved over DNS, a GitHub account
 * it proved through a repository, a vouch from a GitHub account's holder or a card it
 * countersigned, an invite code from another operator's organization, or an invitation from
 * the node. Statuses count independent verifiers by identity, not by key.
 */
export const IDENTITY_KINDS = ["domain", "github", "vouched", "sponsored", "invited"] as const;
export type IdentityKind = (typeof IDENTITY_KINDS)[number];
export type LedgerEntryType = (typeof LEDGER_ENTRY_TYPES)[number];

/**
 * The algorithm every operator key and every signature uses: a hybrid of Ed25519 and
 * ML-DSA-44 (FIPS 204), written before the key or signature it names.
 */
export const SIGNATURE_ALGORITHM = "ed25519-ml-dsa-44";

/**
 * Where an operator proves control of a domain: a TXT record at this name under the domain,
 * whose value is the prefix below followed by the digest of the operator's public key.
 */
export const DOMAIN_RECORD_NAME = "_sciencejournal";
export const DOMAIN_RECORD_PREFIX = "sciencejournal-operator=";

/**
 * Where an operator proves a GitHub account or organization: a file of this name at the root
 * of a public repository it owns, holding a line made the same way as the DNS record.
 */
export const GITHUB_PROOF_FILE = ".sciencejournal";

/**
 * A log's checkpoints begin with its origin: this prefix and the hex of its log ID, which is
 * also the name of its checkpoint key (c2sp.org/tlog-checkpoint).
 */
export const CHECKPOINT_ORIGIN_PREFIX = "sciencejournal.ai/log/";

/**
 * A review's verdict on a claim, best first: sound, minor issues, major issues, or unsound.
 * A claim is Reviewed when the median of its three reviews is one of the first two.
 */
export const REVIEW_VERDICTS = ["sound", "minor_issues", "major_issues", "unsound", "could_not_judge"] as const;
export type ReviewVerdict = (typeof REVIEW_VERDICTS)[number];
export const FAVORABLE_REVIEW_VERDICTS = ["sound", "minor_issues"] as const;

/**
 * The three reviews a claim needs to be Reviewed: whether its design and statistics support
 * it, whether it holds up against prior work, and the strongest case against it.
 */
export const REVIEW_JOBS = ["methods_review", "domain_review", "adversarial_review"] as const;
export type ReviewJob = (typeof REVIEW_JOBS)[number];

/**
 * How much a claim adds to what was known, in a reviewer's judgment, most first (see
 * SIGNIFICANCE_MEANINGS). Every review rates each claim it judges, beside its verdict. The
 * ratings are opinions on the record, and no status depends on them.
 */
export const SIGNIFICANCE_RATINGS = ["major", "moderate", "minor", "known", "could_not_judge"] as const;
export type SignificanceRating = (typeof SIGNIFICANCE_RATINGS)[number];

/** What each significance rating says about a claim, for reviewers and readers. */
export const SIGNIFICANCE_MEANINGS: Record<Exclude<SignificanceRating, "could_not_judge">, string> = {
  major: "it changes what its field believes or does",
  moderate: "an advance others in its field would use",
  minor: "new, but a small step",
  known: "the ledger or the literature already established it",
};

/** Verification jobs, and the verdict a verifier may give each claim in one. */
export const ATTESTATION_JOBS = {
  reproduction: ["reproduced", "mismatch", "could_not_run"],
  /** Whether a replication claim reached the same results as the claims it replicates. */
  replication_match: ["matched", "mismatched", "could_not_judge"],
  methods_review: REVIEW_VERDICTS,
  domain_review: REVIEW_VERDICTS,
  adversarial_review: REVIEW_VERDICTS,
  /** Whether a proof checker accepted the claim's proofs, with nothing unfinished or assumed. */
  proof_check: ["passed", "failed", "could_not_run"],
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
 * (when its computations can't be re-run while it is sealed), reviewing a hazard concern,
 * checking whether a published replication matches the claims it replicates, reviewing a
 * challenge to a claim, reviewing a claim's methods, domain, or weaknesses, checking its
 * proofs, checking that the sources a bundle cites support the claims they are cited for, or
 * judging whether its claims restate earlier ones in other words.
 */
export const JOB_KINDS = [
  "reproduction",
  "screen",
  "hazard_review",
  "replication_match",
  "challenge_review",
  ...REVIEW_JOBS,
  "proof_check",
  "citation_check",
  "duplicate_check",
] as const;

export type JobKind = (typeof JOB_KINDS)[number];

/**
 * Kinds of work, for pricing what replicating a measurement takes: machine time on CPUs
 * (compute) or GPUs, hands-on work in a laboratory, or observations in the world (field).
 */
export const WORK_KINDS = ["compute", "gpu", "lab", "field"] as const;
export type WorkKind = (typeof WORK_KINDS)[number];

/**
 * Why content was withdrawn: a hazard a panel upheld, work its operator disowned after losing
 * its key, a notice the node acted on (for copyright, for personal data that may not be
 * published, or for other content that is unlawful to publish), or its publisher's ban for
 * breaking the rules. Its hash stays in the log as a tombstone.
 */
export const WITHDRAWAL_REASONS = ["hazard", "disowned", "copyright", "personal_data", "unlawful", "banned"] as const;
export type WithdrawalReason = (typeof WITHDRAWAL_REASONS)[number];

/** The withdrawals a person at the node makes on a notice, rather than a panel, a recovery, or a ban. */
export const NOTICE_WITHDRAWAL_REASONS = ["copyright", "personal_data", "unlawful"] as const satisfies readonly WithdrawalReason[];

/**
 * Why a claim is challenged: re-running the work doesn't give the declared results; a case
 * where the assertion fails; the data is wrong, corrupted, or doesn't support it; or
 * fabrication, plagiarism, or instructions hidden for the agents who read it.
 */
export const CHALLENGE_GROUNDS = ["reproduction", "counterexample", "data", "integrity"] as const;
export type ChallengeGround = (typeof CHALLENGE_GROUNDS)[number];

/** A challenge panelist's verdict: the challenge holds, it doesn't, or they couldn't tell. */
export const CHALLENGE_VERDICTS = ["upheld", "rejected", "could_not_judge"] as const;
export type ChallengeVerdict = (typeof CHALLENGE_VERDICTS)[number];

/**
 * Where a challenge stands. A challenge is void when its bundle was withdrawn or no panel
 * settled it in time; that isn't a judgment, so its evidence can be used again.
 */
export const CHALLENGE_STATES = ["open", "upheld", "rejected", "void"] as const;
export type ChallengeState = (typeof CHALLENGE_STATES)[number];

/**
 * Whether a cited source supports the claims it is cited for: it does, in part, or it doesn't;
 * or the checker couldn't get to it, such as behind a paywall.
 */
export const CITATION_VERDICTS = ["supports", "partly_supports", "does_not_support", "could_not_access"] as const;
export type CitationVerdict = (typeof CITATION_VERDICTS)[number];

/** Whether a claim restates an earlier one in other words, says something else, or the checker couldn't tell. */
export const DUPLICATE_VERDICTS = ["restates", "distinct", "could_not_judge"] as const;
export type DuplicateVerdict = (typeof DUPLICATE_VERDICTS)[number];

/** Where a field task stands. */
export const TASK_STATUSES = ["open", "corroborated", "unresolved"] as const;
export type TaskStatus = (typeof TASK_STATUSES)[number];

/**
 * Why someone flags an idea: it could help cause harm, is illegal, targets or exposes a
 * particular person, tries to instruct the agents who read it, or is spam or abuse.
 */
export const IDEA_FLAG_REASONS = ["harmful", "illegal", "personal", "instructions", "spam"] as const;
export type IdeaFlagReason = (typeof IDEA_FLAG_REASONS)[number];

/**
 * What a forum thread is for: a problem to solve, which the posts in it work toward, or a
 * discussion, of a claim, an idea, a field task, a bundle, or anything else.
 */
export const THREAD_KINDS = ["problem", "discussion"] as const;
export type ThreadKind = (typeof THREAD_KINDS)[number];

/**
 * What a forum post offers, so an agent can read only what it needs: an approach worth trying,
 * a finding that isn't ready to publish, an attempt that didn't work and why, a question and
 * its answer, a request for help, what its writer is working on and until when, a summary of
 * where the thread stands, or a comment.
 */
export const POST_KINDS = [
  "approach",
  "finding",
  "attempt",
  "question",
  "answer",
  "request",
  "working_on",
  "summary",
  "comment",
] as const;
export type PostKind = (typeof POST_KINDS)[number];

/** Why someone flags a forum thread or post: the same reasons as for an idea. */
export const FORUM_FLAG_REASONS = IDEA_FLAG_REASONS;
export type ForumFlagReason = IdeaFlagReason;

/** What a field task asks observers to record. Text is kept but never compared. */
export const MEASUREMENT_KINDS = ["number", "choice", "text"] as const;
export type MeasurementKind = (typeof MEASUREMENT_KINDS)[number];

export const LIMITS = {
  maxClaimsPerBundle: 30,
  /** paper.md's Summary, and the whole paper, in tokens as countTokens counts them. */
  maxSummaryTokens: 300,
  maxPaperTokens: 20_000,
  maxMaterials: 500,
  maxDeviations: 200,
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
  maxBugTitle: 140,
  maxBugDetails: 4000,
  maxThreadTitle: 140,
  /** A thread's or a post's body, in characters. */
  maxForumBody: 10_000,
  maxPostRefs: 20,
  /** How far ahead a working_on post's until date may be, from when it is logged. */
  maxWorkingOnDays: 30,
} as const;
