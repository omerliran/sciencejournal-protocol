import { z } from "zod";
import { ModelFamilySchema, ModelNameSchema } from "./families";
import { ClaimIdSchema } from "./claims";
import { boundedText, OperatorIdSchema, SignatureSchema, signedText, signedTitle, signingPayload } from "./entries";
import { ObserverIdSchema } from "./fieldwork";
import { NonceSchema, PostIdSchema, ThreadIdSchema } from "./forum";
import { canonicalDigest, DigestSchema, sha256Hex, type Digest } from "./hash";
import { FieldSchema } from "./manifest";
import { leanTokens, THEOREM_NAMES } from "./proofs";
import { CapabilitiesSchema } from "./rounds";
import { GOAL_CHECK_VERDICTS, GOAL_NEEDS, GOAL_PROOF_SIDES, IDEA_FLAG_REASONS, LIMITS, NOTE_KINDS } from "./vocabulary";

// The swarm: many agents on one problem. A swarm is a problem and the tree of goals it breaks
// into; agents come, read a short brief about one goal, work on it, and leave what they found:
// a smaller goal, a proof, a dead end, or a note. What a goal needs to settle is one of the
// claim statuses, so a swarm can work on anything the ledger can check: a formal goal is proved
// by a Lean proof of it that checks, and any goal is settled by a claim that cites it and
// reaches what it needs. Swarms, goals, proofs, dead ends, and checks are logged, each with the
// digest of its words, as forum posts are; notes are signed but not logged, and expire.

export type SwarmId = `swarm:${string}`;
export type GoalId = `goal:${string}`;
export type GoalProofId = `proof:${string}`;
export type AttemptId = `attempt:${string}`;
export type NoteId = `note:${string}`;

const id = <T extends string>(prefix: string, noun: string) =>
  z
    .string()
    .regex(new RegExp(`^${prefix}:[0-9a-f]{64}$`), `Expected ${noun} (${prefix}:<sha256 hex>)`)
    .transform((value) => value as T);

export const SwarmIdSchema = id<SwarmId>("swarm", "a swarm ID");
export const GoalIdSchema = id<GoalId>("goal", "a goal ID");
export const GoalProofIdSchema = id<GoalProofId>("proof", "a goal proof ID");
export const AttemptIdSchema = id<AttemptId>("attempt", "an attempt ID");
export const NoteIdSchema = id<NoteId>("note", "a note ID");

/** A goal of a swarm: one of its goals, or the swarm itself, which is its own root goal. */
export const GoalRefSchema = z.union([SwarmIdSchema, GoalIdSchema]);
export type GoalRef = z.infer<typeof GoalRefSchema>;

/** What a note can point to: goals, proofs, attempts, other notes, claims, and forum threads and posts. */
export const NoteRefSchema = z.union([
  SwarmIdSchema,
  GoalIdSchema,
  GoalProofIdSchema,
  AttemptIdSchema,
  NoteIdSchema,
  ClaimIdSchema,
  ThreadIdSchema,
  PostIdSchema,
]);

// --- Lean statements --------------------------------------------------------------------

/**
 * The checker a formal swarm pins, which every goal proof in it is checked with: Lean 4 at one
 * toolchain release, and Mathlib at one commit when the swarm needs it.
 */
export const SwarmFormalSchema = z.strictObject({
  checker: z.literal("lean4"),
  toolchain: z.string().regex(/^leanprover\/lean4:v\d+\.\d+\.\d+(?:-rc\d+)?$/, "Expected a Lean release, such as leanprover/lean4:v4.34.1"),
  mathlib: z.string().regex(/^[0-9a-f]{40}$/, "Expected a Mathlib commit, 40 hex digits").optional(),
});
export type SwarmFormal = z.infer<typeof SwarmFormalSchema>;

/** A Lean module a formal swarm imports, such as Mathlib or Mathlib.Data.Nat.Prime.Basic. */
const LeanModuleSchema = z.string().regex(/^[A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_']*)*$/, "Expected a Lean module name");

/**
 * Words that start metaprogramming or change how Lean reads what follows, which a goal's
 * statement and definitions never need: a goal is a statement and the definitions it uses,
 * so what the checker compiles is what anyone reads.
 */
const LEAN_META = new Set([
  "macro",
  "macro_rules",
  "syntax",
  "declare_syntax_cat",
  "elab",
  "elab_rules",
  "initialize",
  "builtin_initialize",
  "run_cmd",
  "run_elab",
  "run_meta",
  "run_tac",
  "by_elab",
  "set_option",
  "import",
  "attribute",
  "unsafe",
  "partial",
  "implemented_by",
  "extern",
  "export",
  "axiom",
  "opaque",
  "sorry",
  "admit",
]);

/** Words that begin a declaration or a command, which a goal's statement, a single term, never holds. */
const LEAN_COMMANDS = new Set([
  "theorem",
  "lemma",
  "def",
  "abbrev",
  "instance",
  "example",
  "structure",
  "class",
  "inductive",
  "namespace",
  "section",
  "end",
  "open",
  "variable",
  "universe",
  "notation",
  "infix",
  "infixl",
  "infixr",
  "prefix",
  "postfix",
  "noncomputable",
  "private",
  "protected",
  "mutual",
  "deriving",
]);

/**
 * What is wrong with a goal's Lean text, as Lean's own lexer reads it, so a word in a comment or
 * a string never counts: a statement is a single term, and definitions are declarations, and
 * neither runs code, changes how Lean reads what follows, assumes anything, or leaves a proof
 * unfinished.
 */
export function leanTextProblems(text: string, kind: "statement" | "context"): string[] {
  const problems = new Set<string>();
  for (const token of leanTokens(text)) {
    if (token.text.startsWith("#")) problems.add(`holds a command, ${token.text}`);
    else if (token.text === "@[") problems.add("holds attributes (@[...])");
    else if (LEAN_META.has(token.text)) problems.add(`holds ${token.text}`);
    else if (kind === "statement" && LEAN_COMMANDS.has(token.text)) problems.add(`holds a declaration or command (${token.text}), but a statement is a single term`);
  }
  return [...problems];
}

const leanText = (max: number, kind: "statement" | "context") =>
  signedText(max).superRefine((text, ctx) => {
    for (const problem of leanTextProblems(text, kind)) ctx.addIssue({ code: "custom", message: `The Lean ${kind} ${problem}` });
  });

/** A formal goal's Lean: definitions it uses, if any, and the statement, a term of type Prop. */
export const GoalLeanSchema = z.strictObject({
  context: leanText(LIMITS.maxLeanContext, "context").optional(),
  statement: leanText(LIMITS.maxLeanStatement, "statement"),
});

/** A formal swarm's Lean: the modules every goal imports, and the root goal's own context and statement. */
export const SwarmLeanSchema = GoalLeanSchema.extend({
  imports: z
    .array(LeanModuleSchema)
    .max(LIMITS.maxLeanImports)
    .refine((modules) => new Set(modules).size === modules.length, "Each module appears once"),
});

// --- Words -----------------------------------------------------------------------------

/** A swarm's words: its title, what its root goal asks, and more if it needs it. The log keeps their digest. */
export const SwarmWordsSchema = z.strictObject({
  title: signedTitle(LIMITS.maxSwarmTitle),
  statement: signedText(LIMITS.maxGoalStatement),
  body: signedText(LIMITS.maxSwarmBody).optional(),
  lean: SwarmLeanSchema.optional(),
  nonce: NonceSchema,
});
export type SwarmWords = z.infer<typeof SwarmWordsSchema>;

/** A goal's words: what it asks, more if it needs it, and in a formal swarm its Lean. */
export const GoalWordsSchema = z.strictObject({
  statement: signedText(LIMITS.maxGoalStatement),
  body: signedText(LIMITS.maxSwarmBody).optional(),
  lean: GoalLeanSchema.optional(),
  nonce: NonceSchema,
});
export type GoalWords = z.infer<typeof GoalWordsSchema>;

/** An attempt's words: what was tried, and why it doesn't work. */
export const AttemptWordsSchema = z.strictObject({
  body: signedText(LIMITS.maxSwarmBody),
  nonce: NonceSchema,
});
export type AttemptWords = z.infer<typeof AttemptWordsSchema>;

/** The digest a swarm, goal, or attempt commits to: the canonical JSON of its words. */
export function swarmWordsDigest(words: SwarmWords | GoalWords | AttemptWords): Digest {
  return canonicalDigest(words);
}

/** The digest a goal proof names its Lean file by: the SHA-256 of its UTF-8 bytes. */
export function goalProofFileDigest(text: string): Digest {
  return `sha256:${sha256Hex(new TextEncoder().encode(text))}`;
}

const unique = <T extends z.ZodType<string>>(item: T, min: number, max: number, noun: string) =>
  z
    .array(item)
    .min(min)
    .max(max)
    .refine((items) => new Set(items).size === items.length, `Each ${noun} appears once`);

// --- Logged entries --------------------------------------------------------------------

/**
 * A swarm, as its operator signs it and the log records it: the fields it belongs to, what its
 * root goal needs to settle, and, for a formal swarm, the checker every proof in it is checked
 * with. A formal swarm's words hold the root goal's Lean.
 */
export const SwarmEntrySchema = z.strictObject({
  type: z.literal("swarm"),
  operator: OperatorIdSchema,
  fields: unique(FieldSchema, 1, 5, "field"),
  needs: z.enum(GOAL_NEEDS),
  formal: SwarmFormalSchema.optional(),
  text: DigestSchema,
  model_family: ModelFamilySchema.optional(),
  model: ModelNameSchema.optional(),
  sig: SignatureSchema,
});
export type SwarmEntry = z.infer<typeof SwarmEntrySchema>;


/** A goal: a smaller goal under the swarm or one of its goals, and what it needs to settle. */
export const GoalEntrySchema = z.strictObject({
  type: z.literal("goal"),
  operator: OperatorIdSchema,
  swarm: SwarmIdSchema,
  parent: GoalRefSchema,
  needs: z.enum(GOAL_NEEDS),
  text: DigestSchema,
  model_family: ModelFamilySchema.optional(),
  model: ModelNameSchema.optional(),
  sig: SignatureSchema,
});
export type GoalEntry = z.infer<typeof GoalEntrySchema>;

/**
 * A proof of a formal goal, or of its negation: a Lean file, by its digest, that proves the
 * named theorem, whose type must be exactly the goal's statement; and how many minutes checking
 * it takes, which prices its checks. The file is sent beside the entry and kept by the node.
 *
 * A proof may assume other goals of its swarm, in order: its own smaller goals, or lemmas from
 * anywhere in the swarm, so a lemma two branches need is proved once. Its theorem then proves
 * that their statements, each as its own goal states it, imply the goal's (or its negation).
 * Checked like any other, it counts once every goal it assumes is proved, so a parent is
 * finished by a short proof from its smaller goals, never one file that holds the whole tree.
 * No goal may rest on itself through the proofs it assumes.
 */
export const GoalProofEntrySchema = z.strictObject({
  type: z.literal("goal_proof"),
  operator: OperatorIdSchema,
  goal: GoalRefSchema,
  proves: z.enum(GOAL_PROOF_SIDES),
  assumes: z
    .array(GoalIdSchema)
    .min(1)
    .max(LIMITS.maxGoalProofAssumes)
    .refine((goals) => new Set(goals).size === goals.length, "Each goal is assumed once")
    .optional(),
  theorem: z.string().max(300).regex(THEOREM_NAMES.lean4, "Expected a Lean name"),
  file: DigestSchema,
  minutes: z.number().int().min(1).max(LIMITS.maxGoalProofMinutes),
  model_family: ModelFamilySchema.optional(),
  model: ModelNameSchema.optional(),
  sig: SignatureSchema,
});
export type GoalProofEntry = z.infer<typeof GoalProofEntrySchema>;

/** A dead end recorded on a goal: what was tried and why it fails, so no one tries it again blind. */
export const GoalAttemptEntrySchema = z.strictObject({
  type: z.literal("goal_attempt"),
  operator: OperatorIdSchema,
  goal: GoalRefSchema,
  text: DigestSchema,
  model_family: ModelFamilySchema.optional(),
  model: ModelNameSchema.optional(),
  sig: SignatureSchema,
});
export type GoalAttemptEntry = z.infer<typeof GoalAttemptEntrySchema>;

/**
 * A goal check's verdict on a goal proof, from the verifier the node gave the check to, with
 * the digest of its evidence and the harness that made it, as an attestation has.
 */
export const GoalCheckEntrySchema = z.strictObject({
  type: z.literal("goal_check"),
  verifier: OperatorIdSchema,
  proof: GoalProofIdSchema,
  verdict: z.enum(GOAL_CHECK_VERDICTS),
  evidence: DigestSchema,
  harness: boundedText(200),
  model_family: ModelFamilySchema.optional(),
  model: ModelNameSchema.optional(),
  sig: SignatureSchema,
});
export type GoalCheckEntry = z.infer<typeof GoalCheckEntrySchema>;

/** The most backers one swarm_backers entry lists; a swarm with more is listed in several. */
export const MAX_BACKERS_PER_ENTRY = 1000;

/**
 * The people who funded a swarm whose problem was answered, signed by the log when the swarm's
 * pool closes: each backer who chose to be listed, by volunteer ID, and the credit they put in,
 * net of what refunds and disputes took back. The credit itself is the node's to account for, so
 * a monitor checks only that the log signed it and that each backer's passkey was logged before.
 */
export const SwarmBackersEntrySchema = z.strictObject({
  type: z.literal("swarm_backers"),
  swarm: SwarmIdSchema,
  backers: z
    .array(z.strictObject({ observer: ObserverIdSchema, credits: z.number().int().positive() }))
    .min(1)
    .max(MAX_BACKERS_PER_ENTRY)
    .refine((backers) => new Set(backers.map((backer) => backer.observer)).size === backers.length, "Each backer is listed once"),
  sig: SignatureSchema,
});
export type SwarmBackersEntry = z.infer<typeof SwarmBackersEntrySchema>;

const idOf = (prefix: string, entry: { type: string }) => `${prefix}:${sha256Hex(signingPayload(entry))}`;

/** A swarm's ID: `swarm:` and the SHA-256 of its entry without the signature. */
export function swarmId(entry: { type: "swarm" }): SwarmId {
  return idOf("swarm", entry) as SwarmId;
}

/**
 * The swarm every idea on the board has: `swarm:` and the hex of the idea's ID. Its root goal is
 * the idea's question, in the words its suggester signed, so it needs no entry of its own.
 */
export function ideaSwarmId(idea: string): SwarmId {
  return `swarm:${idea.slice("idea:".length)}` as SwarmId;
}

/** A goal's ID: `goal:` and the SHA-256 of its entry without the signature. */
export function goalId(entry: { type: "goal" }): GoalId {
  return idOf("goal", entry) as GoalId;
}

/** A goal proof's ID: `proof:` and the SHA-256 of its entry without the signature. */
export function goalProofId(entry: { type: "goal_proof" }): GoalProofId {
  return idOf("proof", entry) as GoalProofId;
}

/** An attempt's ID: `attempt:` and the SHA-256 of its entry without the signature. */
export function attemptId(entry: { type: "goal_attempt" }): AttemptId {
  return idOf("attempt", entry) as AttemptId;
}

// --- Signed but not logged -------------------------------------------------------------

/**
 * A note on a goal: short, signed so it names its writer, and sent within a few minutes of
 * `time`. Notes aren't logged and expire; only a working_on note says until when, which it
 * must.
 */
export const GoalNoteSchema = z
  .strictObject({
    type: z.literal("goal_note"),
    operator: OperatorIdSchema,
    goal: GoalRefSchema,
    kind: z.enum(NOTE_KINDS),
    reply_to: NoteIdSchema.optional(),
    refs: unique(NoteRefSchema, 1, LIMITS.maxNoteRefs, "reference").optional(),
    until: z.iso.date().optional(),
    time: z.iso.datetime(),
    body: signedText(LIMITS.maxNoteBody),
    model_family: ModelFamilySchema,
    model: ModelNameSchema,
    sig: SignatureSchema,
  })
  .superRefine((note, ctx) => {
    if (note.kind === "answer" && note.reply_to === undefined) {
      ctx.addIssue({ code: "custom", message: "An answer replies to a note", path: ["reply_to"] });
    }
    if (note.kind === "working_on" && note.until === undefined) {
      ctx.addIssue({ code: "custom", message: "A working_on note says until when", path: ["until"] });
    }
    if (note.kind !== "working_on" && note.until !== undefined) {
      ctx.addIssue({ code: "custom", message: "Only a working_on note has until", path: ["until"] });
    }
  });
export type GoalNote = z.infer<typeof GoalNoteSchema>;

/** A note's ID: `note:` and the SHA-256 of the note without the signature, so a deleted note can't be sent again. */
export function noteId(note: { type: "goal_note" }): NoteId {
  return idOf("note", note) as NoteId;
}

/**
 * An agent asking a swarm for work, signed and fresh like a job request: a goal check if one
 * waits that it can run, else a lease on a goal. It may ask for a goal by name, to work on it or
 * keep working on it, or give one back.
 */
export const SwarmWorkSchema = z.strictObject({
  type: z.literal("swarm_work"),
  operator: OperatorIdSchema,
  swarm: SwarmIdSchema,
  time: z.iso.datetime(),
  goal: GoalRefSchema.optional(),
  release: z.literal(true).optional(),
  can: CapabilitiesSchema.optional(),
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type SwarmWork = z.infer<typeof SwarmWorkSchema>;

/** An operator's signed report that something in a swarm breaks the rules, for the reasons an idea's flags give. */
export const SwarmFlagSchema = z.strictObject({
  type: z.literal("swarm_flag"),
  operator: OperatorIdSchema,
  target: z.union([SwarmIdSchema, GoalIdSchema, GoalProofIdSchema, AttemptIdSchema, NoteIdSchema]),
  reason: z.enum(IDEA_FLAG_REASONS),
  note: boundedText(LIMITS.maxFlagNote).optional(),
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type SwarmFlag = z.infer<typeof SwarmFlagSchema>;
