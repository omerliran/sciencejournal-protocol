import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import { isCheckableReference, isGoalReference } from "./citations";
import { detachSignatures, signObject, verifyObject } from "./entries";
import { sha256Hex } from "./hash";
import { LogLeafSchema } from "./leaves";
import { ReferencesFileSchema } from "./references";
import { generateKeyPair } from "./signing";
import {
  attemptId,
  GoalEntrySchema,
  goalId,
  GoalNoteSchema,
  GoalProofEntrySchema,
  goalProofFileDigest,
  goalProofId,
  GoalWordsSchema,
  leanTextProblems,
  noteId,
  SwarmEntrySchema,
  swarmId,
  SwarmWordsSchema,
  swarmWordsDigest,
  SwarmWorkSchema,
  type SwarmWords,
} from "./swarm";

const op = `op:${"1".repeat(64)}`;
const nonce = "0123456789abcdef0123456789abcdef";
const keys = generateKeyPair();
const TIME = "2026-10-05T12:00:00.000Z";

const words: SwarmWords = {
  title: "Every n has a Hamiltonian cycle in SB(n, 3)",
  statement: "For every m > 1, the graph SB(m, 3) has a Hamiltonian cycle.",
  lean: { imports: ["Mathlib"], context: "def double (n : Nat) : Nat := 2 * n", statement: "∀ n : Nat, double n = n + n" },
  nonce,
};
const swarm = signObject(
  {
    type: "swarm" as const,
    operator: op,
    fields: ["mathematics"],
    needs: "formally_verified" as const,
    formal: { checker: "lean4" as const, toolchain: "leanprover/lean4:v4.34.1", mathlib: "a".repeat(40) },
    text: swarmWordsDigest(words),
  },
  keys.secretKey,
);
const goal = (fields: Record<string, unknown> = {}) =>
  signObject(
    { type: "goal" as const, operator: op, swarm: swarmId(swarm), parent: swarmId(swarm), needs: "formally_verified" as const, text: swarmWordsDigest({ statement: "Doubling is adding a number to itself.", nonce }), ...fields },
    keys.secretKey,
  );

describe("swarms and their goals", () => {
  it("commit to the digest of their words, and are named by their entries", () => {
    expect(swarm.text).toBe(`sha256:${sha256Hex(canonicalJson(words))}`);
    const unsigned: Record<string, unknown> = { ...swarm };
    delete unsigned.sig;
    expect(swarmId(swarm)).toBe(`swarm:${sha256Hex(canonicalJson(unsigned))}`);
    expect(goalId(goal())).toMatch(/^goal:[0-9a-f]{64}$/);
    // The same words under another parent make another goal.
    expect(goalId(goal({ parent: goalId(goal()) }))).not.toBe(goalId(goal()));
  });

  it("are signed by their operator, and logged with each signature by digest", () => {
    expect(SwarmEntrySchema.parse(swarm)).toEqual(swarm);
    expect(verifyObject(GoalEntrySchema.parse(goal()), keys.publicKey)).toBe(true);
    const proof = signObject(
      { type: "goal_proof" as const, operator: op, goal: goalId(goal()), proves: "goal" as const, theorem: "Double.main", file: goalProofFileDigest("theorem x : True := trivial"), minutes: 5 },
      keys.secretKey,
    );
    const attempt = signObject({ type: "goal_attempt" as const, operator: op, goal: swarmId(swarm), text: swarmWordsDigest({ body: "Induction on n alone stalls at the carry.", nonce }) }, keys.secretKey);
    const check = signObject(
      { type: "goal_check" as const, verifier: op, proof: goalProofId(proof), verdict: "passed" as const, evidence: goalProofFileDigest("evidence"), harness: "sj-harness 0.1.0" },
      keys.secretKey,
    );
    expect(attemptId(attempt)).toMatch(/^attempt:[0-9a-f]{64}$/);
    for (const entry of [swarm, goal(), proof, attempt]) {
      expect(LogLeafSchema.safeParse({ timestamp: TIME, operator: op, entry: detachSignatures(entry) }).success).toBe(true);
    }
    expect(LogLeafSchema.safeParse({ timestamp: TIME, operator: op, entry: detachSignatures(check) }).success).toBe(true);
  });

  it("pin a checker exactly, and a proof names a theorem and only a theorem", () => {
    const pinned = (formal: Record<string, unknown>) => SwarmEntrySchema.safeParse({ ...swarm, formal }).success;
    expect(pinned({ checker: "lean4", toolchain: "leanprover/lean4:v4.35.0-rc1" })).toBe(true);
    expect(pinned({ checker: "lean4", toolchain: "leanprover/lean4:stable" })).toBe(false);
    expect(pinned({ checker: "lean4", toolchain: "leanprover/lean4:v4.34.1", mathlib: "master" })).toBe(false);
    expect(pinned({ checker: "rocq", toolchain: "leanprover/lean4:v4.34.1" })).toBe(false);
    const proof = (theorem: string) =>
      GoalProofEntrySchema.safeParse({ type: "goal_proof", operator: op, goal: swarmId(swarm), proves: "negation", theorem, file: goalProofFileDigest("x"), minutes: 1, sig: swarm.sig }).success;
    expect(proof("Main.«odd name»")).toBe(true);
    expect(proof("main\n#exit")).toBe(false);
  });

  it("hold a goal's words and Lean as written: trimmed by the writer, never by the node", () => {
    expect(SwarmWordsSchema.safeParse(words).success).toBe(true);
    expect(SwarmWordsSchema.safeParse({ ...words, title: "Two\nlines" }).success).toBe(false);
    expect(GoalWordsSchema.safeParse({ statement: " padded", nonce }).success).toBe(false);
    expect(SwarmWordsSchema.safeParse({ ...words, lean: { ...words.lean!, imports: ["mathlib"] } }).success).toBe(false);
  });
});

describe("a goal's Lean", () => {
  it("is a single term for a statement, and declarations for its definitions", () => {
    expect(leanTextProblems("∀ n : Nat, n + 0 = n", "statement")).toEqual([]);
    expect(leanTextProblems("(#[1, 2, 3].size = 3) ∧ (fun x => x) 1 = 1", "statement")).toEqual([]);
    expect(leanTextProblems("structure P where\n  x : Nat\n\ndef f (p : P) : Nat := p.x\ninstance : Inhabited P := ⟨⟨0⟩⟩", "context")).toEqual([]);
    expect(leanTextProblems("True\ntheorem t : False := by simp", "statement")).toEqual(["holds a declaration or command (theorem), but a statement is a single term"]);
  });

  it("runs no code, changes nothing about how Lean reads it, and assumes nothing", () => {
    expect(leanTextProblems("def x := 1\n#eval IO.println x", "context")).toEqual(["holds a command, #eval"]);
    expect(leanTextProblems("@[simp] def x := 1", "context")).toEqual(["holds attributes (@[...])"]);
    expect(leanTextProblems("macro_rules | `(stmt) => `(True)", "context")).toEqual(["holds macro_rules"]);
    expect(leanTextProblems("axiom cheat : False", "context")).toEqual(["holds axiom"]);
    expect(leanTextProblems("def x : Nat := by exact sorry", "context")).toEqual(["holds sorry"]);
    expect(leanTextProblems("set_option maxHeartbeats 0 in\ndef x := 1", "context")).toEqual(["holds set_option"]);
  });

  it("is read as Lean reads it: comments, strings, and longer names don't count", () => {
    expect(leanTextProblems('-- theorem in a comment\n/- #eval -/ "macro_rules" = "x" ∧ Foo.sorry = Foo.sorry', "statement")).toEqual([]);
  });
});

describe("notes", () => {
  const note = (fields: Record<string, unknown> = {}) =>
    signObject({ type: "goal_note" as const, operator: op, goal: swarmId(swarm), kind: "approach", time: TIME, body: "Try strong induction on the carry.", model_family: "claude", model: "claude-test-1", ...fields }, keys.secretKey);

  it("are signed, fresh, and named by what they say, so one deleted can't be sent again as new", () => {
    expect(GoalNoteSchema.safeParse(note()).success).toBe(true);
    expect(noteId(note())).toBe(noteId(note()));
    expect(noteId(note({ body: "Something else." }))).not.toBe(noteId(note()));
    expect(GoalNoteSchema.safeParse(note({ time: "yesterday" })).success).toBe(false);
  });

  it("hold what each kind needs: an answer replies, and only working_on says until when", () => {
    expect(GoalNoteSchema.safeParse(note({ kind: "answer" })).success).toBe(false);
    expect(GoalNoteSchema.safeParse(note({ kind: "answer", reply_to: noteId(note()) })).success).toBe(true);
    expect(GoalNoteSchema.safeParse(note({ kind: "working_on" })).success).toBe(false);
    expect(GoalNoteSchema.safeParse(note({ kind: "working_on", until: "2026-10-20" })).success).toBe(true);
    expect(GoalNoteSchema.safeParse(note({ until: "2026-10-20" })).success).toBe(false);
    expect(GoalNoteSchema.safeParse(note({ body: "x".repeat(2001) })).success).toBe(false);
  });

  it("can ask a swarm for work, by a goal or by none, and give one back", () => {
    const work = (fields: Record<string, unknown> = {}) => SwarmWorkSchema.safeParse(signObject({ type: "swarm_work", operator: op, swarm: swarmId(swarm), time: TIME, model_family: "claude", model: "claude-test-1", ...fields }, keys.secretKey)).success;
    expect(work()).toBe(true);
    expect(work({ goal: goalId(goal()), release: true })).toBe(true);
    expect(work({ goal: `thread:${"a".repeat(64)}` })).toBe(false);
  });
});

describe("citing a goal", () => {
  it("is a reference a bundle can make, and one a citation check judges", () => {
    const references = [{ id: goalId(goal()), claims: ["C1"] }, { id: swarmId(swarm) }];
    expect(ReferencesFileSchema.safeParse(references).success).toBe(true);
    expect(isGoalReference({ id: goalId(goal()) })).toBe(true);
    expect(isCheckableReference({ id: swarmId(swarm) })).toBe(true);
    expect(isCheckableReference({ id: `thread:${"a".repeat(64)}` })).toBe(false);
  });
});
