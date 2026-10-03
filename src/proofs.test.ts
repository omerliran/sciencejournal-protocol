import { describe, expect, it } from "vitest";
import { unfinishedProofs } from "./proofs";

const keywords = (checker: "lean4" | "rocq", text: string) =>
  unfinishedProofs(checker, text).map(({ keyword, line, column }) => `${keyword}@${line}:${column}`);

describe("unfinished Lean 4 proofs", () => {
  it("finds sorry and admit where Lean reads them as words of the proof", () => {
    const text = ["theorem a : 1 = 1 := by", "  sorry", "theorem b (n : Nat) : n = n := by admit", "def c : Nat := sorry"].join("\n");
    expect(keywords("lean4", text)).toEqual(["sorry@2:3", "admit@3:35", "sorry@4:16"]);
  });

  it("skips comments, nested or not, doc comments, strings, and characters", () => {
    const text = [
      "-- sorry in a line comment",
      "/- a block comment with sorry /- nested sorry -/ still sorry -/",
      "/-- a doc comment: sorry -/",
      "/-! module docs: admit -/",
      'def s := "sorry, and an escaped \\" quote, then sorry"',
      'def r := r#"raw "sorry" string"#',
      "def c := 's'",
      "theorem t : True := trivial -- sorry",
    ].join("\n");
    expect(keywords("lean4", text)).toEqual([]);
  });

  it("reads longer names, dotted names, and «quoted» names as names", () => {
    const text = ["def sorry_count := 3", "def x := Foo.sorry", "def «sorry» := 1", "def h' := sorry'", "theorem y : sorry! = 1 := rfl"].join("\n");
    expect(keywords("lean4", text)).toEqual([]);
  });

  it("counts columns in code points, after letters outside the basic plane", () => {
    expect(keywords("lean4", "def 𝔸 := sorry")).toEqual(["sorry@1:10"]);
  });
});

describe("unfinished Rocq proofs", () => {
  it("finds Admitted and admit where Rocq reads them as words of the proof", () => {
    const text = ["Theorem a : 1 = 1.", "Proof. admit. Admitted.", "Lemma b : True.", "Proof.", "  admit.", "Admitted."].join("\n");
    expect(keywords("rocq", text)).toEqual(["admit@2:8", "Admitted@2:15", "admit@5:3", "Admitted@6:1"]);
  });

  it("skips nested comments, strings in comments, and strings with doubled quotes", () => {
    const text = [
      "(* Admitted (* nested admit *) still Admitted *)",
      '(* a string in a comment: "*) Admitted" keeps the comment open *)',
      'Definition s := "admit, and a ""quoted"" Admitted".',
      "Theorem t : True. Proof. exact I. Qed. (* admit *)",
    ].join("\n");
    expect(keywords("rocq", text)).toEqual([]);
  });

  it("reads qualified and longer names as names, and a period before a space as the end of a sentence", () => {
    const text = ["Definition admit_count := 3.", "Check Lib.admit.", "Definition Admitted' := 1.", "Proof. admit."].join("\n");
    expect(keywords("rocq", text)).toEqual(["admit@4:8"]);
  });
});
