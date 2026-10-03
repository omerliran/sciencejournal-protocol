import type { ProofChecker } from "./vocabulary";

// Unfinished proofs. A proof checker accepts a file whose proofs say "trust me": Lean's `sorry`
// (and the `admit` tactic, which stands for it), Rocq's `Admitted` and `admit`. Checking the
// named theorem's axioms shows whether it rests on one; this finds where they are written, as
// information. Each checker's own lexical rules decide what is a word of the proof and what is
// a comment, a string, or part of a longer name, so a word in a comment never counts.

/** The words, by checker, that leave a proof unfinished. */
export const UNFINISHED_PROOF_KEYWORDS: Record<ProofChecker, readonly string[]> = {
  lean4: ["sorry", "admit"],
  rocq: ["Admitted", "admit"],
};

/** The file a checker reads proofs from, by extension. */
export const PROOF_FILE_EXTENSIONS: Record<ProofChecker, string> = { lean4: ".lean", rocq: ".v" };

export interface UnfinishedProof {
  keyword: string;
  /** Where it is: the line, from 1, and the column, from 1, counted in code points. */
  line: number;
  column: number;
}

/** Each unfinished-proof keyword in a proof file, as its checker would read the file. */
export function unfinishedProofs(checker: ProofChecker, text: string): UnfinishedProof[] {
  const keywords = new Set(UNFINISHED_PROOF_KEYWORDS[checker]);
  const words = checker === "lean4" ? leanWords(text) : rocqWords(text);
  return words.filter((word) => keywords.has(word.text)).map((word) => ({ keyword: word.text, ...position(text, word.start) }));
}

type Word = { text: string; start: number };

// Letters as both languages' lexers take them: ASCII and Unicode letters, and `_`. Lean's lexer
// also takes letter-like symbols such as Greek letters, which \p{L} covers.
const LETTER = /[\p{L}_]/u;
const LEAN_REST = /[\p{L}\p{N}_'!?₀-ₜᵢ-ᵪ]/u;
const ROCQ_REST = /[\p{L}\p{N}_']/u;

/**
 * Lean 4's words, skipping `--` line comments, nested `/- -/` block comments (doc comments
 * included), string literals with their escapes, raw strings (`r"…"`, `r#"…"#`), character
 * literals, and «quoted» names, which are names however they are spelled. A dotted name such as
 * `Foo.sorry` is one name, not the keyword. Interpolated strings (`s!"…{x}…"`) are skipped
 * whole, braces included.
 */
function leanWords(text: string): Word[] {
  const words: Word[] = [];
  let i = 0;
  while (i < text.length) {
    const char = text[i];
    if (text.startsWith("--", i)) {
      i = lineEnd(text, i);
    } else if (text.startsWith("/-", i)) {
      i = nestedComment(text, i, "/-", "-/");
    } else if (char === '"') {
      i = escapedString(text, i);
    } else if (char === "r" && /^r#*"/.test(text.slice(i, i + 258))) {
      const hashes = /^r(#*)"/.exec(text.slice(i, i + 258))![1];
      const end = text.indexOf(`"${hashes}`, i + 2 + hashes.length);
      i = end < 0 ? text.length : end + 1 + hashes.length;
    } else if (char === "'" && /^'(\\(u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'/u.test(text.slice(i, i + 16))) {
      i += /^'(\\(u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'/u.exec(text.slice(i, i + 16))![0].length;
    } else if (char === "«") {
      i = dottedName(text, i, LEAN_REST, words, false);
    } else if (LETTER.test(codePointAt(text, i))) {
      i = dottedName(text, i, LEAN_REST, words, true);
    } else {
      i += codePointAt(text, i).length;
    }
  }
  return words;
}

/**
 * Rocq's words, skipping nested `(* *)` comments, inside which strings are still strings, and
 * string literals, where `""` is a quote. A qualified name such as `Lib.admit` is one name; a
 * period followed by anything but a letter ends a sentence.
 */
function rocqWords(text: string): Word[] {
  const words: Word[] = [];
  let i = 0;
  while (i < text.length) {
    const char = text[i];
    if (text.startsWith("(*", i)) {
      i = rocqComment(text, i);
    } else if (char === '"') {
      i = doubledString(text, i);
    } else if (LETTER.test(codePointAt(text, i))) {
      i = dottedName(text, i, ROCQ_REST, words, true);
    } else {
      i += codePointAt(text, i).length;
    }
  }
  return words;
}

/**
 * Reads a name starting at `i`, with its dotted parts, and records it as a word when it is a
 * single plain part (a keyword can't be qualified or quoted). Returns where it ends.
 */
function dottedName(text: string, i: number, rest: RegExp, words: Word[], plain: boolean): number {
  const start = i;
  let parts = 0;
  let quoted = !plain;
  for (;;) {
    if (text[i] === "«") {
      const close = text.indexOf("»", i + 1);
      i = close < 0 ? text.length : close + 1;
      quoted = true;
    } else {
      i += codePointAt(text, i).length;
      while (i < text.length && rest.test(codePointAt(text, i))) i += codePointAt(text, i).length;
    }
    parts++;
    const next = codePointAt(text, i + 1);
    if (text[i] === "." && next && (LETTER.test(next) || next === "«")) {
      i++;
      continue;
    }
    break;
  }
  if (parts === 1 && !quoted) words.push({ text: text.slice(start, i), start });
  return i;
}

function nestedComment(text: string, i: number, open: string, close: string): number {
  let depth = 0;
  while (i < text.length) {
    if (text.startsWith(open, i)) {
      depth++;
      i += open.length;
    } else if (text.startsWith(close, i)) {
      depth--;
      i += close.length;
      if (depth === 0) return i;
    } else {
      i++;
    }
  }
  return text.length;
}

/** A Rocq comment: nested, and a string inside it is read as a string, as Rocq's lexer does. */
function rocqComment(text: string, i: number): number {
  let depth = 0;
  while (i < text.length) {
    if (text.startsWith("(*", i)) {
      depth++;
      i += 2;
    } else if (text.startsWith("*)", i)) {
      depth--;
      i += 2;
      if (depth === 0) return i;
    } else if (text[i] === '"') {
      i = doubledString(text, i);
    } else {
      i++;
    }
  }
  return text.length;
}

/** A string with backslash escapes, as Lean writes them; returns the index after its closing quote. */
function escapedString(text: string, i: number): number {
  for (i++; i < text.length; i++) {
    if (text[i] === "\\") i++;
    else if (text[i] === '"') return i + 1;
  }
  return text.length;
}

/** A string where a doubled quote is a quote, as Rocq writes them. */
function doubledString(text: string, i: number): number {
  for (i++; i < text.length; i++) {
    if (text[i] === '"') {
      if (text[i + 1] === '"') i++;
      else return i + 1;
    }
  }
  return text.length;
}

function lineEnd(text: string, i: number): number {
  const end = text.indexOf("\n", i);
  return end < 0 ? text.length : end;
}

function codePointAt(text: string, i: number): string {
  const code = text.codePointAt(i);
  return code === undefined ? "" : String.fromCodePoint(code);
}

function position(text: string, offset: number): { line: number; column: number } {
  const before = text.slice(0, offset);
  const lineStart = before.lastIndexOf("\n") + 1;
  return { line: before.split("\n").length, column: [...before.slice(lineStart)].length + 1 };
}
