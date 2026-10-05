import { ClaimsFileSchema, needsReplication } from "./claims";
import { followed } from "./deviations";
import { parseJson } from "./json";
import { missingSections, parseMarkdown, plainText, sectionDepth, type MarkdownNode } from "./paper";
import { spelledNumbers } from "./number-words";
import { ReferenceIdSchema, ReferencesFileSchema } from "./references";
import { RESULT_PLACEHOLDER } from "./results";
import { revealHidden } from "./scan";

// Deterministic integrity checks. Each one flags something for verifiers to look at; none
// rejects a bundle, since a flag can be innocent and only a reader can tell.
//
// No orphan numbers: the sections of paper.md that state results (Summary, Claims, and
// Results) give each result as a placeholder, {{R3.loss_delta}}, so the prose can't disagree
// with the declared results. A number typed into one of those sections is flagged, in digits
// or spelled out in words, though prose may spell out the counts zero to nine, as in "two
// methods". Methods and the other sections are where parameters live, such as a learning rate
// or a sample size, so their numbers aren't.
//
// Citations: the paper cites a source where it uses it, as a link to the source's reference
// ID, such as [Klebanoff (2001)](doi:10.1142/S0218348X01000828), and references.json lists
// every source it cites. A reference the paper never cites, or a citation of an ID that
// references.json doesn't list, is flagged, since a reader can't tell what supports what.
//
// What someone needs to repeat the work: paper.md's fixed sections, Methods among them, and the
// files its claims call for: materials.json when a claim rests on a measurement, which only
// measuring again with the same materials can check, and deviations.json when the work follows
// a claim it replicates or a pre-registered plan. A bundle may say there is nothing to list
// with an empty list; saying nothing is what's flagged.
//
// Data forensics: in a table under data/, exact duplicate rows, and numeric columns whose
// first digits stray from Benford's law, which naturally occurring numbers spanning several
// orders of magnitude follow and invented ones often don't.

/** The sections of paper.md that state results, by their fixed names. */
export const CLAIM_BEARING_SECTIONS = ["Summary", "Claims", "Results"] as const;

/** The files a bundle's claims call for, and why each is flagged when the bundle lacks it. */
export const MISSING_FILE_REASONS = {
  "materials.json": "a claim rests on a measurement, and repeating it takes the same materials",
  "deviations.json": "the work follows a claim it replicates or a plan it pre-registered, and doesn't say how it departed from it",
} as const;
export type CalledForFile = keyof typeof MISSING_FILE_REASONS;

export interface OrphanNumber {
  /** The section it's in, as the paper names it. */
  section: string;
  /** Where it starts: the line, from 1, and the column, from 1, counted in code points. */
  line: number;
  column: number;
  /** The number as written, in digits or in words. */
  number: string;
  /** The text around it on its line, with any hidden characters made visible. */
  excerpt: string;
}

/** What a data flag says, by kind. */
export const DATA_FLAG_KINDS = {
  duplicate_rows: "rows repeated exactly, which measurements rarely produce",
  benford: "first digits far from Benford's law, which numbers spanning orders of magnitude follow",
} as const;
export type DataFlagKind = keyof typeof DATA_FLAG_KINDS;

export type DataFlag =
  | {
      kind: "duplicate_rows";
      path: string;
      /** Data rows, not counting the header. */
      rows: number;
      /** Rows that repeat an earlier row exactly. */
      duplicates: number;
      /** The first few repeats: the row, and the earlier row it repeats, counting the header as row 1. */
      examples: { row: number; repeats: number }[];
    }
  | {
      kind: "benford";
      path: string;
      column: string;
      /** Values whose first digit was counted: nonzero numbers. */
      values: number;
      /** Mean absolute deviation of the first-digit proportions from Benford's (Nigrini). */
      mad: number;
      /** The share of values starting with each digit, 1 to 9. */
      observed: number[];
    };

export interface IntegrityFlags {
  orphan_numbers: OrphanNumber[];
  /** paper.md's fixed sections that it doesn't have, in order. */
  missing_sections: string[];
  /** Files the bundle's claims call for that it doesn't have. */
  missing_files: CalledForFile[];
  /** IDs references.json lists that paper.md never cites, in references.json's order. */
  uncited_references: string[];
  /** Reference IDs paper.md cites that references.json doesn't list, in the paper's order. */
  unlisted_citations: string[];
  data: DataFlag[];
  /** Files too large to check, which a verifier checks itself if it matters. */
  skipped: { path: string; bytes: number }[];
}

export const INTEGRITY_LIMITS = {
  /** Flags listed per file; the rest are counted in the totals they come with. */
  orphanNumbersShown: 100,
  /** The largest table checked, in bytes. */
  maxTableBytes: 8 * 1024 * 1024,
  /** Values a column needs before its first digits are compared with Benford's law. */
  benfordMinValues: 500,
  /** How many times larger its largest value must be than its smallest; Benford's law needs the spread. */
  benfordMinSpread: 100,
  /** Nigrini's bound for nonconformity of first digits: above it, a column is flagged. */
  benfordMaxMad: 0.015,
  /** Repeats listed for a table with duplicate rows. */
  duplicateExamples: 5,
} as const;

/** The share of numbers Benford's law expects to start with each digit, 1 to 9. */
export const BENFORD = Array.from({ length: 9 }, (_, i) => Math.log10(1 + 1 / (i + 1)));

/** The files the checks read besides the tables: the paper, and what says which files the claims call for. */
const READ_WHOLE = new Set(["paper.md", "claims.json", "references.json"]);

/** Whether the checks read a file: paper.md, claims.json, references.json, and the tables under data/. Others needn't be loaded. */
export function readByIntegrityChecks(path: string): boolean {
  return READ_WHOLE.has(path) || isCheckedTable(path);
}

/** Whether the checks read a file as a table, which they skip once it's larger than maxTableBytes. */
export function isCheckedTable(path: string): boolean {
  return tableDelimiter(path) !== null;
}

/**
 * Runs every check over a bundle's files: paper.md for orphan numbers and missing sections,
 * claims.json and references.json for the files they call for, and the tables under data/ for
 * forensics. `paths` names every file the bundle has, read or not; without it, the files given
 * are all it has.
 */
export function integrityFlags(files: Iterable<readonly [string, Uint8Array]>, paths?: Iterable<string>): IntegrityFlags {
  const read = [...files];
  const flags: IntegrityFlags = {
    orphan_numbers: [],
    missing_sections: [],
    missing_files: [],
    uncited_references: [],
    unlisted_citations: [],
    data: [],
    skipped: [],
  };
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const texts = new Map<string, string>();
  for (const [path, bytes] of read) {
    if (!readByIntegrityChecks(path)) continue;
    if (isCheckedTable(path) && bytes.length > INTEGRITY_LIMITS.maxTableBytes) {
      flags.skipped.push({ path, bytes: bytes.length });
      continue;
    }
    let text: string;
    try {
      text = decoder.decode(bytes);
    } catch {
      continue;
    }
    if (READ_WHOLE.has(path)) texts.set(path, text);
    else flags.data.push(...tableFlags(path, parseDelimited(text, tableDelimiter(path)!)));
  }
  const paper = texts.get("paper.md");
  if (paper !== undefined) {
    const tree = parseMarkdown(paper);
    flags.orphan_numbers.push(...orphanNumbersIn(paper, tree).slice(0, INTEGRITY_LIMITS.orphanNumbersShown));
    flags.missing_sections.push(...missingSections(paper, tree));
    const listed = listedReferences(texts.get("references.json"));
    if (listed) {
      const cited = citations(tree);
      const known = new Set(listed);
      flags.uncited_references.push(...listed.filter((id) => !cited.includes(id)));
      flags.unlisted_citations.push(...cited.filter((id) => !known.has(id)));
    }
  }
  flags.missing_files.push(
    ...missingFiles(texts.get("claims.json"), texts.get("references.json"), new Set(paths ?? read.map(([path]) => path))),
  );
  return flags;
}

/**
 * The files a bundle's claims call for that it doesn't have. A claims file or references file
 * that doesn't parse calls for nothing here: the bundle check rejects it before anything is
 * flagged.
 */
function missingFiles(claimsText: string | undefined, referencesText: string | undefined, paths: ReadonlySet<string>): CalledForFile[] {
  const claims = claimsText === undefined ? null : ClaimsFileSchema.safeParse(parsed(claimsText));
  if (!claims?.success) return [];
  const references = referencesText === undefined ? null : ReferencesFileSchema.safeParse(parsed(referencesText));
  const calledFor: CalledForFile[] = [];
  if (claims.data.some(needsReplication)) calledFor.push("materials.json");
  if (followed(claims.data, references?.success ? references.data : []).size > 0) calledFor.push("deviations.json");
  return calledFor.filter((path) => !paths.has(path));
}

/**
 * The IDs references.json lists, in its order: none when there is no references.json, and null
 * when it doesn't parse, which the bundle check rejects before anything is flagged.
 */
function listedReferences(text: string | undefined): string[] | null {
  if (text === undefined) return [];
  const references = ReferencesFileSchema.safeParse(parsed(text));
  return references.success ? references.data.map((reference) => reference.id) : null;
}

// --- Citations ---------------------------------------------------------------------------

/**
 * The reference IDs a paper cites, once each, in the order it first cites them: every link
 * whose target is a reference ID, inline (`[text](doi:…)`), automatic (`<claim:…>`), or by
 * reference (`[text][label]` with `[label]: arxiv:…`).
 */
export function citations(tree: MarkdownNode): string[] {
  const cited = new Set<string>();
  const visit = (node: MarkdownNode) => {
    if ((node.type === "link" || node.type === "definition") && node.url !== undefined && ReferenceIdSchema.safeParse(node.url).success) {
      cited.add(node.url);
    }
    node.children?.forEach(visit);
  };
  visit(tree);
  return [...cited];
}

function parsed(text: string): unknown {
  try {
    return parseJson(text);
  } catch {
    return undefined;
  }
}

// --- No orphan numbers -------------------------------------------------------------------

/** Nodes whose text isn't prose a reader takes as a stated result. */
const NOT_PROSE = new Set(["code", "inlineCode", "math", "inlineMath", "html", "image", "imageReference", "definition", "footnoteDefinition"]);

/**
 * A number as written: digits with an optional sign, thousands separators, decimals, and
 * exponent. It's lexing, not reading: whether a number states a result is decided by where it
 * is, not by what the words around it say.
 */
const NUMBER = /[-+−]?(?:\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?|\.\d+)(?:[eE][-+]?\d+)?/gu;
const WORD_CHARACTER = /[\p{L}\p{N}_]/u;

/**
 * Numbers typed into the sections that state results, outside the placeholders that bind
 * them, in digits or spelled out in English words. Skipped: code, math, raw HTML, images, link
 * targets, headings, numbers that are part of a name (C1, R3, GPT-4, ResNet-50), years from
 * 1900 to 2099, which date things rather than measure them, and the single words for zero to
 * nine and first to ninth, which prose spells out to count things.
 */
export function orphanNumbers(markdown: string): OrphanNumber[] {
  return orphanNumbersIn(markdown, parseMarkdown(markdown));
}

function orphanNumbersIn(markdown: string, tree: MarkdownNode): OrphanNumber[] {
  const depth = sectionDepth(tree);
  const claimBearing = new Set(CLAIM_BEARING_SECTIONS.map((name) => name.toLowerCase()));
  const lines = lineStarts(markdown);
  const found: OrphanNumber[] = [];
  let section: string | null = null;

  const visit = (node: MarkdownNode) => {
    if (NOT_PROSE.has(node.type) || node.type === "heading") return;
    // A bare web or mail address shows as itself; its digits are part of the address.
    if (node.type === "link" && node.url !== undefined && bareAddress(node.url) === bareAddress(plainText(node))) return;
    if (node.type === "text" && node.position?.start.offset !== undefined && node.position.end.offset !== undefined) {
      found.push(...numbersIn(markdown, lines, node.position.start.offset, node.position.end.offset, section!));
    }
    node.children?.forEach(visit);
  };
  for (const node of tree.children ?? []) {
    // A heading at the sections' depth starts one; a shallower one, such as a title, ends it.
    if (node.type === "heading" && depth !== null && (node.depth ?? 1) <= depth) {
      section = node.depth === depth ? plainText(node).trim() : null;
      continue;
    }
    if (section !== null && claimBearing.has(section.toLowerCase())) visit(node);
  }
  return found;
}

function numbersIn(text: string, lines: number[], start: number, end: number, section: string): OrphanNumber[] {
  const source = text.slice(start, end);
  // Numbers inside a placeholder are its result's name, not a value.
  const bound = [...source.matchAll(RESULT_PLACEHOLDER)].map((m) => [m.index, m.index + m[0].length] as const);
  const unbound = (at: number) => !bound.some(([from, to]) => at >= from && at < to);
  const numbers: { at: number; number: string }[] = [
    ...[...source.matchAll(NUMBER)]
      .filter((match) => unbound(match.index) && !partOfName(source, match.index, text, start) && !isYear(match[0]))
      .map((match) => ({ at: match.index, number: match[0] })),
    ...spelledNumbers(source)
      .filter((spelled) => !spelled.small && unbound(spelled.start))
      .map((spelled) => ({ at: spelled.start, number: spelled.text })),
  ].sort((a, b) => a.at - b.at);
  return numbers.map(({ at, number }) => {
    const offset = start + at;
    const line = lineIndex(lines, offset);
    return {
      section,
      line: line + 1,
      column: [...text.slice(lines[line], offset)].length + 1,
      number,
      excerpt: lineExcerpt(text, lines, line, offset),
    };
  });
}

/** Whether a number continues a word, as in C1 or R3, or follows one with a hyphen, as in GPT-4. */
function partOfName(source: string, at: number, text: string, start: number): boolean {
  const before = (i: number) => (i >= 0 ? source[i] : text[start + i]) ?? "";
  const previous = before(at - 1);
  if (WORD_CHARACTER.test(previous) || previous === ".") return true;
  // A sign the pattern took may really be a hyphen joining a name to the number.
  const sign = source[at];
  if (sign === "-" || sign === "+" || sign === "−") return WORD_CHARACTER.test(previous);
  return (previous === "-" || previous === "_") && WORD_CHARACTER.test(before(at - 2));
}

/** An address without the scheme a link adds to it, so www.example.org and its link compare equal. */
function bareAddress(address: string): string {
  return address.replace(/^(mailto:|https?:\/\/)/i, "");
}

function isYear(number: string): boolean {
  return /^\d{4}$/.test(number) && Number(number) >= 1900 && Number(number) <= 2099;
}

function lineStarts(text: string): number[] {
  return [0, ...[...text.matchAll(/\r\n|\r|\n/g)].map((m) => m.index + m[0].length)];
}

function lineIndex(lines: number[], offset: number): number {
  let low = 0;
  let high = lines.length - 1;
  while (low < high) {
    const middle = (low + high + 1) >> 1;
    if (lines[middle] <= offset) low = middle;
    else high = middle - 1;
  }
  return low;
}

/** Up to 50 characters either side of a position on its line, with anything hidden made visible. */
function lineExcerpt(text: string, lines: number[], line: number, offset: number): string {
  const lineEnd = (lines[line + 1] ?? text.length + 1) - 1;
  const before = [...text.slice(lines[line], offset)];
  const after = [...text.slice(offset, Math.max(offset, lineEnd))];
  const shown = (before.length > 50 ? "…" : "") + before.slice(-50).join("") + after.slice(0, 50).join("") + (after.length > 50 ? "…" : "");
  return revealHidden(shown.replace(/[\r\n]+$/, "").trim());
}

// --- Data forensics ----------------------------------------------------------------------

/** The delimiter of a table under data/ by its extension, or null for anything else. */
function tableDelimiter(path: string): string | null {
  if (!path.startsWith("data/")) return null;
  const extension = path.slice(path.lastIndexOf(".") + 1).toLowerCase();
  return extension === "csv" ? "," : extension === "tsv" ? "\t" : null;
}

/**
 * Rows of a delimited table, as RFC 4180 reads them: fields in double quotes may hold the
 * delimiter, line breaks, and doubled quotes. Blank lines are left out.
 */
export function parseDelimited(text: string, delimiter: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  const endRow = () => {
    row.push(field);
    if (row.length > 1 || row[0] !== "") rows.push(row);
    row = [];
    field = "";
  };
  for (; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"' && field === "") quoted = true;
    else if (c === delimiter) {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      endRow();
    } else field += c;
  }
  if (field !== "" || row.length > 0) endRow();
  return rows;
}

/** Duplicate rows and Benford's law for a table whose first row names its columns. */
export function tableFlags(path: string, rows: string[][]): DataFlag[] {
  const [header, ...data] = rows;
  if (!header || data.length === 0) return [];
  const flags: DataFlag[] = [];

  const seen = new Map<string, number>();
  const repeats: { row: number; repeats: number }[] = [];
  data.forEach((row, i) => {
    const key = JSON.stringify(row);
    const first = seen.get(key);
    if (first === undefined) seen.set(key, i);
    else repeats.push({ row: i + 2, repeats: first + 2 });
  });
  if (repeats.length > 0) {
    flags.push({
      kind: "duplicate_rows",
      path,
      rows: data.length,
      duplicates: repeats.length,
      examples: repeats.slice(0, INTEGRITY_LIMITS.duplicateExamples),
    });
  }

  header.forEach((name, column) => {
    const cells = data.map((row) => (row[column] ?? "").trim()).filter((cell) => cell !== "");
    const numbers = cells.filter((cell) => Number.isFinite(Number(cell)));
    // A column is numeric when nearly every filled cell is a number.
    if (cells.length === 0 || numbers.length < 0.9 * cells.length) return;
    const nonzero = numbers.filter((cell) => Number(cell) !== 0);
    if (nonzero.length < INTEGRITY_LIMITS.benfordMinValues) return;
    let smallest = Infinity;
    let largest = 0;
    for (const cell of nonzero) {
      const size = Math.abs(Number(cell));
      smallest = Math.min(smallest, size);
      largest = Math.max(largest, size);
    }
    if (largest < INTEGRITY_LIMITS.benfordMinSpread * smallest) return;
    const counts = Array<number>(9).fill(0);
    for (const cell of nonzero) counts[firstDigit(cell) - 1]++;
    const observed = counts.map((count) => count / nonzero.length);
    const mad = observed.reduce((sum, share, i) => sum + Math.abs(share - BENFORD[i]), 0) / 9;
    if (mad > INTEGRITY_LIMITS.benfordMaxMad) {
      flags.push({
        kind: "benford",
        path,
        column: name,
        values: nonzero.length,
        mad: round(mad),
        observed: observed.map(round),
      });
    }
  });
  return flags;
}

/** The first significant digit of a nonzero number as written, read from its digits so rounding can't change it. */
function firstDigit(cell: string): number {
  const mantissa = cell.replace(/^[-+]/, "").split(/[eE]/)[0];
  for (const c of mantissa) if (c >= "1" && c <= "9") return Number(c);
  throw new Error(`No nonzero digit in ${cell}`);
}

const round = (n: number) => Math.round(n * 1e4) / 1e4;
