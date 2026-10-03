import { fromMarkdown } from "mdast-util-from-markdown";
import { gfmFromMarkdown } from "mdast-util-gfm";
import { mathFromMarkdown } from "mdast-util-math";
import { gfm } from "micromark-extension-gfm";
import { math } from "micromark-extension-math";

// Hidden content. A model reads every character a file holds, while a person reading the same
// file, or the page rendered from it, sees only what displays. Text that renders as nothing,
// reorders what is around it, or never renders at all can carry instructions aimed at the
// agents that verify a bundle. So the scan goes by what Unicode and Markdown say about the
// text, never by what the text says: characters by their Unicode properties, and Markdown that
// a page wouldn't show by a Markdown parser, with the extensions pages render with (GFM and
// math), so the scan and a rendered page agree about what is HTML.

/** What the scan reports, and what each kind is. */
export const HIDDEN_KINDS = {
  bidi: "bidirectional controls, which reorder how the text around them displays",
  tag: "tag characters, invisible copies of ASCII",
  format: "invisible format characters, such as zero-width spaces and joiners",
  ignorable: "other characters that render as nothing, such as variation selectors outside emoji",
  private_use: "private-use characters, which have no agreed meaning",
  noncharacter: "Unicode noncharacters",
  control: "control characters other than tab and line breaks",
  html: "raw HTML in Markdown, which a rendered page hides or reshapes",
  link_definition: "Markdown link definitions, which never render",
} as const;
export type HiddenKind = keyof typeof HIDDEN_KINDS;

export interface HiddenContent {
  path: string;
  kind: HiddenKind;
  /** Where it starts: the line, from 1, and the column, from 1, counted in code points. */
  line: number;
  column: number;
  /** How many characters the run holds; 1 for Markdown. */
  count: number;
  /** The run's distinct code points, such as "U+200B", for hidden characters. */
  code_points?: string[];
  /** What a run of tag characters spells: each mirrors an ASCII character. */
  decoded?: string;
  /** The text around it on its line, with hidden characters written as <U+200B>. */
  excerpt: string;
}

export interface ScanResult {
  /** Files read as UTF-8 text and scanned. */
  scanned: string[];
  /** Files that aren't UTF-8 text. */
  binary: string[];
  findings: HiddenContent[];
  /** Findings past the limit for each file, counted but not listed. */
  omitted: Record<string, number>;
}

/** Markdown files, which render: paper.md, and any other file the bundle names as Markdown. */
export function isMarkdown(path: string): boolean {
  return /\.(md|markdown)$/i.test(path);
}

/** Scans each UTF-8 text file; anything else is listed as binary. */
export function scanFiles(files: Iterable<readonly [string, Uint8Array]>, limitPerFile = 100): ScanResult {
  const result: ScanResult = { scanned: [], binary: [], findings: [], omitted: {} };
  // The byte order mark is kept, so the scan sees exactly what a reader of the bytes sees.
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  for (const [path, bytes] of files) {
    let text: string;
    try {
      text = decoder.decode(bytes);
    } catch {
      result.binary.push(path);
      continue;
    }
    result.scanned.push(path);
    const found = scanText(path, text);
    result.findings.push(...found.slice(0, limitPerFile));
    if (found.length > limitPerFile) result.omitted[path] = found.length - limitPerFile;
  }
  return result;
}

/** Hidden characters in any text, and Markdown that doesn't render in a Markdown file. */
export function scanText(path: string, text: string): HiddenContent[] {
  const findings = [...hiddenCharacters(path, text), ...(isMarkdown(path) ? unrendered(path, text) : [])];
  return findings.sort((a, b) => a.line - b.line || a.column - b.column);
}

// Everything that could be hidden, narrowed by kindOf.
const CANDIDATES = /[\p{Cc}\p{Cf}\p{Co}\p{Noncharacter_Code_Point}\p{Default_Ignorable_Code_Point}]/gu;
const CANDIDATE = new RegExp(CANDIDATES.source, "u");
const LINE_BREAK = /\r\n|\r|\n/g;
const BYTE_ORDER_MARK = 0xfeff;

function kindOf(char: string, previous: string | undefined, offset: number): HiddenKind | null {
  const code = char.codePointAt(0)!;
  if (char === "\t" || char === "\n" || char === "\r") return null;
  if (/\p{Cc}/u.test(char)) return "control";
  if (/\p{Noncharacter_Code_Point}/u.test(char)) return "noncharacter";
  if (/\p{Co}/u.test(char)) return "private_use";
  // The Tags block mirrors ASCII invisibly, which is how text is smuggled in them.
  if (code >= 0xe0000 && code <= 0xe007f) return "tag";
  if (/\p{Bidi_Control}/u.test(char)) return "bidi";
  // Unicode treats U+FEFF at the very start of a text as a byte order mark, not content.
  if (/\p{Cf}/u.test(char)) return offset === 0 && code === BYTE_ORDER_MARK ? null : "format";
  // What remains is default-ignorable: it renders as nothing. A variation selector after an
  // emoji picks how the emoji displays, the one place such a character is ordinary text.
  if ((code === 0xfe0e || code === 0xfe0f) && previous !== undefined && /\p{Emoji}/u.test(previous)) return null;
  return "ignorable";
}

type Run = { kind: HiddenKind; start: number; end: number; chars: string[] };

function hiddenCharacters(path: string, text: string): HiddenContent[] {
  const lines = lineStarts(text);
  const runs: Run[] = [];
  for (const match of text.matchAll(CANDIDATES)) {
    const offset = match.index;
    const kind = kindOf(match[0], codePointBefore(text, offset), offset);
    if (!kind) continue;
    const last = runs.at(-1);
    if (last && last.kind === kind && last.end === offset) {
      last.end += match[0].length;
      last.chars.push(match[0]);
    } else {
      runs.push({ kind, start: offset, end: offset + match[0].length, chars: [match[0]] });
    }
  }
  return runs.map((run) => {
    const decoded = run.kind === "tag" ? decodeTags(run.chars) : "";
    return {
      path,
      kind: run.kind,
      ...position(text, lines, run.start),
      count: run.chars.length,
      code_points: [...new Set(run.chars.map(codePointName))],
      ...(decoded && { decoded }),
      excerpt: excerpt(text, lines, run.start, run.end),
    };
  });
}

/** Raw HTML and link definitions in Markdown, found by a Markdown parser rather than patterns. */
function unrendered(path: string, text: string): HiddenContent[] {
  const tree: MarkdownNode = fromMarkdown(text, {
    extensions: [gfm(), math()],
    mdastExtensions: [gfmFromMarkdown(), mathFromMarkdown()],
  });
  const lines = lineStarts(text);
  const findings: HiddenContent[] = [];
  const visit = (node: MarkdownNode) => {
    const at = node.position;
    if ((node.type === "html" || node.type === "definition") && at?.start.offset !== undefined) {
      findings.push({
        path,
        kind: node.type === "html" ? "html" : "link_definition",
        ...position(text, lines, at.start.offset),
        count: 1,
        excerpt: visible(text.slice(at.start.offset, at.end.offset).trim().replace(/\s+/g, " "), 120),
      });
    }
    node.children?.forEach(visit);
  };
  visit(tree);
  return findings;
}

/** What the scan needs of a Markdown syntax tree node. */
type MarkdownNode = {
  type: string;
  position?: { start: { offset?: number }; end: { offset?: number } };
  children?: MarkdownNode[];
};

function lineStarts(text: string): number[] {
  return [0, ...[...text.matchAll(LINE_BREAK)].map((m) => m.index + m[0].length)];
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

function position(text: string, lines: number[], offset: number): { line: number; column: number } {
  const line = lineIndex(lines, offset);
  return { line: line + 1, column: [...text.slice(lines[line], offset)].length + 1 };
}

function lineEnd(text: string, lines: number[], offset: number): number {
  const next = lines[lineIndex(lines, offset) + 1];
  if (next === undefined) return text.length;
  // Back up over the break itself.
  return text[next - 2] === "\r" && text[next - 1] === "\n" ? next - 2 : next - 1;
}

const CONTEXT = 24;

function excerpt(text: string, lines: number[], start: number, end: number): string {
  const before = [...text.slice(lines[lineIndex(lines, start)], start)].slice(-CONTEXT).join("");
  const after = [...text.slice(end, Math.max(end, lineEnd(text, lines, end)))].slice(0, CONTEXT).join("");
  const run = [...text.slice(start, end)];
  const shown = run.slice(0, 4).map(escape).join("") + (run.length > 4 ? `<+${run.length - 4} more>` : "");
  return visible(before) + shown + visible(after);
}

/**
 * Text with every character that could hide something written as <U+XXXX>, tabs aside, so
 * text from a bundle can be shown without carrying anything invisible along.
 */
export function revealHidden(text: string): string {
  return visible(text);
}

/** Text with every hidden character written as <U+XXXX>, cut to `max` code points. */
function visible(text: string, max = Infinity): string {
  const chars = [...text];
  const cut = chars.length > max ? chars.slice(0, max) : chars;
  const shown = cut.map((char) => (char !== "\t" && CANDIDATE.test(char) ? escape(char) : char)).join("");
  return cut.length < chars.length ? `${shown}…` : shown;
}

function escape(char: string): string {
  return `<${codePointName(char)}>`;
}

function codePointName(char: string): string {
  return `U+${char.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`;
}

function codePointBefore(text: string, offset: number): string | undefined {
  if (offset === 0) return undefined;
  const low = text.charCodeAt(offset - 1);
  const pair = offset >= 2 && low >= 0xdc00 && low <= 0xdfff;
  return String.fromCodePoint(text.codePointAt(offset - (pair ? 2 : 1))!);
}

function decodeTags(chars: string[]): string {
  return chars
    .map((char) => char.codePointAt(0)! - 0xe0000)
    .filter((ascii) => ascii >= 0x20 && ascii <= 0x7e)
    .map((ascii) => String.fromCharCode(ascii))
    .join("");
}
