import { fromMarkdown } from "mdast-util-from-markdown";
import { gfmFromMarkdown } from "mdast-util-gfm";
import { mathFromMarkdown } from "mdast-util-math";
import { gfm } from "micromark-extension-gfm";
import { math } from "micromark-extension-math";
import { LIMITS } from "./vocabulary";

// paper.md: the prose that explains a bundle's claims. Its fixed sections, where each one sits,
// and the limits that keep reading it bounded, since every verifier of the bundle reads it.

/** The sections paper.md has, by their fixed names, in order. */
export const PAPER_SECTIONS = ["Summary", "Claims", "Methods", "Results", "Limitations", "Provenance"] as const;

/** What the checks need of a Markdown syntax tree node. */
export type MarkdownNode = {
  type: string;
  depth?: number;
  url?: string;
  value?: string;
  position?: { start: { offset?: number }; end: { offset?: number } };
  children?: MarkdownNode[];
};

/** The paper as pages render it: GitHub-flavored Markdown with math. */
export function parseMarkdown(markdown: string): MarkdownNode {
  return fromMarkdown(markdown, {
    extensions: [gfm(), math()],
    mdastExtensions: [gfmFromMarkdown(), mathFromMarkdown()],
  }) as MarkdownNode;
}

export function plainText(node: MarkdownNode): string {
  if (node.value !== undefined && (node.type === "text" || node.type === "inlineCode")) return node.value;
  return (node.children ?? []).map(plainText).join("");
}

/**
 * The heading depth the paper's sections are at: the shallowest that names one of the fixed
 * sections, so a title above them is fine, whatever depth the paper starts at. Null when no
 * heading names one.
 */
export function sectionDepth(tree: MarkdownNode): number | null {
  const fixed = new Set(PAPER_SECTIONS.map((name) => name.toLowerCase()));
  const depths = (tree.children ?? [])
    .filter((node) => node.type === "heading" && fixed.has(plainText(node).trim().toLowerCase()))
    .map((node) => node.depth ?? 1);
  return depths.length === 0 ? null : Math.min(...depths);
}

/**
 * The paper's sections, in order, each with its name as written and its body: the text from
 * its heading to the next heading at its depth or shallower, or to the end.
 */
export function paperSections(markdown: string, tree = parseMarkdown(markdown)): { name: string; body: string }[] {
  const depth = sectionDepth(tree);
  if (depth === null) return [];
  const bounds = (tree.children ?? []).filter((node) => node.type === "heading" && (node.depth ?? 1) <= depth);
  return bounds.flatMap((heading, i) =>
    heading.depth === depth
      ? [
          {
            name: plainText(heading).trim(),
            body: markdown.slice(heading.position?.end.offset ?? 0, bounds[i + 1]?.position?.start.offset ?? markdown.length),
          },
        ]
      : [],
  );
}

/** paper.md's fixed sections that it doesn't have, in order. */
export function missingSections(markdown: string, tree = parseMarkdown(markdown)): string[] {
  const present = new Set(paperSections(markdown, tree).map((section) => section.name.toLowerCase()));
  return PAPER_SECTIONS.filter((name) => !present.has(name.toLowerCase()));
}

// --- Length ----------------------------------------------------------------------------

/** A run of letters, marks, and digits, or any single character that is none of those and isn't white space. */
const WORD_OR_SYMBOL = /[\p{L}\p{M}\p{N}]+|[^\s\p{L}\p{M}\p{N}]/gu;

/**
 * A text's length in tokens, counted the same way by every implementation, since each model's
 * tokenizer differs: the larger of its words and symbols (each run of letters, marks, and
 * digits, and each other character that isn't white space) and its UTF-8 bytes divided by
 * four, rounded up. Words undercount scripts written without spaces between words, and bytes
 * undercount code and math; the larger of the two stays close to what models count for both.
 */
export function countTokens(text: string): number {
  const words = text.match(WORD_OR_SYMBOL)?.length ?? 0;
  return Math.max(words, Math.ceil(new TextEncoder().encode(text).length / 4));
}

/** Where a paper runs over a limit: its Summary, or the whole paper. */
export interface PaperOverLimit {
  part: "Summary" | "paper.md";
  tokens: number;
  limit: number;
}

/**
 * Where a paper runs over the limits that keep reading it bounded: a Summary over
 * LIMITS.maxSummaryTokens, counted without its heading, and a paper over LIMITS.maxPaperTokens.
 */
export function paperOverLimits(markdown: string, tree = parseMarkdown(markdown)): PaperOverLimit[] {
  const over: PaperOverLimit[] = [];
  for (const section of paperSections(markdown, tree)) {
    if (section.name.toLowerCase() !== "summary") continue;
    const tokens = countTokens(section.body);
    if (tokens > LIMITS.maxSummaryTokens) over.push({ part: "Summary", tokens, limit: LIMITS.maxSummaryTokens });
  }
  const tokens = countTokens(markdown);
  if (tokens > LIMITS.maxPaperTokens) over.push({ part: "paper.md", tokens, limit: LIMITS.maxPaperTokens });
  return over;
}

/** What a node says about a paper over a limit. */
export function overLimitMessage({ part, tokens, limit }: PaperOverLimit): string {
  const count = (n: number) => n.toLocaleString("en-US");
  return part === "Summary"
    ? `The Summary is ${count(tokens)} tokens; at most ${count(limit)}. Say what the work found, and leave the rest to the other sections`
    : `paper.md is ${count(tokens)} tokens; at most ${count(limit)}. Split larger work into linked bundles`;
}
