import type { MarkdownNode } from "./paper";

// Figures: the images a paper embeds, `![Figure 1. What it shows.](results/fig1.png)`. A study's
// page shows one in the paper only when it is a raster image the bundle's own code wrote: a
// PNG, JPEG, or WebP file under results/, no larger than maxBytes, whose bytes say it is the
// image its name says. Nothing else loads: an image on the web would tell its host who reads
// the paper, and SVG can carry scripts, so each such image is shown as a link, as before. What a
// figure shows is screened with the rest of the work, since every screener reads every file.

/** What a page shows inline, by the media type it is served as. */
export const FIGURE_TYPES = ["image/png", "image/jpeg", "image/webp"] as const;
export type FigureType = (typeof FIGURE_TYPES)[number];

export const FIGURE_LIMITS = {
  /** The largest figure a page shows inline, in bytes. */
  maxBytes: 2 * 1024 * 1024,
} as const;

/** The extensions a figure's file may have, by the type its bytes must be. */
const EXTENSIONS: Readonly<Record<string, FigureType>> = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  webp: "image/webp",
};

/** Why a figure isn't shown inline, or is flagged though it is. */
export const FIGURE_PROBLEMS = {
  external: "it is on the web, and pages load nothing from elsewhere",
  missing: "the bundle has no file at that path",
  outside_results: "it isn't under results/, where the code that makes the results writes its figures",
  format: "it isn't a PNG, JPEG, or WebP image",
  too_large: `it is larger than ${FIGURE_LIMITS.maxBytes / (1024 * 1024)} MB`,
  no_caption: "it has no caption: give it as the image's alt text",
} as const;
export type FigureProblem = keyof typeof FIGURE_PROBLEMS;

/** The one problem that still shows a figure inline. */
const SHOWN_ANYWAY: ReadonlySet<FigureProblem> = new Set(["no_caption"]);

export interface Figure {
  /** Where the paper points, as written. */
  src: string;
  /** The line of paper.md it is on, from 1. */
  line: number;
  /** Its alt text, which is its caption. */
  caption: string;
  /** Whether the study's page shows it in the paper. */
  shown: boolean;
  problem: FigureProblem | null;
}

/** The bundle path a relative link in the paper names, as pages resolve it, or null for an absolute URL. */
export function bundlePath(src: string): string | null {
  if (/^[a-z][a-z0-9+.-]*:/i.test(src) || src.startsWith("//") || src.startsWith("#")) return null;
  return src.replace(/^\.\//, "");
}

/** Whether a path could hold a figure a page shows: under results/, with a raster image's extension. */
export function isFigureFile(path: string): boolean {
  return path.startsWith("results/") && extensionType(path) !== null;
}

function extensionType(path: string): FigureType | null {
  const dot = path.lastIndexOf(".");
  return dot < 0 ? null : (EXTENSIONS[path.slice(dot + 1).toLowerCase()] ?? null);
}

/** The image type a file's first bytes say it is, or null if it isn't a PNG, JPEG, or WebP image. */
export function figureType(bytes: Uint8Array): FigureType | null {
  const starts = (prefix: readonly number[], at = 0) => prefix.every((byte, i) => bytes[at + i] === byte);
  if (starts([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "image/png";
  if (starts([0xff, 0xd8, 0xff])) return "image/jpeg";
  // "RIFF", four bytes of length, then "WEBP".
  if (starts([0x52, 0x49, 0x46, 0x46]) && starts([0x57, 0x45, 0x42, 0x50], 8)) return "image/webp";
  return null;
}

/** The images a paper embeds, in order: inline (`![alt](src)`) and by reference (`![alt][label]`). */
export function embeddedImages(tree: MarkdownNode): { src: string; line: number; caption: string }[] {
  const definitions = new Map<string, string>();
  const collect = (node: MarkdownNode) => {
    if (node.type === "definition" && node.identifier !== undefined && node.url !== undefined && !definitions.has(node.identifier)) {
      definitions.set(node.identifier, node.url);
    }
    node.children?.forEach(collect);
  };
  collect(tree);
  const images: { src: string; line: number; caption: string }[] = [];
  const visit = (node: MarkdownNode) => {
    const src =
      node.type === "image" ? node.url : node.type === "imageReference" && node.identifier !== undefined ? definitions.get(node.identifier) : undefined;
    if (src !== undefined && src !== "") {
      images.push({ src, line: node.position?.start.line ?? 0, caption: (node.alt ?? "").trim() });
    }
    node.children?.forEach(visit);
  };
  visit(tree);
  return images;
}

/** What a figure's file is, for the checks: its first bytes when they were read, and its size. */
export interface FigureFile {
  head: Uint8Array | null;
  bytes: number;
}

/**
 * Each image the paper embeds, whether its page shows it, and why not. `file` gives what is
 * known of the file at a bundle path, or null when the bundle has none.
 */
export function paperFigures(tree: MarkdownNode, file: (path: string) => FigureFile | null): Figure[] {
  return embeddedImages(tree).map(({ src, line, caption }) => {
    const problem = figureProblem(src, caption, file);
    return { src, line, caption, shown: problem === null || SHOWN_ANYWAY.has(problem), problem };
  });
}

function figureProblem(src: string, caption: string, file: (path: string) => FigureFile | null): FigureProblem | null {
  const path = bundlePath(src);
  if (path === null) return "external";
  const found = file(path);
  if (!found) return "missing";
  if (!path.startsWith("results/")) return "outside_results";
  if (extensionType(path) === null) return "format";
  if (found.bytes > FIGURE_LIMITS.maxBytes) return "too_large";
  // A JPEG named .png is still a raster image: what matters is that the bytes are one.
  if (found.head === null || figureType(found.head) === null) return "format";
  return caption === "" ? "no_caption" : null;
}

/** The bundle paths of the figures a page shows. */
export function shownFigures(figures: readonly Figure[] | undefined): Set<string> {
  return new Set((figures ?? []).filter((figure) => figure.shown).map((figure) => bundlePath(figure.src)!));
}
