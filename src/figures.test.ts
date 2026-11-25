import { describe, expect, it } from "vitest";
import { bundlePath, embeddedImages, FIGURE_LIMITS, figureType, isFigureFile, paperFigures, shownFigures, type FigureFile } from "./figures";
import { integrityFlags } from "./integrity";
import { parseMarkdown } from "./paper";

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]);
const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 16]);
const WEBP = new Uint8Array([0x52, 0x49, 0x46, 0x46, 1, 2, 3, 4, 0x57, 0x45, 0x42, 0x50, 0x56, 0x50]);
const SVG = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');

describe("figures", () => {
  it("know a PNG, JPEG, or WebP image by its first bytes, and nothing else", () => {
    expect([PNG, JPEG, WEBP].map(figureType)).toEqual(["image/png", "image/jpeg", "image/webp"]);
    expect(figureType(SVG)).toBeNull();
    expect(figureType(new TextEncoder().encode("GIF89a"))).toBeNull();
    expect(figureType(new Uint8Array([0x89, 0x50]))).toBeNull();
    // RIFF alone is a WAV or an AVI as often as a WebP.
    expect(figureType(new Uint8Array([0x52, 0x49, 0x46, 0x46, 1, 2, 3, 4, 0x57, 0x41, 0x56, 0x45]))).toBeNull();
  });

  it("are files under results/ with a raster image's name, as the paper names them", () => {
    expect(["results/fig1.png", "results/plots/a.JPG", "results/b.jpeg", "results/c.webp"].map(isFigureFile)).toEqual([true, true, true, true]);
    expect(["results/fig.svg", "data/fig.png", "fig.png", "results/png"].map(isFigureFile)).toEqual([false, false, false, false]);
    expect(bundlePath("./results/fig1.png")).toBe("results/fig1.png");
    for (const absolute of ["https://example.org/a.png", "data:image/png;base64,AAAA", "//example.org/a.png", "#top", "javascript:alert(1)"]) {
      expect(bundlePath(absolute)).toBeNull();
    }
  });

  it("find every image a paper embeds, inline or by reference, with its caption and line", () => {
    const tree = parseMarkdown(
      ["# Results", "", "As Figure 1 shows: ![Figure 1. Loss by epoch.](results/fig1.png)", "", "![Figure 2. Residuals.][res]", "", "[res]: results/fig2.png", "", "`![not an image](x.png)`"].join("\n"),
    );
    expect(embeddedImages(tree)).toEqual([
      { src: "results/fig1.png", line: 3, caption: "Figure 1. Loss by epoch." },
      { src: "results/fig2.png", line: 5, caption: "Figure 2. Residuals." },
    ]);
  });

  it("show only a raster image the bundle's code wrote, small enough, and say why any other isn't", () => {
    const files: Record<string, FigureFile> = {
      "results/fig1.png": { head: PNG, bytes: 40_000 },
      "results/fig2.jpg": { head: PNG, bytes: 40_000 },
      "results/fig3.png": { head: SVG, bytes: 300 },
      "results/fig4.svg": { head: SVG, bytes: 300 },
      "results/fig5.webp": { head: WEBP, bytes: FIGURE_LIMITS.maxBytes + 1 },
      "data/fig6.png": { head: PNG, bytes: 40_000 },
      "results/fig7.png": { head: PNG, bytes: 40_000 },
    };
    const markdown = [
      "![Figure 1. Shown.](results/fig1.png)",
      "![Figure 2. A PNG named as a JPEG is still an image.](./results/fig2.jpg)",
      "![Figure 3. An SVG named as a PNG.](results/fig3.png)",
      "![Figure 4.](results/fig4.svg)",
      "![Figure 5.](results/fig5.webp)",
      "![Figure 6.](data/fig6.png)",
      "![](results/fig7.png)",
      "![Figure 8.](results/missing.png)",
      "![Figure 9.](https://example.org/fig9.png)",
    ].join("\n\n");
    const figures = paperFigures(parseMarkdown(markdown), (path) => files[path] ?? null);
    expect(figures.map((figure) => [figure.shown, figure.problem])).toEqual([
      [true, null],
      [true, null],
      [false, "format"],
      [false, "format"],
      [false, "too_large"],
      [false, "outside_results"],
      [true, "no_caption"],
      [false, "missing"],
      [false, "external"],
    ]);
    expect([...shownFigures(figures)]).toEqual(["results/fig1.png", "results/fig2.jpg", "results/fig7.png"]);
    expect(shownFigures(undefined).size).toBe(0);
  });

  it("are read by the integrity checks from the bytes given, or from the sizes of files too large to load", () => {
    const encode = (text: string) => new TextEncoder().encode(text);
    const paper = encode("# Results\n\n![Figure 1. Shown.](results/fig1.png)\n\n![Figure 2. Too large.](results/fig2.png)\n");
    const flags = integrityFlags(
      [
        ["paper.md", paper],
        ["results/fig1.png", PNG],
      ],
      ["paper.md", "results/fig1.png", "results/fig2.png"],
      new Map([["results/fig2.png", 9 * 1024 * 1024]]),
    );
    expect(flags.figures).toEqual([
      { src: "results/fig1.png", line: 3, caption: "Figure 1. Shown.", shown: true, problem: null },
      { src: "results/fig2.png", line: 5, caption: "Figure 2. Too large.", shown: false, problem: "too_large" },
    ]);
    // A figure is never read as a table or as text.
    expect(flags.data).toEqual([]);
    expect(flags.skipped).toEqual([]);
  });
});
