import { describe, expect, it } from "vitest";
import { countTokens, missingSections, paperOverLimits, paperSections } from "./paper";
import { LIMITS } from "./vocabulary";

describe("the paper's sections", () => {
  it("are its headings at the shallowest depth that names a fixed section, each running to the next", () => {
    const paper = "# A title\n\nIntro.\n\n## Summary\n\nIt rose.\n\n### Detail\n\nBy a lot.\n\n## Methods\n\nWe measured.\n";
    expect(paperSections(paper)).toEqual([
      { name: "Summary", body: "\n\nIt rose.\n\n### Detail\n\nBy a lot.\n\n" },
      { name: "Methods", body: "\n\nWe measured.\n" },
    ]);
    // A heading shallower than the sections ends the one before it.
    expect(paperSections("## Results\n\nUp.\n\n# Appendix\n\nMore.")).toEqual([{ name: "Results", body: "\n\nUp.\n\n" }]);
    expect(paperSections("No headings at all.")).toEqual([]);
  });

  it("are flagged when one is missing, in order", () => {
    const all = ["Summary", "Claims", "Methods", "Results", "Limitations", "Provenance"];
    expect(missingSections(all.map((name) => `## ${name}\n\nText.`).join("\n\n"))).toEqual([]);
    expect(missingSections(`# Title\n\n${all.map((name) => `## ${name.toUpperCase()}\n`).join("\n")}`)).toEqual([]);
    expect(missingSections("# Summary\n\n## Methods\n\n# Results")).toEqual(["Claims", "Methods", "Limitations", "Provenance"]);
    expect(missingSections("Just prose.")).toEqual(all);
  });
});

describe("token counts", () => {
  it("count words and symbols, or UTF-8 bytes over four, whichever is larger", () => {
    // Five words and a period; 28 bytes would be 7.
    expect(countTokens("The quick brown fox jumped.")).toBe(7);
    expect(countTokens("Loss fell by {{R1.loss_delta}} over five seeds, as expected from the bound.")).toBe(22);
    // Scripts written without spaces count by their bytes: 19 characters of three bytes each.
    expect(countTokens("我们测量了化合物在大气压下的熔点结果为")).toBe(15);
    // Math and code count every symbol.
    expect(countTokens("$\\frac{a}{b}$")).toBe(10);
    expect(countTokens("")).toBe(0);
    expect(countTokens(" \n\t ")).toBe(1);
  });
});

describe("the paper's limits", () => {
  const sentence = "Method X lowers the loss on the held out set by a small margin. ";
  /** Prose of as many sentences as fit in `tokens`, so one sentence more runs over. */
  const prose = (tokens: number) => {
    let text = "";
    while (countTokens(text + sentence) <= tokens) text += sentence;
    return text;
  };

  it("hold the Summary to its limit, counted without its heading", () => {
    const fits = prose(LIMITS.maxSummaryTokens - 2);
    expect(paperOverLimits(`# Summary\n\n${fits}\n\n# Results\n\n${prose(1000)}`)).toEqual([]);
    const over = `# Title\n\n## Summary\n\n${fits}${sentence}\n\n## Results\n\nUp.\n`;
    const [found, ...rest] = paperOverLimits(over);
    expect(rest).toEqual([]);
    expect(found).toMatchObject({ part: "Summary", limit: LIMITS.maxSummaryTokens });
    expect(found.tokens).toBeGreaterThan(LIMITS.maxSummaryTokens);
  });

  it("hold the whole paper to its limit, and a paper with no Summary has no Summary to hold", () => {
    const body = prose(LIMITS.maxPaperTokens - 20);
    expect(paperOverLimits(`# Results\n\n${body}`)).toEqual([]);
    expect(paperOverLimits(`# Results\n\n${body}${sentence}${sentence}`)).toEqual([
      { part: "paper.md", tokens: expect.any(Number), limit: LIMITS.maxPaperTokens },
    ]);
  });
});
