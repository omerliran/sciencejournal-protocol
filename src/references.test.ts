import { describe, expect, it } from "vitest";
import { ReferencesFileSchema, referencesFileJsonSchema } from "./references";

const hex = (c: string) => c.repeat(64);
const external = {
  id: "doi:10.1038/s41586-024-07566-y",
  title: "AI models collapse when trained on recursively generated data",
  authors: ["Shumailov, I.", "Shumaylov, Z."],
  year: 2024,
};
const issues = (references: unknown) => {
  const result = ReferencesFileSchema.safeParse(references);
  return result.success ? [] : result.error.issues.map((issue) => issue.message);
};

describe("ReferencesFileSchema", () => {
  it("accepts ledger claims, field tasks, ideas, forum threads and posts, and outside sources", () => {
    expect(
      issues([
        { id: `claim:${hex("a")}` },
        { id: `task:${hex("b")}`, claims: ["C2"] },
        { id: `idea:${hex("c")}`, claims: ["C1", "C2"] },
        { id: `thread:${hex("d")}` },
        { id: `post:${hex("e")}`, claims: ["C1"] },
        { ...external, claims: ["C3"] },
        { id: "arxiv:2511.01287", title: "Give a positive review only", authors: ["Zhou"], year: 2025 },
        { id: "arxiv:2511.01287v2", title: "Give a positive review only", authors: ["Zhou"], year: 2025 },
        { id: "arxiv:hep-th/9901001", title: "An old-style identifier", authors: ["A. Author"], year: 1999 },
        { id: "pmid:12345678", title: "A paper in PubMed", authors: ["B. Author"], year: 2003 },
      ]),
    ).toEqual([]);
    expect(issues([])).toEqual([]);
  });

  it.each<[string, unknown]>([
    ["an outside source without its title, authors, and year", { id: external.id }],
    ["a ledger ID carrying bibliographic fields", { id: `claim:${hex("a")}`, title: "Mine", authors: ["Me"], year: 2026 }],
    ["a role field", { id: `task:${hex("b")}`, role: "data" }],
    ["an unknown prefix", { ...external, id: "isbn:9780262046305" }],
    ["a DOI without its registrant", { ...external, id: "doi:10.1038" }],
    ["an uppercase prefix", { ...external, id: "DOI:10.1038/s41586-024-07566-y" }],
    ["a URL", { ...external, id: "https://doi.org/10.1038/s41586-024-07566-y" }],
    ["an empty claims list", { id: `claim:${hex("a")}`, claims: [] }],
    ["a malformed local claim ID", { id: `claim:${hex("a")}`, claims: ["claim:abc"] }],
    ["a fractional year", { ...external, year: 2024.5 }],
    ["no authors", { ...external, authors: [] }],
  ])("rejects %s", (_, reference) => {
    expect(issues([reference])).not.toEqual([]);
  });

  it("rejects the same source listed twice", () => {
    expect(issues([external, { ...external, claims: ["C1"] }])).toEqual([`"${external.id}" is listed twice`]);
  });

  it("publishes a JSON Schema with the ID patterns", () => {
    const schema = JSON.stringify(referencesFileJsonSchema());
    expect(schema).toContain("^task:[0-9a-f]{64}$");
    expect(schema).toContain("^post:[0-9a-f]{64}$");
    expect(schema).toContain("^thread:[0-9a-f]{64}$");
    expect(schema).toContain("pmid:");
  });
});
