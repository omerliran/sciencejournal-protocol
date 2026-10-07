import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { expect, it } from "vitest";
import type { Material } from "../materials";
import { checkMaterials, readMaterials, RRID_RESOLVER } from "./materials";
import { selfCheck } from "./self-check";

/** The resolver's answers, by RRID, as its JSON gives them; anything else is a 404, and "down" fails. */
function resolver(records: Record<string, unknown>) {
  const asked: string[] = [];
  const fetch = (async (url: string) => {
    const rrid = decodeURIComponent(url.slice(RRID_RESOLVER.length).replace(/\.json$/, ""));
    asked.push(rrid);
    if (rrid === "RRID:SCR_000000") throw new TypeError("fetch failed");
    if (!(rrid in records)) return new Response(JSON.stringify({ hits: { total: 0, hits: [] } }), { status: 404 });
    return new Response(JSON.stringify(records[rrid]), { status: 200 });
  }) as typeof globalThis.fetch;
  return { fetch, asked };
}

const hit = (curie: string, name: string, issues?: unknown) => ({
  _source: { item: { name }, rrid: { curie, properCitation: `(Example Cat# 1, ${curie})` }, ...(issues !== undefined && { issues }) },
});

it("resolves each RRID once, and reports what the record names and holds against it", async () => {
  const { fetch, asked } = resolver({
    "RRID:CVCL_1906": {
      hits: {
        total: 2,
        hits: [
          hit("RRID:CVCL_0030", "HeLa"),
          hit("RRID:CVCL_1906", "HEp-2", {
            global: [{ issue: "Contaminated", comments: "Problematic cell line:  Contaminated.\n<br/><br/>Registration: ICLAC-00007." }],
            indirect: [{ issue: "Discontinued", comments: "Discontinued: ATCC; CRL-7923" }],
          }),
        ],
      },
    },
  });
  const materials: Material[] = [
    { kind: "cell_line", name: "HEp-2", rrid: "RRID:CVCL_1906" },
    { kind: "cell_line", name: "HEp-2 again", rrid: "RRID:CVCL_1906" },
    { kind: "antibody", name: "Anti-X", rrid: "RRID:AB_0000001" },
    { kind: "software", name: "An analysis tool", rrid: "RRID:SCR_000000" },
    { kind: "chemical", name: "Water" },
  ];
  const check = await checkMaterials(materials, { fetch });
  expect(asked.sort()).toEqual(["RRID:AB_0000001", "RRID:CVCL_1906", "RRID:SCR_000000"]);
  expect(check.lookups).toEqual([
    {
      rrid: "RRID:CVCL_1906",
      found: "resolved",
      name: "HEp-2",
      citation: "(Example Cat# 1, RRID:CVCL_1906)",
      problems: ["Problematic cell line: Contaminated. Registration: ICLAC-00007."],
      notes: ["Discontinued: ATCC; CRL-7923"],
    },
    { rrid: "RRID:AB_0000001", found: "unknown", problems: [], notes: [] },
    { rrid: "RRID:SCR_000000", found: "unreachable", problems: [], notes: [] },
  ]);
  expect(check.not_looked_up).toEqual([]);
});

it("reads materials.json from a job's files, and nothing that doesn't fit its schema", () => {
  const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  expect(readMaterials(encode([{ kind: "kit", name: "Assay kit" }]))).toEqual([{ kind: "kit", name: "Assay kit" }]);
  expect(readMaterials(encode([{ kind: "reagent", name: "Water" }]))).toBeNull();
  expect(readMaterials(new Uint8Array([0xff]))).toBeNull();
  expect(readMaterials(undefined)).toBeNull();
});

it("tells an author, before it submits, what verifiers will see about repeating the work", async () => {
  const root = join(await mkdtemp(join(tmpdir(), "sj-materials-")), "bundle");
  const files: Record<string, unknown> = {
    "manifest.json": {
      operator_key_digest: `sha256:${"a".repeat(64)}`,
      fields: ["cell-biology"],
      license: { prose: "CC-BY-4.0" },
      compute: { minutes: 1, gpu: false },
      replication: { needs: [{ kind: "lab", hours: 20 }], days: 7 },
    },
    "paper.md": "# Summary\n\nViability fell.\n\n# Results\n\nIt fell.\n",
    "claims.json": [
      {
        local_id: "M1",
        type: "empirical",
        core: true,
        statement: "Drug D lowers HEp-2 viability.",
        evidence: [{ result: "R1.viability", measured: "data/plate.csv", tolerance: 0.05 }],
        depends_on: [],
        confidence: 0.7,
      },
    ],
    "data/plate.csv": "well,luminescence\nA1,10412\n",
    "results/R1.json": { viability: 0.62 },
    "materials.json": [{ kind: "cell_line", name: "HEp-2", rrid: "RRID:CVCL_1906" }],
  };
  for (const [path, value] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), typeof value === "string" ? value : JSON.stringify(value));
  }
  const { fetch } = resolver({
    "RRID:CVCL_1906": { hits: { hits: [hit("RRID:CVCL_1906", "HEp-2", { global: [{ comments: "Problematic cell line: Contaminated." }] })] } },
  });
  const lines: string[] = [];
  const deps = { fetch, now: () => new Date(), print: (line: string) => lines.push(line), env: {}, home: tmpdir(), invocation: "sj-harness", findEngine: async () => null };

  // A measurement alone has nothing to re-run, so the check passes, and says what it found.
  expect(await selfCheck(root, {}, deps)).toBe(0);
  expect(lines).toContain("paper.md has no Claims, Methods, Discussion, Limitations, Provenance sections; verifiers will see that flagged.");
  expect(lines).toContain("RRID:CVCL_1906 (HEp-2): Problematic cell line: Contaminated.");
});
