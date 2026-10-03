import { z } from "zod";
import { LIMITS, MATERIAL_KINDS, type MaterialKind } from "./vocabulary";

// materials.json: what the work was done with, so someone else can get the same things and do
// it again. It is a lab's key resources table, in words any field can use: each entry says what
// it is, what it's called, where it came from, and the identifiers that pin down which one.
// The details that change results (a lot, a passage number, an instrument's settings) belong
// here or in the paper's Methods. Like every file a bundle signs, it is validated and never
// transformed; it isn't a verification input, so fixing an entry changes no claim ID.

/**
 * A Research Resource Identifier: "RRID:" and an authority's own ID, such as RRID:AB_2298772
 * for an antibody or RRID:CVCL_0030 for a cell line. Authorities spell their IDs differently,
 * so the pattern checks only the shape; resolving one is what shows it exists. A plain pattern,
 * so it carries over into the JSON Schema.
 */
export const RridSchema = z
  .string()
  .regex(/^RRID:[A-Za-z][A-Za-z0-9_:.()-]{1,99}$/, "Expected an RRID, such as RRID:AB_2298772 or RRID:CVCL_0030");

const text = (max: number) => z.string().min(1).max(max);

export const MaterialSchema = z.strictObject({
  kind: z.enum(MATERIAL_KINDS),
  /** What it is, as its maker names it, such as "Anti-NeuN antibody, clone A60". */
  name: text(300),
  /** Where it came from: a vendor, a repository, another lab, or this work itself. */
  source: text(200).optional(),
  /** The source's catalog number. */
  catalog: text(100).optional(),
  /** The lot or batch used. */
  lot: text(100).optional(),
  rrid: RridSchema.optional(),
  /** Anything else that pins it down: a passage number, how it was authenticated, an instrument's settings. */
  details: text(1000).optional(),
});
export type Material = z.infer<typeof MaterialSchema>;

export const MaterialsFileSchema = z.array(MaterialSchema).max(LIMITS.maxMaterials);

/** The kinds that RRIDs cover, so an entry of one without an RRID is worth a reviewer's look. */
export const RRID_KINDS: readonly MaterialKind[] = ["antibody", "cell_line", "organism", "plasmid", "software"];

/** materials.json as JSON Schema. */
export function materialsFileJsonSchema() {
  return z.toJSONSchema(MaterialsFileSchema, { io: "input" });
}
