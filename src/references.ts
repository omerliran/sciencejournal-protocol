import { z } from "zod";
import { ClaimIdSchema, LocalClaimIdSchema } from "./claims";
import { TaskIdSchema } from "./fieldwork";
import { PostIdSchema, ThreadIdSchema } from "./forum";
import { IdeaIdSchema } from "./ideas";
import { PreregistrationIdSchema } from "./preregistration";

// references.json: what a bundle cites. Each reference's ID prefix says what it is, so there
// is no role field to contradict it: a claim on the ledger, a field task whose records the
// work uses as data, an idea from people that the work takes up, the plan it registered, a
// forum thread or post the work builds on, or a source outside the ledger. Strict objects,
// validated and never transformed, like everything a bundle signs.

/** The bundle's claims, by local ID, that a reference supports. Absent: the whole bundle. */
const SupportsSchema = z.array(LocalClaimIdSchema).min(1).max(30).optional();

const LedgerReferenceSchema = z.strictObject({
  id: z.union([ClaimIdSchema, TaskIdSchema, IdeaIdSchema, PreregistrationIdSchema, ThreadIdSchema, PostIdSchema]),
  claims: SupportsSchema,
});

// A DOI, a new- or old-style arXiv identifier with an optional version, or a PubMed ID. Plain
// patterns, so they carry over into the JSON Schema.
const ExternalIdSchema = z
  .string()
  .regex(
    /^(doi:10\.[0-9]{4,9}\/\S+|arxiv:([0-9]{4}\.[0-9]{4,5}|[a-z-]+(\.[A-Z]{2})?\/[0-9]{7})(v[1-9][0-9]*)?|pmid:[1-9][0-9]{0,9})$/,
    "Expected doi:10.<registrant>/<suffix>, arxiv:<id>, or pmid:<number>",
  );

/** A source outside the ledger, with what the node checks it against. */
const ExternalReferenceSchema = z.strictObject({
  id: ExternalIdSchema,
  title: z.string().min(1).max(500),
  authors: z.array(z.string().min(1).max(200)).min(1).max(100),
  year: z.number().int().min(1).max(9999),
  claims: SupportsSchema,
});

export const ReferenceSchema = z.union([LedgerReferenceSchema, ExternalReferenceSchema]);
export type Reference = z.infer<typeof ReferenceSchema>;
export type ExternalReference = z.infer<typeof ExternalReferenceSchema>;

/** Whether a reference names a source outside the ledger: a DOI, an arXiv ID, or a PubMed ID. */
export function isExternalReference(reference: Pick<Reference, "id">): boolean {
  return ExternalIdSchema.safeParse(reference.id).success;
}

/** Any ID a reference can name: on the ledger or outside it. */
export const ReferenceIdSchema = z.union([LedgerReferenceSchema.shape.id, ExternalIdSchema]);

export const ReferencesFileSchema = z
  .array(ReferenceSchema)
  .max(1000)
  .superRefine((references, ctx) => {
    const seen = new Set<string>();
    references.forEach((reference, i) => {
      if (seen.has(reference.id)) {
        ctx.addIssue({ code: "custom", message: `"${reference.id}" is listed twice`, path: [i, "id"] });
      }
      seen.add(reference.id);
    });
  });

/** references.json as JSON Schema. Whether `claims` name real claims needs claims.json too. */
export function referencesFileJsonSchema() {
  return z.toJSONSchema(ReferencesFileSchema, { io: "input" });
}
