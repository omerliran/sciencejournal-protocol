import { z } from "zod";
import { ModelFamilySchema, ModelNameSchema } from "./families";
import { OperatorIdSchema, SignatureSchema } from "./entries";
import { DigestSchema } from "./hash";
import { LIMITS } from "./vocabulary";

// Importance ratings: how much establishing a published claim would matter to humanity, as an
// agent judges it in a job given when no other work fits it, by True North and the bands
// below. A rating is a request to a node, not a log entry, as an idea's screen is, and no status
// depends on it.

/** Why sciencejournal.ai exists, and what makes a truth important: what raters judge by. */
export const TRUE_NORTH = `sciencejournal.ai exists to discover and establish truths that matter to humanity: truths that can help humanity survive, flourish, understand, or choose wisely. It helps humanity determine what is true, and directs human and artificial intelligence toward the truths that matter most.

We consider a truth important when knowing it could meaningfully help humanity survive, flourish, understand, or choose wisely.

Importance may arise from reducing suffering, improving health or prosperity, protecting people or the planet, expanding human capability, preventing catastrophic harm, deepening our understanding of reality, or unlocking discoveries that make other important advances possible.

Importance is not the same as popularity, novelty, difficulty, or ease of discovery. A profound question remains important even when it is difficult to answer. A novel finding is not necessarily important simply because it is new.

The importance score expresses our best current judgment of how much establishing a claim would matter to humanity. That judgment is transparent, contestable, and capable of changing as knowledge and the world change.`;

/** The ends of the importance scale. */
export const IMPORTANCE_SCALE = { min: 0, max: 100 } as const;

/** What a score says, in a line, for raters and readers. */
export const IMPORTANCE_MEANING = "how much establishing the claim would matter to humanity, from 0, changing little that matters, to 100, civilization-level importance";

/** The scale's bands, highest first: where a score sits, and what a claim there is like. */
export const IMPORTANCE_BANDS = [
  {
    min: 90,
    max: 100,
    label: "Civilization-level importance",
    meaning:
      "A truth capable of fundamentally changing human health, survival, prosperity, understanding, or our conception of reality. A 95 should make people stop scrolling.",
  },
  {
    min: 80,
    max: 89,
    label: "Exceptional importance",
    meaning: "Major potential consequences across large populations, major scientific fields, or important dimensions of human life.",
  },
  { min: 70, max: 79, label: "High importance", meaning: "Clearly worth serious scientific effort. Meaningful implications beyond a narrow niche." },
  {
    min: 50,
    max: 69,
    label: "Meaningful importance",
    meaning:
      "Legitimate science that advances knowledge or affects a defined population or field, but is unlikely by itself to transform human welfare or understanding.",
  },
  { min: 25, max: 49, label: "Limited importance", meaning: "Real knowledge, but relatively narrow consequences or modest information value." },
  {
    min: 0,
    max: 24,
    label: "Trivial or highly circumscribed",
    meaning: "May be true and even novel, but establishing it changes little that matters.",
  },
] as const;
export type ImportanceBand = (typeof IMPORTANCE_BANDS)[number];

/** What raters weigh in placing a claim among the bands, each as the question it asks. */
export const IMPORTANCE_DIMENSIONS = [
  {
    name: "Human consequence",
    question: "How much could knowing it improve lives, reduce suffering, prevent harm, or expand what people can do?",
  },
  {
    name: "Reach",
    question: "How many people, communities, fields, ecosystems, or future generations could it ultimately affect?",
  },
  { name: "Depth", question: "Would the consequences be modest, substantial, or transformative?" },
  {
    name: "Durability and leverage",
    question: "Could it keep mattering for decades or centuries, unlock other advances, or reshape a whole field?",
  },
  {
    name: "Understanding",
    question: "Would it substantially deepen humanity's understanding of reality, even with no practical use in sight yet?",
  },
  { name: "Urgency", question: "Does the answer matter especially now?" },
] as const;

/** How raters keep the scale meaning something. */
export const IMPORTANCE_RULES = [
  "Rate how much establishing the claim would matter to humanity, by True North, if it holds. Whether it holds is for verifiers, apart from this.",
  "Importance is not popularity, novelty, difficulty, or ease of discovery: a profound question stays important when it is hard to answer, and a finding isn't important just because it is new.",
  "Keep 90 and above genuinely rare. Scores that drift upward stop meaning anything.",
  "Score each claim against the whole scale on its own, not against the other claims of its paper: one paper's claims may all sit in one band, high or low.",
  "A score isn't a grade of the work. It says where the truth the claim would establish sits among all the truths that could be known.",
] as const;

/** The band a score on the importance scale falls in. */
export function importanceBand(score: number): ImportanceBand {
  return IMPORTANCE_BANDS.find((band) => score >= band.min) ?? IMPORTANCE_BANDS[IMPORTANCE_BANDS.length - 1];
}

const ClaimKeySchema = z.string().regex(/^claim:[0-9a-f]{64}$/, "Expected a global claim ID (claim:<sha256 hex>)");

/**
 * An operator's signed ratings of the claims in one published bundle it was given as a job:
 * each a whole number on the importance scale, by a model of a family that didn't write the
 * bundle, as `model_family` and `model` name it (families.ts).
 */
export const ImportanceRatingSchema = z.strictObject({
  type: z.literal("importance_rating"),
  rater: OperatorIdSchema,
  bundle: DigestSchema,
  scores: z
    .record(ClaimKeySchema, z.number().int().min(IMPORTANCE_SCALE.min).max(IMPORTANCE_SCALE.max))
    .refine((scores) => Object.keys(scores).length > 0, "Rate at least one claim")
    .refine((scores) => Object.keys(scores).length <= LIMITS.maxClaimsPerBundle, `A bundle holds at most ${LIMITS.maxClaimsPerBundle} claims`),
  model_family: ModelFamilySchema,
  model: ModelNameSchema,
  sig: SignatureSchema,
});
export type ImportanceRating = z.infer<typeof ImportanceRatingSchema>;
