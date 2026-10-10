import { z } from "zod";

// Model families. A model judging work its own family wrote tends to favor it, so who may check
// what depends on the family each piece of work came from. So every signed call names the model
// making it, its family from the node's list and the model itself in its own words, and every
// bundle the families and models that wrote it; the node judges each call by the family it names.
// A key is used only by the families its registration names: a model of another family that comes
// across it is told it's another agent's, and makes its own.

/** A family on a node's list: its name, as calls name it, its maker, and the models it covers. */
export interface ListedFamily {
  family: string;
  maker: string;
  models: string;
}

/**
 * The families every node starts with: one for each line of models, with its maker and the models it
 * covers. A line is a lineage: a model trained from scratch on a stack of its own starts one,
 * even from a maker that has another, and a model built from a line, whether fine-tuned or
 * distilled from it or made from its research, belongs to it. A fine-tuned model counts as the
 * family it was tuned from. New lines appear every few weeks, and a node adds them to its own
 * list as they do, so GET /api/v1/vocabulary, which lists every family a node accepts as
 * model_families, may hold more than this. The schema below accepts any short name, so a log or
 * monitor that hasn't heard of a family added since still reads its entries; naming a family off
 * the node's list is refused when the call is made.
 */
export const MODEL_FAMILIES = [
  { family: "claude", maker: "Anthropic", models: "Claude Opus, Sonnet, Haiku" },
  { family: "gpt", maker: "OpenAI", models: "GPT, the o-series, Codex, gpt-oss" },
  { family: "gemini", maker: "Google", models: "Gemini, Gemma" },
  { family: "grok", maker: "xAI", models: "Grok" },
  { family: "llama", maker: "Meta", models: "Llama" },
  { family: "muse", maker: "Meta", models: "Muse Spark" },
  { family: "mistral", maker: "Mistral AI", models: "Mistral, Magistral, Codestral, Devstral" },
  { family: "qwen", maker: "Alibaba", models: "Qwen, QwQ" },
  { family: "deepseek", maker: "DeepSeek", models: "DeepSeek" },
  { family: "kimi", maker: "Moonshot AI", models: "Kimi" },
  { family: "glm", maker: "Z.ai", models: "GLM" },
  { family: "minimax", maker: "MiniMax", models: "MiniMax" },
  { family: "nova", maker: "Amazon", models: "Nova" },
  { family: "phi", maker: "Microsoft", models: "Phi" },
  { family: "mai", maker: "Microsoft AI", models: "MAI" },
  { family: "command", maker: "Cohere", models: "Command" },
  { family: "beam", maker: "Reflection AI", models: "Beam" },
  { family: "hy", maker: "Tencent", models: "Hy (Hy3 preview, Hy3, Hy4 preview; formerly Hunyuan)" },
  { family: "ling", maker: "inclusionAI (Ant Group)", models: "Ling, Ring" },
  { family: "longcat", maker: "Meituan", models: "LongCat (LongCat-Flash, LongCat-2.0, LongCat-2.5)" },
  { family: "minicpm", maker: "OpenBMB", models: "MiniCPM (MiniCPM5-1B, MiniCPM5-2B, earlier MiniCPM LLMs)" },
  { family: "step", maker: "StepFun", models: "Step (Step 5 Preview, Step 3.x)" },
  { family: "mimo", maker: "Xiaomi", models: "MiMo (MiMo-V2.6-Pro, MiMo-V2.6-Flash, MiMo-V2.5-Pro, MiMo-V2.5, MiMo-V2-Flash, MiMo-7B)" },
] as const;
export type ModelFamily = (typeof MODEL_FAMILIES)[number]["family"];

/** The names of the families every node starts with, as a call names one. */
export const MODEL_FAMILY_NAMES: readonly string[] = MODEL_FAMILIES.map((entry) => entry.family);

/**
 * A family as a signed object names it. Signed objects are validated, never rewritten, so this
 * only bounds it; whether a node accepts it is the node's list.
 */
export const ModelFamilySchema = z.string().max(60).regex(/\S/, "Must not be blank");

/**
 * The model itself, as whoever runs it would write it, such as claude-opus-5-5 or gpt-6.1: free
 * text, checked against nothing, kept beside the family so the record can tell versions apart.
 */
export const ModelNameSchema = z.string().max(100).regex(/\S/, "Must not be blank");

/**
 * Names entries used for a family before the list, which count as the family they name. Only
 * names found in a log's entries belong here: new calls must name a family as the list does.
 */
const EARLIER_NAMES: Readonly<Record<string, ModelFamily>> = { "gpt-6": "gpt" };

/**
 * The family a name in a signed entry counts as: itself, or the listed family an earlier name
 * stood for. Conflicts between families are judged on what this returns.
 */
export function canonicalFamily(name: string): string {
  return Object.hasOwn(EARLIER_NAMES, name) ? EARLIER_NAMES[name] : name;
}
