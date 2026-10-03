import { parseJson } from "../json";
import { MaterialsFileSchema, RRID_KINDS, type Material } from "../materials";
import type { Deps } from "./context";

// A review's mechanical part for the work's materials: resolve each RRID materials.json gives,
// so the reviewer sees whether it names a real resource, what that resource is called, and any
// problem the record holds against it, such as a cell line known to be contaminated or
// misidentified (the resolver carries Cellosaurus's and ICLAC's records of those). It reports;
// the reviewer judges. A lookup sends only the RRID, nothing else about the work.

/** Where RRIDs resolve. Adding ".json" to a resolver link gets the record as JSON. */
export const RRID_RESOLVER = "https://scicrunch.org/resolver/";

/** The most RRIDs one job looks up, and how many at once. */
const MAX_LOOKUPS = 100;
const AT_ONCE = 4;
const TIMEOUT_MS = 15_000;

export interface RridLookup {
  rrid: string;
  /** resolved, unknown to the resolver, or unreachable (the lookup failed, which says nothing about the RRID). */
  found: "resolved" | "unknown" | "unreachable";
  /** The resource's name in the record, to compare with the name the work gives. */
  name?: string;
  /** How the record says to cite it, with its source and catalog number. */
  citation?: string;
  /** Problems the record holds against the resource itself, such as contamination or misidentification. */
  problems: string[];
  /** Notes about where it comes from, such as a vendor that discontinued it. */
  notes: string[];
}

export interface MaterialsCheck {
  materials: Material[];
  lookups: RridLookup[];
  /** RRIDs past the most one job looks up, left for the reviewer. */
  not_looked_up: string[];
}

/** Reads materials.json from a job's files; null when the bundle has none or it doesn't parse. */
export function readMaterials(bytes: Uint8Array | undefined): Material[] | null {
  if (!bytes) return null;
  try {
    const parsed = MaterialsFileSchema.safeParse(parseJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/** Looks up each distinct RRID the materials give, a few at a time. */
export async function checkMaterials(materials: Material[], deps: Pick<Deps, "fetch">): Promise<MaterialsCheck> {
  const rrids = [...new Set(materials.flatMap((material) => (material.rrid ? [material.rrid] : [])))];
  const lookups: RridLookup[] = [];
  const queue = rrids.slice(0, MAX_LOOKUPS);
  const worker = async () => {
    for (let rrid = queue.shift(); rrid !== undefined; rrid = queue.shift()) lookups.push(await lookUp(rrid, deps));
  };
  await Promise.all(Array.from({ length: AT_ONCE }, worker));
  lookups.sort((a, b) => rrids.indexOf(a.rrid) - rrids.indexOf(b.rrid));
  return { materials, lookups, not_looked_up: rrids.slice(MAX_LOOKUPS) };
}

/** Kinds that RRIDs cover whose entries give none, for the reviewer to ask about. */
export function withoutRrid(materials: Material[]): Material[] {
  return materials.filter((material) => !material.rrid && RRID_KINDS.includes(material.kind));
}

async function lookUp(rrid: string, deps: Pick<Deps, "fetch">): Promise<RridLookup> {
  const none = { rrid, problems: [], notes: [] };
  let response: Response;
  try {
    response = await deps.fetch(`${RRID_RESOLVER}${rrid}.json`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch {
    return { ...none, found: "unreachable" };
  }
  if (response.status === 404) return { ...none, found: "unknown" };
  if (!response.ok) return { ...none, found: "unreachable" };
  let record: unknown;
  try {
    record = await response.json();
  } catch {
    return { ...none, found: "unreachable" };
  }
  const hits = asArray(field(field(record, "hits"), "hits")).map((hit) => field(hit, "_source"));
  // The resolver may return related records too; the one whose RRID matches is this one's.
  const source = hits.find((hit) => text(field(field(hit, "rrid"), "curie"))?.toLowerCase() === rrid.toLowerCase()) ?? hits[0];
  if (source === undefined) return { ...none, found: "unknown" };
  const issues = field(source, "issues");
  return {
    rrid,
    found: "resolved",
    name: text(field(field(source, "item"), "name")),
    citation: text(field(field(source, "rrid"), "properCitation")),
    problems: issueComments(field(issues, "global")),
    notes: issueComments(field(issues, "indirect")),
  };
}

function issueComments(list: unknown): string[] {
  return asArray(list).flatMap((issue) => {
    const said = text(field(issue, "comments")) ?? text(field(issue, "issue"));
    // The resolver writes line breaks as HTML; a brief is plain text.
    return said ? [said.replaceAll("<br/>", " ").replace(/\s+/g, " ").trim()] : [];
  });
}

function field(value: unknown, key: string): unknown {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>)[key] : undefined;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}
