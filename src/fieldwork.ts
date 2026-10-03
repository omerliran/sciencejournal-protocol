import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import { z } from "zod";
import { boundedText, PublicKeySchema, SignatureSchema, signingPayload } from "./entries";
import { canonicalDigest, DigestSchema, sha256Hex, type Digest } from "./hash";
import { FieldSchema } from "./manifest";
import { PasskeyKeySchema, PasskeySignatureSchema } from "./passkey";
import type { Issue } from "./validate";
import { LIMITS, type TaskStatus } from "./vocabulary";

// Fieldwork: agents post tasks for what they can't observe, people observe and sign with
// passkeys, and a task is corroborated once enough independent observations match.

export type TaskId = `task:${string}`;

export const TaskIdSchema = z
  .string()
  .regex(/^task:[0-9a-f]{64}$/, "Expected a task ID (task:<sha256 hex>)")
  .transform((id) => id as TaskId);

export const ObserverIdSchema = z
  .string()
  .regex(/^obs:[1-9][0-9]*$/, "Expected an observer ID (obs:<n>)");

// --- Observers ------------------------------------------------------------------------

/**
 * The log's record of a volunteer's passkey and public name, signed by the log's own key as
 * an invitation is. Creating a passkey signs nothing, so joining proves nothing about who
 * holds the key; the volunteer's first observation does. The node logs this entry just
 * before that observation, so every logged observer key has signed something.
 */
export const ObserverKeyEntrySchema = z.strictObject({
  type: z.literal("observer_key"),
  observer: ObserverIdSchema,
  key: PasskeyKeySchema,
  name: boundedText(60),
  sig: SignatureSchema,
});
export type ObserverKeyEntry = z.infer<typeof ObserverKeyEntrySchema>;

// --- Tasks ----------------------------------------------------------------------------

const MeasurementKeySchema = z
  .string()
  .max(40)
  .regex(/^[a-z][a-z0-9_]*$/, "Expected a lowercase key, such as water_temp_c");

/**
 * A number in units of its last decimal place, or null if it has more than `decimals`
 * places or is too large to count exactly. A JSON number with at most `decimals` places
 * passes exactly, because units / 10^decimals rounds to the same double as the number's
 * own decimal text. Comparing units makes agreement integer arithmetic in every language.
 */
export function toUnits(value: number, decimals: number): number | null {
  const scale = 10 ** decimals;
  const units = Math.round(value * scale);
  return Number.isSafeInteger(units) && units / scale === value ? units : null;
}

const measurement = { key: MeasurementKeySchema, label: boundedText(80) };

const places = (decimals: number) => `${decimals} decimal place${decimals === 1 ? "" : "s"}`;

const NumberMeasurementSchema = z
  .strictObject({
    ...measurement,
    kind: z.literal("number"),
    unit: boundedText(20),
    decimals: z.int().min(0).max(LIMITS.maxDecimals),
    tolerance: z.number().nonnegative(),
    min: z.number(),
    max: z.number(),
  })
  .superRefine((m, ctx) => {
    for (const name of ["tolerance", "min", "max"] as const) {
      if (toUnits(m[name], m.decimals) === null) {
        ctx.addIssue({ code: "custom", path: [name], message: `Must have at most ${places(m.decimals)}` });
      }
    }
    if (m.min > m.max) ctx.addIssue({ code: "custom", path: ["max"], message: "Must be at least min" });
  });

const ChoiceMeasurementSchema = z
  .strictObject({
    ...measurement,
    kind: z.literal("choice"),
    options: z.array(boundedText(60)).min(2).max(20),
  })
  .superRefine((m, ctx) => {
    if (new Set(m.options).size !== m.options.length) {
      ctx.addIssue({ code: "custom", path: ["options"], message: "Options must be distinct" });
    }
  });

/** Free text, such as notes. Kept with the record but never compared. */
const TextMeasurementSchema = z.strictObject({ ...measurement, kind: z.literal("text") });

export const MeasurementSchema = z.discriminatedUnion("kind", [
  NumberMeasurementSchema,
  ChoiceMeasurementSchema,
  TextMeasurementSchema,
]);
export type Measurement = z.infer<typeof MeasurementSchema>;

export const PlaceSchema = z.strictObject({
  name: boundedText(120),
  lat: z.number().min(-90).max(90),
  lon: z.number().min(-180).max(180),
  radius_m: z.int().min(1).max(100_000),
});

const DAY_MS = 24 * 60 * 60 * 1000;

/** What an operator's agent asks people to observe: where, when, what, and how many must match. */
export const TaskEntrySchema = z
  .strictObject({
    type: z.literal("task"),
    operator_key: PublicKeySchema,
    title: boundedText(120),
    instructions: boundedText(4000),
    fields: z.array(FieldSchema).min(1).max(5),
    place: PlaceSchema.optional(),
    opens_at: z.iso.datetime(),
    closes_at: z.iso.datetime(),
    measurements: z.array(MeasurementSchema).min(1).max(LIMITS.maxMeasurementsPerTask),
    replicas: z.int().min(LIMITS.minReplicas).max(LIMITS.maxReplicas),
    max_observations: z.int().min(LIMITS.minReplicas).max(LIMITS.maxObservationsPerTask),
    sig: SignatureSchema,
  })
  .superRefine((task, ctx) => {
    const issue = (path: string, message: string) => ctx.addIssue({ code: "custom", path: [path], message });
    const window = Date.parse(task.closes_at) - Date.parse(task.opens_at);
    if (window <= 0) issue("closes_at", "Must be after opens_at");
    else if (window > LIMITS.maxTaskWindowDays * DAY_MS) {
      issue("closes_at", `A task's window may last at most ${LIMITS.maxTaskWindowDays} days`);
    }
    if (task.max_observations < task.replicas) issue("max_observations", "Must be at least replicas");
    const keys = task.measurements.map((m) => m.key);
    if (new Set(keys).size !== keys.length) issue("measurements", "Measurement keys must be distinct");
    if (task.measurements.every((m) => m.kind === "text")) {
      issue("measurements", "At least one measurement must be a number or a choice, or nothing can be corroborated");
    }
  });
export type TaskEntry = z.infer<typeof TaskEntrySchema>;

/** A task's ID: `task:` and the SHA-256 of its canonical JSON without `sig`. */
export function taskId(task: { type: "task" }): TaskId {
  return `task:${sha256Hex(signingPayload(task))}`;
}

// --- Observations ---------------------------------------------------------------------

/**
 * What an observer signs and the log records: the task, and the digest of a sealed record.
 * The record's values stay with the node until the task closes.
 */
export const ObservationEntrySchema = z.strictObject({
  type: z.literal("observation"),
  task: TaskIdSchema,
  record: DigestSchema,
  sig: PasskeySignatureSchema,
});
export type ObservationEntry = z.infer<typeof ObservationEntrySchema>;

/** The sealed values. The random nonce keeps the digest from revealing them. */
export const ObservationRecordSchema = z.strictObject({
  task: TaskIdSchema,
  values: z.record(MeasurementKeySchema, z.union([z.number(), z.string()])),
  nonce: z.string().regex(/^[0-9a-f]{32}$/, "Expected 16 random bytes in hex"),
});
export type ObservationRecord = z.infer<typeof ObservationRecordSchema>;

/** A new record for `task` with a fresh nonce, ready to digest and sign. */
export function createRecord(task: TaskId, values: Record<string, number | string>): ObservationRecord {
  return { task, values, nonce: bytesToHex(randomBytes(16)) };
}

/** The digest an observation entry commits to: the record's canonical JSON. */
export function recordDigest(record: ObservationRecord): Digest {
  return canonicalDigest(record);
}

/**
 * Checks a record against its task: it names the task, holds a valid value for every number
 * and choice, optionally text, and nothing else. Returns the problems, each at a JSON Pointer.
 */
export function checkRecord(task: TaskEntry, record: ObservationRecord): Issue[] {
  const issues: Issue[] = [];
  const problem = (key: string, message: string) => issues.push({ path: `/values/${key}`, message });
  if (record.task !== taskId(task)) issues.push({ path: "/task", message: "Names a different task" });

  const values = new Map(Object.entries(record.values));
  const keys = new Set(task.measurements.map((m) => m.key));
  for (const key of values.keys()) if (!keys.has(key)) problem(key, "Not one of the task's measurements");

  for (const m of task.measurements) {
    const value = values.get(m.key);
    if (value === undefined) {
      if (m.kind !== "text") problem(m.key, "Required");
      continue;
    }
    switch (m.kind) {
      case "number":
        if (typeof value !== "number" || !Number.isFinite(value)) problem(m.key, "Must be a number");
        else if (value < m.min || value > m.max) problem(m.key, `Must be between ${m.min} and ${m.max}`);
        else if (toUnits(value, m.decimals) === null) {
          problem(m.key, `Must have at most ${places(m.decimals)}`);
        }
        break;
      case "choice":
        if (typeof value !== "string" || !m.options.includes(value)) {
          problem(m.key, `Must be one of: ${m.options.join(", ")}`);
        }
        break;
      case "text":
        if (typeof value !== "string" || !/\S/.test(value) || value.length > LIMITS.maxObservationText) {
          problem(m.key, `Must be text of 1 to ${LIMITS.maxObservationText} characters`);
        }
        break;
    }
  }
  return issues;
}

// --- Corroboration --------------------------------------------------------------------

/** An observation as the log holds it, with its revealed record. */
export interface LoggedObservation {
  /** Its index in the log. */
  index: number;
  /** The log's timestamp for it. */
  timestamp: string;
  observer: string;
  record: ObservationRecord;
}

export type TaskOutcome =
  | { status: Extract<TaskStatus, "open"> }
  | {
      status: Extract<TaskStatus, "corroborated">;
      closed_at: string;
      /** Log indexes of the corroborating set, in log order. */
      corroborating: number[];
      /** The median of each number and the shared value of each choice. */
      values: Record<string, number | string>;
    }
  | { status: Extract<TaskStatus, "unresolved">; closed_at: string };

/**
 * Where a task stands, from its observations and the time. Deterministic: anyone holding the
 * log and the revealed records gets the same outcome. Observations count in log order, only
 * inside the window, only an observer's first, and only with a valid record. The first
 * observation after which some observation matches at least k - 1 others corroborates the
 * task; the earliest such observation and the first k - 1 that match it form the set.
 */
export function resolveTask(
  task: TaskEntry,
  observations: readonly LoggedObservation[],
  now: Date,
): TaskOutcome {
  const opens = Date.parse(task.opens_at);
  const closes = Date.parse(task.closes_at);
  const counted: LoggedObservation[] = [];
  const observers = new Set<string>();

  for (const observation of [...observations].sort((a, b) => a.index - b.index)) {
    const time = Date.parse(observation.timestamp);
    if (time < opens || time >= closes || observers.has(observation.observer)) continue;
    if (checkRecord(task, observation.record).length > 0) continue;
    observers.add(observation.observer);
    counted.push(observation);

    const set = corroboratingSet(task, counted);
    if (set) {
      return {
        status: "corroborated",
        closed_at: observation.timestamp,
        corroborating: set.map((o) => o.index),
        values: consensus(task, set),
      };
    }
    if (counted.length >= task.max_observations) {
      return { status: "unresolved", closed_at: observation.timestamp };
    }
  }
  return now.getTime() >= closes ? { status: "unresolved", closed_at: task.closes_at } : { status: "open" };
}

/** Whether two valid records match: every number within tolerance, every choice equal. */
export function recordsMatch(task: TaskEntry, a: ObservationRecord, b: ObservationRecord): boolean {
  return task.measurements.every((m) => {
    switch (m.kind) {
      case "number":
        return (
          Math.abs(units(a, m.key, m.decimals) - units(b, m.key, m.decimals)) <=
          toUnits(m.tolerance, m.decimals)!
        );
      case "choice":
        return a.values[m.key] === b.values[m.key];
      case "text":
        return true;
    }
  });
}

function corroboratingSet(task: TaskEntry, counted: LoggedObservation[]): LoggedObservation[] | null {
  for (const anchor of counted) {
    const matching = counted.filter((o) => o !== anchor && recordsMatch(task, anchor.record, o.record));
    if (matching.length >= task.replicas - 1) {
      return [anchor, ...matching.slice(0, task.replicas - 1)].sort((a, b) => a.index - b.index);
    }
  }
  return null;
}

function consensus(task: TaskEntry, set: LoggedObservation[]): Record<string, number | string> {
  const values: Record<string, number | string> = {};
  for (const m of task.measurements) {
    if (m.kind === "number") {
      const sorted = set.map((o) => units(o.record, m.key, m.decimals)).sort((a, b) => a - b);
      const middle = Math.floor(sorted.length / 2);
      const median = sorted.length % 2 === 1 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
      values[m.key] = median / 10 ** m.decimals;
    } else if (m.kind === "choice") {
      values[m.key] = set[0].record.values[m.key];
    }
  }
  return values;
}

// Only called on records checkRecord accepted, so the value is a number with valid units.
function units(record: ObservationRecord, key: string, decimals: number): number {
  return toUnits(record.values[key] as number, decimals)!;
}
