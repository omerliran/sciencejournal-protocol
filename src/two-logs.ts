import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { z } from "zod";
import { canonicalJson } from "./canonical";
import { entryDigest, matchesLeafEntry, PublicKeySchema } from "./entries";
import { DigestSchema } from "./hash";
import { leafBytes, logId, TreeHeadSchema, type LogLeaf, type TreeHead } from "./leaves";
import { extendRange, leafHash, rangeRoot, verifyConsistency } from "./merkle";
import {
  checkGrowth,
  exitStatus,
  fetchProof,
  headProblem,
  MonitorError,
  readLogEntries,
  readLogInfo,
  type LogSource,
  type Problem,
} from "./monitor";

// Two logs that keep one record: the first copies every entry it logs to the second, and
// anyone may submit to the second directly, as when the first won't log an entry. This compares
// them. Each log is read the way a monitor reads it (its pinned key, its signed heads, a proof
// that each head extends the last, its leaves hashing to the signed root), and each entry is
// known by the digest of the entry as signed, recomputed here from what each log serves. An
// entry on one log and not the other a day after it was logged is reported: on the first and
// not the second, the second lags or refuses it; on the second and not the first, the first
// may be censoring it. The same signed entry with different leaves is reported, and so is a
// copy the first log says the second holds where the second holds something else.

/** How long an entry may wait on one log before the other must hold it too: the merge window. */
export const MERGE_WINDOW_MS = 24 * 60 * 60 * 1000;

/** What comparing two logs can find, beyond what reading either log finds. */
export const COMPARISON_PROBLEMS = {
  not_on_second: "An entry on the first log is missing from the second a day after it was logged: the second lags behind or refuses it",
  not_on_first: "An entry on the second log is missing from the first a day after it was logged there: the first may be censoring it",
  copies_differ: "The two logs hold the same signed entry in leaves that differ in something both state",
  false_copy: "The first log says the second holds one of its entries where the second holds another, or nothing",
} as const;
export type ComparisonCheck = keyof typeof COMPARISON_PROBLEMS;

export interface ComparisonProblem extends Omit<Problem, "check"> {
  check: Problem["check"] | ComparisonCheck;
  /** The log the problem's index is on. */
  log?: string;
}

const HexHashSchema = z.string().regex(/^[0-9a-f]{64}$/, "Expected 32 bytes in hex");
const JsonObjectSchema = z.record(z.string(), z.unknown());

/** How far one log has been read, and what verified it. */
const LogReadSchema = z.strictObject({
  log: z.string(),
  public_key: PublicKeySchema,
  /** The last tree head read and verified. */
  head: TreeHeadSchema.nullable(),
  /** Entries [0, size) have been read. */
  size: z.number().int().nonnegative(),
  /** The compact range over the leaves read, largest subtree first, in hex. */
  range: z.array(HexHashSchema),
});
type LogRead = z.infer<typeof LogReadSchema>;

/** An entry read on one log and not yet found on the other. */
const WaitingSchema = z.strictObject({
  index: z.number().int().nonnegative(),
  timestamp: z.iso.datetime(),
  leaf: JsonObjectSchema,
});

const FindingSchema = z.object({
  check: z.string(),
  index: z.number().int().nonnegative().optional(),
  log: z.string().optional(),
  reason: z.string(),
  evidence: z.unknown().optional(),
});

/** What comparing two logs keeps between runs. */
export const ComparisonStateSchema = z.strictObject({
  logs: z.tuple([LogReadSchema, LogReadSchema]),
  /** On each log, entries the other doesn't hold yet, by the digest of the entry as signed. */
  waiting: z.tuple([z.record(DigestSchema, WaitingSchema), z.record(DigestSchema, WaitingSchema)]),
  /** Problems found before that stay true, such as two leaves that differ: reported on every run. */
  findings: z.array(FindingSchema),
});
export type ComparisonState = z.infer<typeof ComparisonStateSchema>;

export interface ComparisonOptions {
  /** The most new entries to read from each log in this run. All of them by default. */
  maxEntries?: number;
  /** How many signed entries to fetch at once. */
  concurrency?: number;
  /** The time now, in milliseconds since the epoch. */
  now?: number;
}

export interface LogsComparison {
  /** Each log's ID, once known. */
  logs: [string | null, string | null];
  /** The tree head read from each. */
  heads: [TreeHead | null, TreeHead | null];
  /** The entries read from each this run, [from, to). */
  read: [{ from: number; to: number }, { from: number; to: number }];
  /** Entries found on both logs this run. */
  matched: number;
  /** On each log, entries the other doesn't hold yet but may, as the merge window hasn't passed. */
  waiting: [number, number];
  problems: ComparisonProblem[];
  unchecked: string[];
  error: string | null;
}

export interface ComparisonResult {
  report: LogsComparison;
  /** The state to keep for the next run; null when reading either log found a problem or failed. */
  state: ComparisonState | null;
}

/** An entry read this run: where it is, its leaf, and the digest of the entry as signed. */
interface Read {
  index: number;
  leaf: Record<string, unknown> & { timestamp: string; entry: { type: string } };
  digest: string;
}

const LeafShapeSchema = z.looseObject({ timestamp: z.iso.datetime(), entry: z.looseObject({ type: z.string() }) });

/** A receipt's `copies`: where the first log says other logs hold the entry. Only these fields are read. */
const CopiesSchema = z.looseObject({
  copies: z.array(z.looseObject({ log: z.string(), index: z.number().int().nonnegative() })).optional(),
});

/**
 * Compares two logs from where the last comparison stopped: `first` copies its entries to
 * `second`. The state it returns replaces the saved one only when both logs read without a
 * problem, so a log that misbehaved is read again from the last good point.
 */
export async function compareLogs(
  first: LogSource,
  second: LogSource,
  saved: ComparisonState | null,
  options: ComparisonOptions = {},
): Promise<ComparisonResult> {
  const report: LogsComparison = {
    logs: [saved?.logs[0].log ?? null, saved?.logs[1].log ?? null],
    heads: [null, null],
    read: [
      { from: saved?.logs[0].size ?? 0, to: saved?.logs[0].size ?? 0 },
      { from: saved?.logs[1].size ?? 0, to: saved?.logs[1].size ?? 0 },
    ],
    matched: 0,
    waiting: [0, 0],
    problems: [],
    unchecked: [],
    error: null,
  };
  let state: ComparisonState | null = null;
  try {
    state = await run([first, second], saved, options, report);
  } catch (error) {
    report.error = error instanceof Error ? error.message : String(error);
    state = null;
  }
  return { report, state: report.error === null ? state : null };
}

async function run(
  sources: [LogSource, LogSource],
  saved: ComparisonState | null,
  options: ComparisonOptions,
  report: LogsComparison,
): Promise<ComparisonState | null> {
  const now = options.now ?? Date.now();
  const sides = [0, 1] as const;
  const reads: [{ read: LogRead; entries: Read[] } | null, { read: LogRead; entries: Read[] } | null] = [null, null];
  for (const side of sides) {
    reads[side] = await readLog(sources[side], saved?.logs[side] ?? null, side, options, report);
    if (!reads[side]) return null;
  }
  const [a, b] = reads as [{ read: LogRead; entries: Read[] }, { read: LogRead; entries: Read[] }];
  if (a.read.log === b.read.log) throw new MonitorError(`Both nodes serve ${a.read.log}: compare two different logs`);
  const names = [a.read.log, b.read.log] as const;

  const waiting = [new Map(Object.entries(saved?.waiting[0] ?? {})), new Map(Object.entries(saved?.waiting[1] ?? {}))] as const;
  const findings = [...(saved?.findings ?? [])] as ComparisonProblem[];
  const found = (problem: ComparisonProblem) => findings.push(problem);

  // Each entry read this run either finds its copy waiting on the other log or waits for one.
  for (const side of sides) {
    const other = side === 0 ? 1 : 0;
    for (const entry of reads[side]!.entries) {
      const copy = waiting[other].get(entry.digest);
      if (copy) {
        waiting[other].delete(entry.digest);
        report.matched++;
        const [onFirst, onSecond]: { index: number; leaf: Record<string, unknown> }[] = side === 0 ? [entry, copy] : [copy, entry];
        const differences = leafDifferences(onFirst.leaf, onSecond.leaf);
        if (differences.length > 0) {
          found({
            check: "copies_differ",
            log: names[0],
            index: onFirst.index,
            reason: `Entry ${onFirst.index} on ${names[0]} and entry ${onSecond.index} on ${names[1]} are the same signed entry, but their leaves differ in ${differences.join(", ")}`,
            evidence: { first: { log: names[0], index: onFirst.index, leaf: onFirst.leaf }, second: { log: names[1], index: onSecond.index, leaf: onSecond.leaf } },
          });
        }
        // Published counts bundle entries by the copies the first log names, so those are checked.
        if ((onFirst.leaf.entry as { type: string }).type === "bundle") {
          const claimed = await claimedCopy(sources[0], onFirst.index, names[1]);
          if (claimed !== null && claimed !== onSecond.index) {
            found(falseCopy(names, onFirst.index, claimed, `the second holds it at ${onSecond.index}`));
          }
        }
        continue;
      }
      if (waiting[side].has(entry.digest)) {
        report.unchecked.push(`Entry ${entry.index} on ${names[side]} is an entry it logged before, at ${waiting[side].get(entry.digest)!.index}; only the first is compared.`);
        continue;
      }
      waiting[side].set(entry.digest, { index: entry.index, timestamp: entry.leaf.timestamp, leaf: entry.leaf });
    }
  }

  const problems: ComparisonProblem[] = [...findings];
  // An entry is missing from a log only once that log has been read to its head.
  const caughtUp = sides.map((side) => reads[side]!.read.size === (reads[side]!.read.head?.size ?? 0));
  for (const side of sides) {
    const other = side === 0 ? 1 : 0;
    for (const [digest, entry] of waiting[side]) {
      const overdue = Date.parse(entry.timestamp) + MERGE_WINDOW_MS < now;
      if (!overdue || !caughtUp[other]) {
        report.waiting[side]++;
        continue;
      }
      const reason =
        side === 0
          ? `Entry ${entry.index} on ${names[0]}, logged ${entry.timestamp}, isn't on ${names[1]}`
          : `Entry ${entry.index} on ${names[1]}, logged there ${entry.timestamp}, isn't on ${names[0]}`;
      problems.push({ check: side === 0 ? "not_on_second" : "not_on_first", log: names[side], index: entry.index, reason, evidence: { digest, leaf: entry.leaf } });
      if (side === 0) {
        const claimed = await claimedCopy(sources[0], entry.index, names[1]);
        if (claimed !== null) problems.push(falseCopy(names, entry.index, claimed, "the second holds no such entry"));
      }
    }
  }
  if (!caughtUp[0] || !caughtUp[1]) {
    report.unchecked.push("A log wasn't read to its head this run, so entries missing from it weren't reported yet.");
  }
  report.problems.push(...problems);
  return {
    logs: [a.read, b.read],
    waiting: [Object.fromEntries(waiting[0]), Object.fromEntries(waiting[1])],
    findings: findings as ComparisonState["findings"],
  };
}

/**
 * Reads one log from where the last comparison stopped: pins its key on first sight, checks its
 * head and that the head extends the last one read, and reads its new entries, each with the
 * digest of its entry as signed. Null when the log misbehaved, which `report` says.
 */
async function readLog(
  source: LogSource,
  saved: LogRead | null,
  side: 0 | 1,
  options: ComparisonOptions,
  report: LogsComparison,
): Promise<{ read: LogRead; entries: Read[] } | null> {
  const info = await readLogInfo(source);
  report.logs[side] = info.log;
  const problem = (p: Problem) => report.problems.push({ ...p, log: info.log });
  if (info.log !== logId(info.public_key)) {
    problem({ check: "log_id", reason: `The node calls its log ${info.log}, but its key's ID is ${logId(info.public_key)}` });
    return null;
  }
  const key = PublicKeySchema.safeParse(info.public_key);
  if (!key.success) throw new MonitorError("The node's public key isn't a key this protocol uses");
  if (saved && (saved.log !== info.log || saved.public_key !== info.public_key)) {
    problem({
      check: "log_changed",
      reason: `The node now serves ${info.log}, but this comparison pinned ${saved.log} there. Start a new comparison, with a new state file, only if you trust the change.`,
    });
    return null;
  }
  const read: LogRead = saved ? { ...saved, range: [...saved.range] } : { log: info.log, public_key: key.data, head: null, size: 0, range: [] };
  if (info.tree_head === null) {
    if (read.head) {
      problem({ check: "shrank", reason: `The node says the log is empty, but it signed a tree of ${read.head.size} entries` });
      return null;
    }
    return { read, entries: [] };
  }
  const parsed = TreeHeadSchema.safeParse(info.tree_head);
  if (!parsed.success) throw new MonitorError("The node's answer to GET /api/v1/log has a tree head that isn't one");
  const head = parsed.data;
  report.heads[side] = head;
  const invalid = headProblem(head, read.log, read.public_key);
  if (invalid) {
    problem(invalid);
    return null;
  }
  if (read.head) {
    const growth = await checkGrowth(read.head, head, read.public_key, source);
    if (growth.length > 0) {
      growth.forEach(problem);
      return null;
    }
  }

  const from = read.size;
  const to = Math.min(head.size, from + Math.max(0, options.maxEntries ?? Infinity));
  const range = read.range.map(hexToBytes);
  const entries: Read[] = [];
  let problems = 0;
  await readLogEntries(source, from, to, options.concurrency ?? 8, (index, leaf, servedHash, signed) => {
    const hash = leafHash(leafBytes(leaf as LogLeaf));
    extendRange(range, index, hash);
    const shape = LeafShapeSchema.safeParse(leaf);
    if (bytesToHex(hash) !== servedHash || !shape.success) {
      problems++;
      problem({ check: "leaf", index, reason: "The leaf doesn't fit the protocol, or the node serves the wrong hash for it", evidence: { leaf, leaf_hash: servedHash } });
      return;
    }
    if (!matchesLeafEntry(signed, shape.data.entry)) {
      problems++;
      problem({ check: "signed_entry", index, reason: "The entry served as signed isn't the one its leaf holds", evidence: { leaf, signed } });
      return;
    }
    entries.push({ index, leaf: shape.data as Read["leaf"], digest: entryDigest(signed as { type: string }) });
  });
  report.read[side] = { from, to };
  // The leaves read must be the signed tree, or a prefix of it.
  if (to > from) {
    const root = rangeRoot(range);
    const proof = to === head.size ? [] : await fetchProof(source, to, head.size);
    const holds = to === head.size ? bytesToHex(root) === head.root : verifyConsistency(to, head.size, root, hexToBytes(head.root), proof.map(hexToBytes));
    if (!holds) {
      problems++;
      problem({ check: "root", reason: `The first ${to} leaves the node serves (root ${bytesToHex(root)}) aren't the signed tree of ${head.size}, or a prefix of it`, evidence: { head, proof } });
    }
  }
  if (problems > 0) return null;
  return { read: { ...read, head, size: to, range: range.map(bytesToHex) }, entries };
}

/** The fields two leaves of one signed entry both state and state differently: each log's own time and index aside. */
function leafDifferences(first: Record<string, unknown>, second: Record<string, unknown>): string[] {
  const names = Object.keys(first).filter((name) => Object.hasOwn(second, name) && name !== "timestamp" && name !== "entry");
  return names.sort().flatMap((name) => {
    // A revealed entry names the commitment on its own log; the salt that opens it is the same on both.
    const [x, y] = name === "sealed" ? [(first.sealed as { salt?: unknown }).salt, (second.sealed as { salt?: unknown }).salt] : [first[name], second[name]];
    return canonicalJson(x) === canonicalJson(y) ? [] : [name];
  });
}

/** Where the first log says `logId` holds its entry `index`, from its receipt; null when it names no copy there. */
async function claimedCopy(first: LogSource, index: number, logId: string): Promise<number | null> {
  if (!first.receipt) return null;
  const receipt = CopiesSchema.safeParse(await first.receipt(index));
  if (!receipt.success) throw new MonitorError(`The node's answer to GET /api/v1/log/entries/${index} isn't a receipt`);
  return receipt.data.copies?.find((copy) => copy.log === logId)?.index ?? null;
}

function falseCopy(names: readonly [string, string], index: number, claimed: number, truth: string): ComparisonProblem {
  return {
    check: "false_copy",
    log: names[0],
    index,
    reason: `${names[0]} says ${names[1]} holds its entry ${index} at ${claimed}, but ${truth}`,
    evidence: { first: names[0], index, second: names[1], claimed },
  };
}

/** 0 when everything checked, 1 when a log misbehaved or they disagree, 2 when the comparison couldn't finish. */
export function comparisonStatus(report: LogsComparison): 0 | 1 | 2 {
  return exitStatus({ problems: report.problems as Problem[], error: report.error });
}
