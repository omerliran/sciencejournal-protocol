import { realpathSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { JsonError, parseJson } from "../json";
import type { TreeHead } from "../leaves";
import {
  checkpointOf,
  CheckpointSchema,
  compareCheckpoints,
  exitStatus,
  MonitorError,
  monitorLog,
  type Checkpoint,
  type Comparison,
  type LogSource,
  type MonitorReport,
  type Problem,
} from "../monitor";
import { httpSource, nodeUrl } from "./http";
import { findState, readState, stateDirectory, stateFileName, writeState, type StateFile } from "./state";

// The reference log monitor, for anyone to run on a schedule against any node. It reads only
// the public API. Exit status 0 means every check passed, 1 that the log misbehaved, and 2
// that the monitor couldn't finish, so a cron job or CI can alert on 1.

const USAGE = `Usage:
  monitor check <node> [options]     Check a node's log: its key, its tree heads, and its entries
  monitor compare <a> <b> [options]  Check that two checkpoints are heads of one history

Options for check:
  --state <file>        Where to keep the pinned log and the last verified head
                        (default: a file per log in ~/.config/sciencejournal/monitor)
  --pin                 Pin the log the node serves now, even if it isn't the pinned one
  --max-entries <n>     Audit at most n new entries this run (default: all; 0 skips the audit)
  --checkpoint <file>   After a run that passes, write the verified head to <file> (- for stdout)
  --json                Print the report as JSON

Options for compare:
  --node <url>          Where to fetch the consistency proof (default: the node the larger checkpoint names)
  --json                Print the comparison as JSON

Exit status: 0 when every check passed, 1 when the log misbehaved, 2 when the monitor
couldn't finish (an unreachable node, an unreadable file, or a usage error).
`;

/** What the monitor touches outside itself, so tests can stand in for it. */
export interface Io {
  fetch: typeof fetch;
  out: (text: string) => void;
  err: (text: string) => void;
  env: Record<string, string | undefined>;
  home: string;
}

const processIo = (): Io => ({
  fetch: globalThis.fetch,
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
  env: process.env,
  home: homedir(),
});

/** Runs the monitor with command-line arguments and returns its exit status. */
export async function main(args: string[], io: Io = processIo()): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        state: { type: "string" },
        pin: { type: "boolean" },
        "max-entries": { type: "string" },
        checkpoint: { type: "string" },
        node: { type: "string" },
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
    });
  } catch (error) {
    return usage(io, (error as Error).message);
  }
  const { values, positionals } = parsed;
  const [command, ...operands] = positionals;
  if (values.help || command === "help") {
    io.out(USAGE);
    return 0;
  }
  try {
    if (command === "check" && operands.length === 1) {
      if (values.node !== undefined) return usage(io, "--node is for compare");
      const maxEntries = values["max-entries"] === undefined ? undefined : Number(values["max-entries"]);
      if (maxEntries !== undefined && !(Number.isSafeInteger(maxEntries) && maxEntries >= 0)) {
        return usage(io, "--max-entries takes a whole number, 0 or more");
      }
      return await check(io, operands[0], { ...values, maxEntries });
    }
    if (command === "compare" && operands.length === 2) {
      const misplaced = (["state", "pin", "max-entries", "checkpoint"] as const).find((name) => values[name] !== undefined);
      if (misplaced) return usage(io, `--${misplaced} is for check`);
      return await compare(io, operands[0], operands[1], values);
    }
  } catch (error) {
    // Whatever stops a run outside the log's own checks, such as an unwritable state file. An
    // uncaught error would exit with 1, which means the log misbehaved.
    io.err(`FAILED: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
  return usage(io, command ? "Expected check <node> or compare <a> <b>" : "Name a command");
}

function usage(io: Io, problem: string): number {
  io.err(`${problem}\n\n${USAGE}`);
  return 2;
}

// --- check ---------------------------------------------------------------------------

interface CheckOptions {
  state?: string;
  pin?: boolean;
  maxEntries?: number;
  checkpoint?: string;
  json?: boolean;
}

async function check(io: Io, address: string, options: CheckOptions): Promise<number> {
  const node = nodeUrl(address);
  const source = rememberingLog(httpSource(node, { fetch: io.fetch }));
  const directory = stateDirectory(io.env, io.home);
  const listed = options.state ? null : await findState(directory, node);
  const saved = options.state ? await readState(options.state) : await savedState(directory, listed, source, options.pin);
  // A node not yet seen for this log may lag behind the nodes that were, but no node may shrink,
  // and a node that lags is held to a proof from one that served the newer head.
  const servedBefore = saved ? (Object.hasOwn(saved.nodes, node) ? saved.nodes[node] : 0) : undefined;
  const leader = Object.entries(saved?.nodes ?? {}).find(([url, size]) => url !== node && size === saved?.head?.size)?.[0];
  const ahead = leader ? httpSource(leader, { fetch: io.fetch }) : undefined;
  const run = { pin: options.pin, maxEntries: options.maxEntries, servedBefore, ahead };
  const { report, state } = await monitorLog(source, saved, run);

  let path: string | null = null;
  if (state) {
    path = options.state ?? (listed?.state.log === state.log ? listed.path : join(directory, stateFileName(state.log)));
    const nodes = { ...(saved?.log === state.log ? saved.nodes : {}), [node]: report.head?.size ?? 0 };
    await writeState(path, { ...state, nodes });
    // Pinned to another log: the old log's file no longer speaks for this node.
    if (listed && listed.state.log !== state.log) {
      const rest = Object.fromEntries(Object.entries(listed.state.nodes).filter(([url]) => url !== node));
      await writeState(listed.path, { ...listed.state, nodes: rest });
    }
  }
  // With the checkpoint on stdout, the report goes to stderr so stdout holds only the checkpoint.
  const write = options.checkpoint === "-" ? io.err : io.out;
  write(
    options.json
      ? `${JSON.stringify({ node, state_file: path, ...report, result: result(report) }, null, 2)}\n`
      : summary(node, report, path),
  );
  const checkpoint = state && checkpointOf(state, node);
  if (checkpoint && options.checkpoint) {
    const text = `${JSON.stringify(checkpoint, null, 2)}\n`;
    if (options.checkpoint === "-") io.out(text);
    else await writeFile(options.checkpoint, text);
  }
  return exitStatus(report);
}

/** A source that reads GET /api/v1/log once, so finding the state and the run see one answer. */
function rememberingLog(source: LogSource): LogSource {
  let info: Promise<unknown> | undefined;
  return { ...source, log: () => (info ??= source.log()) };
}

/**
 * The state to check a node against: that of the log it served before, which the run holds
 * it to unless told to pin again. A node seen for the first time, or pinned again, starts
 * from the state of the log it serves now, if another node served that log, so the two
 * nodes are checked against each other.
 */
async function savedState(
  directory: string,
  listed: { state: StateFile } | null,
  source: LogSource,
  pin: boolean | undefined,
): Promise<StateFile | null> {
  const served = await source.log().then(
    (info) => (info as { log?: unknown } | null)?.log,
    () => undefined, // The run reports why it couldn't read the log.
  );
  if (listed && (served === listed.state.log || !pin)) return listed.state;
  return typeof served === "string" ? readState(join(directory, stateFileName(served))) : null;
}

function result(report: { problems: readonly Problem[]; error: string | null }): "ok" | "misbehaved" | "failed" {
  return (["ok", "misbehaved", "failed"] as const)[exitStatus(report)];
}

/** A short account of a run, for a person. */
function summary(node: string, report: MonitorReport, path: string | null): string {
  const lines = [`${report.log ?? "The log"} at ${node}`];
  if (report.pinned) lines.push("  Pinned on this run: its ID is log: and the SHA-256 of its public key.");
  if (report.head) lines.push(`  Tree head: ${describe(report.head)}.`);
  if (report.behind) {
    lines.push(`  History: behind the head verified before, ${describe(report.previous!)}, which extends it.`);
  }
  // The audit runs only once the head verified and extends the one verified before.
  if (report.audit) {
    lines.push(
      report.previous
        ? `  History: consistent with the head verified before, ${describe(report.previous)}.`
        : "  History: the first head this monitor has verified for this log.",
    );
    const { from, to, types } = report.audit;
    const counts = Object.entries(types).map(([type, count]) => `${type} ${count}`).join(", ");
    const read = to > from ? `${from} to ${to - 1} audited this run (${counts})` : "none audited this run";
    lines.push(`  Entries: ${read}; ${report.audited} of ${report.head!.size} audited in all.`);
    if (report.waiting > 0) lines.push(`  Sealed: ${report.waiting} commitment${report.waiting === 1 ? "" : "s"} waiting to be opened.`);
  } else if (!report.head && exitStatus(report) === 0) {
    lines.push("  Tree head: none yet, as the log is empty.");
  }
  for (const note of report.unchecked) lines.push(`  Not checked: ${note}`);
  for (const problem of report.problems) lines.push(`  ${describeProblem(problem)}`);
  const status = exitStatus(report);
  if (status === 0) lines.push(`OK: every check passed. State saved in ${path}.`);
  if (status === 1) {
    const count = report.problems.length;
    lines.push(`MISBEHAVED: ${count} problem${count === 1 ? "" : "s"} with the log. The state file was left as it was; --json shows the evidence.`);
  }
  if (status === 2) lines.push(`FAILED, so the state file was left as it was: ${report.error}`);
  return `${lines.join("\n")}\n`;
}

// --- compare -------------------------------------------------------------------------

async function compare(io: Io, first: string, second: string, options: { node?: string; json?: boolean }): Promise<number> {
  const a = await readCheckpoint(first);
  const b = await readCheckpoint(second);
  // Only a node that has the larger tree can prove the smaller one is a prefix of it.
  const [smaller, larger] = [a, b].sort((x, y) => x.tree_head.size - y.tree_head.size);
  const node = options.node ?? larger.node ?? smaller.node;
  const comparison = await compareCheckpoints(a, b, node ? httpSource(node, { fetch: io.fetch }) : null);
  io.out(options.json ? `${JSON.stringify({ ...comparison, result: result(comparison) }, null, 2)}\n` : comparisonSummary(comparison));
  return exitStatus(comparison);
}

async function readCheckpoint(path: string): Promise<Checkpoint> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    throw new MonitorError(`Can't read the checkpoint ${path}: ${(error as Error).message}`);
  }
  let value: unknown;
  try {
    value = parseJson(text);
  } catch (error) {
    if (!(error instanceof JsonError)) throw error;
    throw new MonitorError(`The checkpoint ${path} isn't JSON: ${error.message}`);
  }
  const checkpoint = CheckpointSchema.safeParse(value);
  if (!checkpoint.success) throw new MonitorError(`${path} isn't a checkpoint: ${checkpoint.error.issues[0].message}`);
  return checkpoint.data;
}

function comparisonSummary(comparison: Comparison): string {
  const lines: string[] = [];
  if (comparison.log) lines.push(comparison.log);
  if (comparison.heads) lines.push(`  Heads: ${describe(comparison.heads[0])}; and ${describe(comparison.heads[1])}.`);
  for (const problem of comparison.problems) lines.push(`  ${describeProblem(problem)}`);
  const status = exitStatus(comparison);
  if (status === 0) lines.push("OK: the heads are consistent, so both readers saw one history.");
  if (status === 1) lines.push("MISBEHAVED: the log showed these readers different histories; --json shows the evidence.");
  if (status === 2) lines.push(`FAILED: ${comparison.error}`);
  return `${lines.join("\n")}\n`;
}

// --- Wording -------------------------------------------------------------------------

function describe(head: TreeHead): string {
  return `${head.size} ${head.size === 1 ? "entry" : "entries"}, root ${head.root}, signed ${head.timestamp}`;
}

function describeProblem(problem: Problem): string {
  const at = problem.index === undefined ? "" : ` at entry ${problem.index}`;
  return `Problem${at} (${problem.check}): ${problem.reason}`;
}

/** Whether this file is the program, as in `tsx src/monitor/cli.ts check https://sciencejournal.ai`. */
function invokedDirectly(): boolean {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  main(process.argv.slice(2)).then(
    (status) => {
      process.exitCode = status;
    },
    (error: unknown) => {
      process.stderr.write(`FAILED: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 2;
    },
  );
}
