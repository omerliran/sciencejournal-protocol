import { realpathSync } from "node:fs";
import { createServer } from "node:http";
import { resolve } from "node:path";
import { Readable } from "node:stream";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import type { TreeHead } from "../leaves";
import { mirrorHandler } from "./serve";
import { syncMirror, syncStatus, type MirrorProblem, type SyncReport } from "./sync";

// The reference mirror, for anyone to keep a full, checked copy of the record and serve it.
// `sync` copies what a node added since the last sync, run it on a schedule as a monitor is;
// `serve` answers reads from the copy. Exit status 0 means every check passed, 1 that the node
// misbehaved, and 2 that the sync couldn't finish, as the monitor's does.

const USAGE = `Usage:
  mirror sync <node> <dir> [options]   Copy the node's log and every file its entries name into
                                       <dir>, checking each against the log, and apply withdrawals
  mirror serve <dir> [options]         Serve the copy in <dir>: the log's read API and files by digest

Options for sync:
  --max-entries <n>     Copy at most n new entries this run (default: all)
  --max-file-bytes <n>  Don't fetch files larger than n bytes; they are listed as skipped, and
                        fetched by a later run once the limit allows (default: no limit)
  --json                Print the report as JSON

Options for serve:
  --port <n>            The port to listen on (default: 8080)
  --host <address>      The address to listen on (default: 127.0.0.1; put a TLS proxy in front)

Exit status for sync: 0 when every check passed, 1 when the node misbehaved, 2 when the sync
couldn't finish (an unreachable node, an unwritable folder, or a usage error).
`;

/** What the mirror touches outside itself, so tests can stand in for it. */
export interface Io {
  fetch: typeof fetch;
  out: (text: string) => void;
  err: (text: string) => void;
  now: () => number;
}

const processIo = (): Io => ({
  fetch: globalThis.fetch,
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
  now: Date.now,
});

/** Runs the mirror with command-line arguments and returns its exit status; `serve` returns only once the server stops. */
export async function main(args: string[], io: Io = processIo()): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        "max-entries": { type: "string" },
        "max-file-bytes": { type: "string" },
        json: { type: "boolean" },
        port: { type: "string" },
        host: { type: "string" },
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
  if (command === "sync" && operands.length === 2) {
    const misplaced = (["port", "host"] as const).find((name) => values[name] !== undefined);
    if (misplaced) return usage(io, `--${misplaced} is for serve`);
    const maxEntries = count(values["max-entries"]);
    const maxFileBytes = count(values["max-file-bytes"]);
    if (maxEntries === null) return usage(io, "--max-entries takes a whole number, 0 or more");
    if (maxFileBytes === null) return usage(io, "--max-file-bytes takes a whole number, 0 or more");
    let report: SyncReport;
    try {
      report = await syncMirror(resolve(operands[1]), operands[0], { maxEntries, maxFileBytes, fetch: io.fetch, now: io.now });
    } catch (error) {
      // An address that isn't a node's, before anything was read.
      io.err(`FAILED: ${(error as Error).message}\n`);
      return 2;
    }
    const status = syncStatus(report);
    io.out(values.json ? `${JSON.stringify({ ...report, result: (["ok", "misbehaved", "failed"] as const)[status] }, null, 2)}\n` : summary(report));
    return status;
  }
  if (command === "serve" && operands.length === 1) {
    const misplaced = (["max-entries", "max-file-bytes", "json"] as const).find((name) => values[name] !== undefined);
    if (misplaced) return usage(io, `--${misplaced} is for sync`);
    const port = count(values.port ?? "8080");
    if (port === null || port === undefined || port > 65535) return usage(io, "--port takes a port number");
    return serve(resolve(operands[0]), port, values.host ?? "127.0.0.1", io);
  }
  return usage(io, command ? "Expected sync <node> <dir> or serve <dir>" : "Name a command");
}

function usage(io: Io, problem: string): number {
  io.err(`${problem}\n\n${USAGE}`);
  return 2;
}

/** A whole-number option: undefined when not given, null when it isn't one. */
function count(value: string | undefined): number | undefined | null {
  if (value === undefined) return undefined;
  const number = Number(value);
  return /^(0|[1-9][0-9]*)$/.test(value) && Number.isSafeInteger(number) ? number : null;
}

/** Serves the copy over HTTP until the process is stopped. */
function serve(dir: string, port: number, host: string, io: Io): Promise<number> {
  const handle = mirrorHandler(dir);
  return new Promise((done) => {
    const server = createServer(async (incoming, outgoing) => {
      try {
        const response = await handle(new Request(new URL(incoming.url ?? "/", `http://${host}:${port}`), { method: incoming.method }));
        outgoing.writeHead(response.status, Object.fromEntries(response.headers));
        if (response.body) Readable.fromWeb(response.body as WebReadableStream).pipe(outgoing);
        else outgoing.end();
      } catch (error) {
        io.err(`Serving ${incoming.url} failed: ${(error as Error).message}\n`);
        if (!outgoing.headersSent) outgoing.writeHead(500, { "content-type": "application/json" });
        outgoing.end(JSON.stringify({ error: "The mirror couldn't read its copy" }));
      }
    });
    server.on("error", (error) => {
      io.err(`FAILED: ${error.message}\n`);
      done(2);
    });
    server.listen(port, host, () => io.out(`Serving the mirror in ${dir} at http://${host}:${port}\n`));
    for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => server.close(() => done(0)));
  });
}

/** A short account of a sync, for a person. */
function summary(report: SyncReport): string {
  const lines = [`${report.log ?? "The log"} at ${report.node}, copied into ${report.dir}`];
  if (report.pinned) lines.push("  Pinned on this run: its ID is log: and the SHA-256 of its public key.");
  if (report.head) lines.push(`  Serving: ${describe(report.head)}.`);
  const { from, to } = report.copied;
  lines.push(`  Entries: ${to > from ? `${from} to ${to - 1} copied this run` : "none copied this run"}; ${to} held.`);
  lines.push(`  Files: ${report.fetched.files} fetched this run (${bytes(report.fetched.bytes)}).`);
  if (report.withdrawn.length > 0) {
    lines.push(`  Withdrawn on the log: ${report.withdrawn.join(", ")}; ${report.deleted} file${report.deleted === 1 ? "" : "s"} deleted.`);
  }
  const large = report.skipped.filter((file) => file.bytes !== null);
  const unserved = report.skipped.filter((file) => file.bytes === null);
  if (large.length > 0) lines.push(`  Skipped: ${large.length} file${large.length === 1 ? "" : "s"} larger than --max-file-bytes (${bytes(large.reduce((sum, file) => sum + file.bytes!, 0))} in all).`);
  if (unserved.length > 0) lines.push(`  Skipped: ${unserved.length} file${unserved.length === 1 ? "" : "s"} the node listed but didn't serve when asked; the next sync asks again.`);
  if (report.unpathed.length > 0) {
    lines.push(`  Not checked: the node lists the files of entries ${report.unpathed.join(", ")} by digest alone, so each was checked against its own digest but not against its entry.`);
  }
  for (const note of report.unchecked) lines.push(`  Not checked: ${note}`);
  for (const problem of report.problems) lines.push(`  ${describeProblem(problem)}`);
  const status = syncStatus(report);
  if (status === 0) lines.push("OK: the copy holds every entry it audited, and every file those entries name that the node serves.");
  if (status === 1) {
    const count = report.problems.length;
    lines.push(`MISBEHAVED: ${count} problem${count === 1 ? "" : "s"} with what the node served. Nothing from this step was kept; --json shows the evidence.`);
  }
  if (status === 2) lines.push(`FAILED, so the copy holds what earlier steps saved: ${report.error}`);
  return `${lines.join("\n")}\n`;
}

function describe(head: TreeHead): string {
  return `${head.size} ${head.size === 1 ? "entry" : "entries"}, root ${head.root}, signed ${head.timestamp}`;
}

function describeProblem(problem: MirrorProblem): string {
  const at = problem.index === undefined ? "" : ` at entry ${problem.index}`;
  return `Problem${at} (${problem.check}): ${problem.reason}`;
}

function bytes(count: number): string {
  if (count < 1024) return `${count} bytes`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = count / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

/** Whether this file is the program, as in `tsx src/mirror/cli.ts sync https://sciencejournal.ai ./mirror`. */
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
