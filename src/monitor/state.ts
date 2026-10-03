import { mkdir, readdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { z } from "zod";
import { JsonError, parseJson } from "../json";
import { MonitorError, MonitorStateSchema } from "../monitor";

// Where the command-line monitor keeps what it verified: one file per log, named by the
// log's ID, which also lists the nodes it read that log from. A node that later serves a
// different log is refused, because its file says which log it served before.

/** A monitor's state file: the pinned log, its last verified head and audit, and where it was read. */
export const StateFileSchema = MonitorStateSchema.safeExtend({
  /**
   * The nodes this log was read from, by base URL, each with the size of the last tree head
   * it served. A node may lag behind another, but it never serves less than it did before.
   */
  nodes: z.record(z.string(), z.number().int().nonnegative()),
});
export type StateFile = z.infer<typeof StateFileSchema>;

/** The default directory: $XDG_CONFIG_HOME/sciencejournal/monitor, or ~/.config/sciencejournal/monitor. */
export function stateDirectory(env: Record<string, string | undefined>, home: string): string {
  return join(env.XDG_CONFIG_HOME || join(home, ".config"), "sciencejournal", "monitor");
}

/** A log's state file name: its ID, with the colon (which some file systems refuse) as an underscore. */
export function stateFileName(log: string): string {
  return `${log.replace(/[^A-Za-z0-9._-]/g, "_")}.json`;
}

/** Reads a state file; null if there is none. Throws if it can't be read or isn't a state file. */
export async function readState(path: string): Promise<StateFile | null> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new MonitorError(`Can't read the state file ${path}: ${(error as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = parseJson(text);
  } catch (error) {
    if (!(error instanceof JsonError)) throw error;
    throw new MonitorError(`The state file ${path} isn't JSON: ${error.message}`);
  }
  const state = StateFileSchema.safeParse(parsed);
  if (!state.success) {
    const issue = state.error.issues[0];
    throw new MonitorError(`The state file ${path} isn't a monitor's state (${issue.path.join(".") || "/"}: ${issue.message})`);
  }
  return state.data;
}

/** Writes a state file whole, so a crash never leaves half of one. */
export async function writeState(path: string, state: StateFile): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const partial = `${path}.${process.pid}.partial`;
  await writeFile(partial, `${JSON.stringify(state, null, 2)}\n`);
  await rename(partial, path);
}

/**
 * The state file in `directory` that lists `node`, if one does. A file that can't be read
 * might be that node's, so it stops the search rather than letting the node be pinned again.
 */
export async function findState(directory: string, node: string): Promise<{ path: string; state: StateFile } | null> {
  let names: string[];
  try {
    names = await readdir(directory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new MonitorError(`Can't read the state directory ${directory}: ${(error as Error).message}`);
  }
  const found: { path: string; state: StateFile }[] = [];
  const unreadable: string[] = [];
  for (const name of names.filter((name) => name.endsWith(".json")).sort()) {
    const path = join(directory, name);
    try {
      const state = await readState(path);
      if (state && Object.hasOwn(state.nodes, node)) found.push({ path, state });
    } catch (error) {
      unreadable.push((error as Error).message);
    }
  }
  if (found.length > 1) {
    throw new MonitorError(`More than one state file lists ${node}: ${found.map((f) => f.path).join(", ")}. Remove it from all but one.`);
  }
  if (found.length === 0 && unreadable.length > 0) throw new MonitorError(unreadable.join(" "));
  return found[0] ?? null;
}
