import { constants } from "node:fs";
import { chmod, copyFile, mkdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { EXTERNAL_DATA, externalBytes, readExternalData, type ExternalData, type ExternalFile } from "../external";
import { parseJson } from "../json";
import { HarnessError, type Deps } from "./context";
import { exists, saveChecked, sha256File, under } from "./files";
import { plural, size } from "./format";

/** How many redirects a pointer's URL may take to its file, each to another https URL. */
const MAX_REDIRECTS = 10;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
/** How long a fetch may go without a byte arriving before the harness gives up on it. */
const IDLE_MINUTES = 5;

/** A public file a run fetched, as run.json and the report record it. */
export interface PointedFile {
  path: string;
  url: string;
  sha256: string;
  bytes: number;
  /** Whether this run fetched it, rather than finding it kept from an earlier run. */
  fetched: boolean;
  /** Where its bytes came from in the end, when its URL redirected. */
  from?: string;
}

/**
 * The public files a bundle points at, from its data/external.json, read against the paths of
 * its own files: none when it has no data/external.json. Throws when the file can't be used,
 * as a node refuses a bundle whose pointers break the schema or the path rules.
 */
export async function readPointers(bundleDir: string, paths: Iterable<string>): Promise<ExternalData> {
  const all = new Set(paths);
  if (!all.has(EXTERNAL_DATA)) return [];
  let value: unknown;
  try {
    value = parseJson(await readFile(under(bundleDir, EXTERNAL_DATA), "utf8"));
  } catch (error) {
    throw new HarnessError(`${EXTERNAL_DATA} isn't valid JSON: ${(error as Error).message}`);
  }
  const read = readExternalData(value, all);
  if (read.issues) {
    throw new HarnessError(
      `${EXTERNAL_DATA} can't be used: ${read.issues.map((issue) => `${issue.path || "/"} ${issue.message}`).join("; ")}`,
    );
  }
  return read.files;
}

/** One line saying what a bundle points at, or nothing when it points at nothing. */
export function describePointers(files: ExternalData): string | null {
  if (files.length === 0) return null;
  const hosts = [...new Set(files.map((file) => new URL(file.url).host))];
  return `${plural(files.length, "public file")} (${size(externalBytes(files))}) from ${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ` and ${plural(hosts.length - 3, "other host")}` : ""}`;
}

/**
 * Makes sure each file a bundle points at is in `store`, named by its digest: one an earlier
 * run kept is used again once its SHA-256 checks; any other is fetched from its URL, following
 * only redirects to other https URLs, stopping at more bytes than it names, and kept only if
 * its size and SHA-256 match. Each host a URL names learns that someone fetched it, and from
 * where. Throws, naming the file, when one can't be had.
 */
export async function fetchPointed(files: ExternalData, store: string, deps: Deps): Promise<PointedFile[]> {
  await mkdir(store, { recursive: true });
  const fetched: PointedFile[] = [];
  for (const file of files) {
    const kept = keptAt(store, file);
    const record = { path: file.path, url: file.url, sha256: file.sha256, bytes: file.bytes };
    if ((await exists(kept)) && `sha256:${await sha256File(kept)}` === file.sha256) {
      fetched.push({ ...record, fetched: false });
      continue;
    }
    deps.print(`Fetching ${file.path} (${size(file.bytes)}) from ${file.url}...`);
    const from = await fetchFile(file, kept, deps);
    fetched.push({ ...record, fetched: true, ...(from && { from }) });
  }
  return fetched;
}

/** Puts each file a bundle points at where its path says in a run's workspace, as a copy the run may change. */
export async function placePointed(files: ExternalData, store: string, workspace: string): Promise<void> {
  for (const file of files) {
    const target = under(workspace, file.path);
    await mkdir(dirname(target), { recursive: true });
    await copyFile(keptAt(store, file), target, constants.COPYFILE_FICLONE);
    await chmod(target, 0o644);
  }
}

function keptAt(store: string, file: ExternalFile): string {
  return join(store, file.sha256.slice("sha256:".length));
}

/** Fetches one file into `destination`, checked; returns where its bytes came from when its URL redirected. */
async function fetchFile(file: ExternalFile, destination: string, deps: Deps): Promise<string | undefined> {
  const failed = (why: string) => new HarnessError(`Couldn't fetch ${file.path}, which ${EXTERNAL_DATA} points at: ${why}`);
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const wait = () => {
    clearTimeout(timer);
    timer = setTimeout(() => controller.abort(), IDLE_MINUTES * 60_000);
  };
  let url = new URL(file.url);
  try {
    for (let redirects = 0; ; redirects++) {
      wait();
      const response = await deps.fetch(url, { redirect: "manual", signal: controller.signal });
      if (REDIRECTS.has(response.status)) {
        await response.body?.cancel().catch(() => {});
        const location = response.headers.get("location");
        if (!location) throw failed(`${url.href} answered ${response.status} without saying where to go`);
        const next = new URL(location, url);
        if (next.protocol !== "https:") throw failed(`${url.href} sends it to ${next.href}, which isn't https`);
        if (redirects >= MAX_REDIRECTS) throw failed(`${file.url} redirects more than ${MAX_REDIRECTS} times`);
        url = next;
        continue;
      }
      if (!response.ok || !response.body) throw failed(`${url.href} answered ${response.status}`);
      try {
        await saveChecked(response.body, destination, { digest: file.sha256, bytes: file.bytes }, EXTERNAL_DATA, wait);
      } catch (error) {
        if (error instanceof HarnessError) throw failed(error.message);
        throw error;
      }
      return redirects > 0 ? url.href : undefined;
    }
  } catch (error) {
    if (error instanceof HarnessError) throw error;
    if (controller.signal.aborted) throw failed(`nothing arrived from ${url.href} for ${IDLE_MINUTES} minutes`);
    throw failed((error as Error).message);
  } finally {
    clearTimeout(timer);
  }
}
