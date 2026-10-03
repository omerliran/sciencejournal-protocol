import { createHash } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import { chmod, copyFile, lstat, mkdir, open, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

/** A bundle path (relative, with forward slashes) as a path under `root` on this machine. */
export function under(root: string, path: string): string {
  return join(root, ...path.split("/"));
}

export async function exists(path: string): Promise<boolean> {
  return (await stat(path).catch(() => null)) !== null;
}

/**
 * Every file under `root` as a bundle path, sorted. A symbolic link to a file counts as the
 * file, as it does for the Python client; a link to a directory is not followed.
 */
export async function listFiles(root: string): Promise<string[]> {
  const found: string[] = [];
  const walk = async (directory: string, prefix: string) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = join(directory, entry.name);
      if (entry.isDirectory()) await walk(full, path);
      else if (entry.isFile() || (entry.isSymbolicLink() && (await stat(full).catch(() => null))?.isFile())) {
        found.push(path);
      }
    }
  };
  if ((await stat(root).catch(() => null))?.isDirectory()) await walk(root, "");
  return found.sort();
}

export async function readFiles(root: string, paths: Iterable<string>): Promise<Map<string, Uint8Array>> {
  const files = new Map<string, Uint8Array>();
  for (const path of paths) files.set(path, new Uint8Array(await readFile(under(root, path))));
  return files;
}

/** A file's SHA-256 in hex, read in pieces, so files of any size fit. */
export async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

/** Writes a file under `root`, replacing one that is there even if it is read-only. */
export async function writeUnder(root: string, path: string, bytes: Uint8Array | string, mode = 0o644): Promise<void> {
  const target = under(root, path);
  await mkdir(dirname(target), { recursive: true });
  const part = `${target}.part`;
  await writeFile(part, bytes, { mode });
  await rename(part, target);
}

/**
 * Copies every file under `from` to `to`, cloning where the file system can (copy on write, as
 * APFS, Btrfs, and XFS do), so large data costs nothing until something changes it. Files are
 * cloned or copied, never hard-linked: a run that wrote into a hard link would change the
 * bundle's own copy.
 */
export async function cloneTree(from: string, to: string): Promise<void> {
  for (const path of await listFiles(from)) {
    const target = under(to, path);
    await mkdir(dirname(target), { recursive: true });
    await copyFile(under(from, path), target, constants.COPYFILE_FICLONE);
    await chmod(target, 0o644);
  }
}

export async function removeTree(path: string): Promise<void> {
  // A run may leave directories it made read-only; they have to open up to be removed.
  await rm(path, { recursive: true, force: true }).catch(async () => {
    const reopen = async (directory: string) => {
      await chmod(directory, 0o755).catch(() => {});
      for (const entry of await readdir(directory, { withFileTypes: true }).catch(() => [])) {
        if (entry.isDirectory()) await reopen(join(directory, entry.name));
      }
    };
    await reopen(path);
    await rm(path, { recursive: true, force: true });
  });
}

// What a run wrote is read as regular files only. A run can leave a symbolic link pointing at
// any file on this machine, such as the operator's key, or a pipe that would never finish
// being read; neither is followed or opened.

/** Every regular file under `root`, as bundle paths, and apart from them anything else there. */
export async function listOutputs(root: string): Promise<{ files: string[]; others: string[] }> {
  const files: string[] = [];
  const others: string[] = [];
  const top = await lstat(root).catch(() => null);
  if (!top) return { files, others };
  if (!top.isDirectory()) return { files, others: ["."] };
  const walk = async (directory: string, prefix: string) => {
    // Directory entries report links as links: nothing here follows one.
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await walk(join(directory, entry.name), path);
      else if (entry.isFile()) files.push(path);
      else others.push(path);
    }
  };
  await walk(root, "");
  return { files: files.sort(), others: others.sort() };
}

/**
 * Where a regular file a run wrote is, and its size: only when no part of its bundle path under
 * `root` is a link. Throws with the reason otherwise.
 */
async function output(root: string, path: string): Promise<{ full: string; bytes: number }> {
  const segments = path.split("/");
  let current = root;
  for (const [index, segment] of ["", ...segments].entries()) {
    current = index === 0 ? root : join(current, segment);
    const info = await lstat(current).catch(() => null);
    const last = index === segments.length;
    if (!info || (!last && !info.isDirectory() && !info.isSymbolicLink())) throw new Error(`there is no ${path}`);
    if (info.isSymbolicLink()) throw new Error(`${path} goes through a link, which the harness doesn't follow`);
    if (last && !info.isFile()) throw new Error(`${path} isn't a regular file`);
    if (last) return { full: current, bytes: info.size };
  }
  throw new Error(`there is no ${path}`);
}

const NO_FOLLOW = constants.O_RDONLY | constants.O_NOFOLLOW;

/** A regular file a run wrote, read only if it is no larger than `maxBytes`. */
export async function readOutput(root: string, path: string, maxBytes: number): Promise<Uint8Array> {
  const { full, bytes } = await output(root, path);
  if (bytes > maxBytes) throw new Error(`${path} is larger than the ${maxBytes} bytes the harness reads`);
  const handle = await open(full, NO_FOLLOW);
  try {
    return new Uint8Array(await handle.readFile());
  } finally {
    await handle.close();
  }
}

/** The SHA-256 of a regular file a run wrote, in hex, read in pieces. */
export async function sha256Output(root: string, path: string): Promise<string> {
  const { full } = await output(root, path);
  const hash = createHash("sha256");
  const handle = await open(full, NO_FOLLOW);
  try {
    for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk as Buffer);
  } finally {
    await handle.close();
  }
  return hash.digest("hex");
}

export async function readJsonFile<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

export async function writeJsonFile(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

/** Keeps the start and the end of output too long to keep whole. */
export class LogTail {
  private readonly head: Buffer[] = [];
  private headBytes = 0;
  private tail: Buffer[] = [];
  private tailBytes = 0;
  /** Every byte written, kept or not. */
  total = 0;

  constructor(
    readonly headLimit: number,
    readonly tailLimit: number,
  ) {}

  write(chunk: Uint8Array | string): void {
    let data = typeof chunk === "string" ? Buffer.from(chunk) : Buffer.from(chunk);
    this.total += data.length;
    if (this.headBytes < this.headLimit) {
      const take = Math.min(this.headLimit - this.headBytes, data.length);
      this.head.push(data.subarray(0, take));
      this.headBytes += take;
      data = data.subarray(take);
    }
    if (data.length === 0) return;
    this.tail.push(data);
    this.tailBytes += data.length;
    while (this.tail.length > 1 && this.tailBytes - this.tail[0].length >= this.tailLimit) {
      this.tailBytes -= this.tail.shift()!.length;
    }
  }

  /** The output, or its start and end with a note of how much was left out between them. */
  bytes(): Buffer {
    const head = Buffer.concat(this.head);
    const all = Buffer.concat(this.tail);
    const kept = all.subarray(Math.max(0, all.length - this.tailLimit));
    const omitted = this.total - head.length - kept.length;
    if (omitted === 0) return Buffer.concat([head, kept]);
    // Start the tail at a line, so it begins with a whole line and a whole character.
    const newline = kept.indexOf(10);
    const lines = newline >= 0 && newline < 4096 ? kept.subarray(newline + 1) : kept;
    const left = omitted + kept.length - lines.length;
    return Buffer.concat([head, Buffer.from(`\n[... ${left} bytes left out ...]\n`), lines]);
  }

  /** The last few lines, shortened, for a summary. */
  lastLines(count: number, width = 200): string[] {
    const lines = this.bytes().toString("utf8").split(/\r?\n/).filter((line) => line.trim() !== "");
    return lines.slice(-count).map((line) => (line.length > width ? `${line.slice(0, width)}…` : line));
  }
}
