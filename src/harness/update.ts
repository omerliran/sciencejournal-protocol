import { chmod, rename, stat, writeFile } from "node:fs/promises";
import { DigestSchema, sha256Digest } from "../hash";
import { parseJson } from "../json";
import { NodeClient, nodeUrl } from "./client";
import { HarnessError, type Deps } from "./context";
import { sha256File } from "./files";

// Keeping the harness current. A node that serves the harness also serves its digest beside it,
// and a harness started from that one file compares its own bytes with it before it takes a job:
// a copy downloaded before the node learned a new kind of job would otherwise go on asking
// without knowing what it was given. `update` replaces the file with the one the node serves.

/** Where a node serves the harness, built into one file. */
export const HARNESS_PATH = "/sj-harness.mjs";
/** Where it serves that file's digest: {"digest": "sha256:<hex>", "bytes"}. */
export const HARNESS_DIGEST_PATH = "/sj-harness.json";

/** The digest and size of the harness a node serves, or null if it says nothing about one. */
async function served(client: NodeClient, deps: Pick<Deps, "fetch">): Promise<{ digest: string; bytes: number } | null> {
  try {
    const response = await deps.fetch(client.resolve(HARNESS_DIGEST_PATH));
    if (!response.ok) return null;
    const body = parseJson(await response.text()) as { digest?: unknown; bytes?: unknown } | null;
    const digest = DigestSchema.safeParse(body?.digest);
    return digest.success && typeof body?.bytes === "number" ? { digest: digest.data, bytes: body.bytes } : null;
  } catch {
    // A node that doesn't serve the harness, or can't be reached for it, leaves the copy as it is.
    return null;
  }
}

/**
 * Throws unless this harness is the one the node serves. A harness run from its source, or a
 * node that serves none, leaves nothing to compare, so either counts as current.
 */
export async function requireCurrent(node: string | undefined, deps: Deps): Promise<void> {
  if (!deps.self) return;
  const client = new NodeClient(nodeUrl(node, deps), deps);
  const latest = await served(client, deps);
  if (!latest || `sha256:${await sha256File(deps.self)}` === latest.digest) return;
  throw new HarnessError(
    `This sj-harness is out of date: ${client.base} serves a newer one, which knows every job it may hand you. Run ${deps.invocation} update, then ask for a job again.`,
  );
}

/** Replaces this harness's file with the one the node serves, checked against its digest. */
export async function update(node: string | undefined, deps: Deps): Promise<number> {
  if (!deps.self) throw new HarnessError("This harness runs from its source, so update the source instead.", 2);
  const client = new NodeClient(nodeUrl(node, deps), deps);
  const latest = await served(client, deps);
  if (!latest) throw new HarnessError(`${client.base} doesn't say which harness it serves.`);
  if (`sha256:${await sha256File(deps.self)}` === latest.digest) {
    deps.print("sj-harness is up to date.");
    return 0;
  }
  let bytes: Uint8Array;
  try {
    const response = await deps.fetch(client.resolve(HARNESS_PATH));
    if (!response.ok) throw new Error(`it answered ${response.status}`);
    bytes = new Uint8Array(await response.arrayBuffer());
  } catch (error) {
    throw new HarnessError(`Couldn't download ${client.resolve(HARNESS_PATH)}: ${(error as Error).message}`);
  }
  if (bytes.length !== latest.bytes || sha256Digest(bytes) !== latest.digest) {
    // While a node deploys, its old and new servers can answer side by side for a few minutes.
    throw new HarnessError(`The harness ${client.base} sent doesn't match the digest it gives for it. Try again in a few minutes.`);
  }
  // Written beside the old file and moved over it, so an interrupted update leaves a harness that runs.
  const next = `${deps.self}.next`;
  await writeFile(next, bytes);
  await chmod(next, (await stat(deps.self)).mode & 0o777);
  await rename(next, deps.self);
  deps.print(`Updated sj-harness to the one ${client.base} serves. Run ${deps.invocation} version to see which it is.`);
  return 0;
}
