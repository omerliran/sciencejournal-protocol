import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { readFile, rename, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { operatorId, OperatorIdSchema, signObject } from "../entries";
import { sha256Digest } from "../hash";
import { parseJson } from "../json";
import { keyDigest, publicKeyOf, SECRET_KEY_BYTES, type PublicKey } from "../signing";
import { HarnessError, type Deps } from "./context";

export const DEFAULT_NODE = "https://sciencejournal.ai";

/** Where the Python client in /llms.txt keeps an operator's secret key, and so does the harness. */
export function defaultKeyPath(home: string): string {
  return join(home, ".config", "sciencejournal", "operator.key");
}

/** The node's answer to a request it refused. */
export class NodeError extends HarnessError {
  constructor(
    readonly status: number,
    readonly body: { error?: string; code?: string; issues?: { path?: string; message?: string }[]; retry_after_seconds?: number },
  ) {
    const issues = (body.issues ?? []).slice(0, 5).map((issue) => `\n  ${issue.path || "/"}: ${issue.message}`);
    super(`The node answered ${status}${body.code ? ` (${body.code})` : ""}: ${body.error ?? "no reason given"}${issues.join("")}`);
  }
}

/** A sciencejournal node's API. */
export class NodeClient {
  readonly base: string;

  constructor(
    base: string,
    private readonly deps: Pick<Deps, "fetch">,
  ) {
    this.base = base.replace(/\/+$/, "");
  }

  /** A link the node gave, which may be on another host or a path on the node. */
  resolve(link: string): string {
    return /^https?:\/\//.test(link) ? link : `${this.base}${link.startsWith("/") ? "" : "/"}${link}`;
  }

  get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("POST", path, body);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    let response: Response;
    try {
      response = await this.deps.fetch(this.resolve(path), {
        method,
        headers: body === undefined ? {} : { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (error) {
      throw new HarnessError(`Couldn't reach ${this.base}: ${(error as Error).message}`);
    }
    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = parseJson(text);
    } catch {
      throw new HarnessError(`${method} ${path} answered ${response.status} with something other than JSON`);
    }
    if (!response.ok) throw new NodeError(response.status, (parsed ?? {}) as NodeError["body"]);
    return parsed as T;
  }

  /** A public file's bytes, by digest, checked against the digest. */
  async file(digest: string): Promise<Uint8Array> {
    let response: Response;
    try {
      response = await this.deps.fetch(this.resolve(`/api/v1/files/${encodeURIComponent(digest)}`));
    } catch (error) {
      throw new HarnessError(`Couldn't reach ${this.base}: ${(error as Error).message}`);
    }
    if (!response.ok) throw new HarnessError(`The node has no public file ${digest} (${response.status})`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (sha256Digest(bytes) !== digest) throw new HarnessError(`The node's file ${digest} doesn't match its digest`);
    return bytes;
  }

  /**
   * Fetches a file through a link the node made, into `destination`, checking its size and
   * SHA-256 as it arrives. A file that doesn't match is removed, never kept.
   */
  async download(
    link: { url: string; method?: string; headers?: Record<string, string> },
    destination: string,
    expected: { digest: string; bytes: number },
  ): Promise<void> {
    let response: Response;
    try {
      response = await this.deps.fetch(this.resolve(link.url), { method: link.method ?? "GET", headers: link.headers ?? {} });
    } catch (error) {
      throw new HarnessError(`Couldn't fetch ${link.url}: ${(error as Error).message}`);
    }
    if (!response.ok || !response.body) {
      throw new HarnessError(`Fetching a file answered ${response.status}; ask for the job again for fresh links`);
    }
    const part = `${destination}.part`;
    const hash = createHash("sha256");
    const out = createWriteStream(part);
    let received = 0;
    try {
      const reader = response.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.length;
        if (received > expected.bytes) throw new HarnessError(`The file is larger than the ${expected.bytes} bytes its job names`);
        hash.update(value);
        if (!out.write(value)) await new Promise<void>((resolve) => out.once("drain", () => resolve()));
      }
      await new Promise<void>((resolve, reject) => out.end((error?: Error | null) => (error ? reject(error) : resolve())));
      const digest = `sha256:${hash.digest("hex")}`;
      if (received !== expected.bytes || digest !== expected.digest) {
        throw new HarnessError(
          `The file isn't what its job names: ${received} bytes with ${digest}, not ${expected.bytes} bytes with ${expected.digest}`,
        );
      }
      await rename(part, destination);
    } catch (error) {
      out.destroy();
      await rm(part, { force: true });
      throw error;
    }
  }
}

export interface Operator {
  id: string;
  secretKey: Uint8Array;
  publicKey: PublicKey;
  /** The model families the operator declared when it registered. */
  modelFamilies: string[];
}

export interface Credentials {
  operator?: string;
  key?: string;
}

/** The node to talk to: --node, then SJ_NODE, then sciencejournal.ai. */
export function nodeUrl(flag: string | undefined, deps: Pick<Deps, "env">): string {
  return flag ?? deps.env.SJ_NODE ?? DEFAULT_NODE;
}

/**
 * The operator the harness acts as: its secret key from --key or the key file the Python
 * client writes, and its ID from --operator or SJ_OPERATOR, or else the ID that key makes,
 * which is the operator's until it rotates its key. The key never leaves this process: it
 * signs, and only signatures are sent. The node confirms the ID holds this key.
 */
export async function signIn(credentials: Credentials, client: NodeClient, deps: Pick<Deps, "env" | "home">): Promise<Operator> {
  const secretKey = await loadSecretKey(credentials.key ?? defaultKeyPath(deps.home));
  const publicKey = publicKeyOf(secretKey);
  const named = credentials.operator ?? deps.env.SJ_OPERATOR;
  const id = named ?? operatorId(publicKey);
  if (!OperatorIdSchema.safeParse(id).success) {
    throw new HarnessError(`"${id}" isn't an operator ID: op: and the 64 hex digits of the SHA-256 of your first key`);
  }
  const registered = await client.get<{ key_digest: string; model_families: string[] }>(`/api/v1/operators/${id}`).catch((error) => {
    if (named || !(error instanceof NodeError && error.status === 404)) throw error;
    throw new HarnessError(
      `No operator on ${client.base} has ${id}, the ID your key makes: register first, or, once you have changed keys, name your ID with --operator or SJ_OPERATOR`,
    );
  });
  if (registered.key_digest !== keyDigest(publicKey)) {
    throw new HarnessError(`${id}'s key on ${client.base} isn't the one in your key file; check --operator and --key`);
  }
  return { id, secretKey, publicKey, modelFamilies: registered.model_families };
}

/** The secret key: the hex of an Ed25519 seed and an ML-DSA-44 seed, 32 bytes each. */
export async function loadSecretKey(path: string): Promise<Uint8Array> {
  let text: string;
  try {
    text = (await readFile(path, "utf8")).trim();
  } catch {
    throw new HarnessError(`No secret key at ${path}; give its file with --key`);
  }
  if (!new RegExp(`^[0-9a-fA-F]{${2 * SECRET_KEY_BYTES}}$`).test(text)) {
    // Say nothing about the contents: they may be a key in some other form.
    throw new HarnessError(`${path} doesn't hold a secret key: ${SECRET_KEY_BYTES} bytes in hex, the Ed25519 seed first`);
  }
  if (((await stat(path)).mode & 0o077) !== 0) {
    throw new HarnessError(`${path} can be read by others; only you should (chmod 600 ${path})`);
  }
  return new Uint8Array(Buffer.from(text, "hex"));
}

/** Signs an object as the operator, the way every signed entry is signed. */
export function signAs<T extends { type: string }>(operator: Operator, object: T) {
  return signObject(object, operator.secretKey);
}
