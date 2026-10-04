import { sha256Hex } from "../hash";
import { JsonError, parseJson } from "../json";
import { MonitorError, type LogSource } from "../monitor";

export interface HttpOptions {
  /** The fetch to use; the global one by default. */
  fetch?: typeof fetch;
  /** How long one request may take. */
  timeoutMs?: number;
  /** How many times to try a request that failed in a way that may pass: no answer, 429, or 5xx. */
  attempts?: number;
  /** How long to wait before the second try; each later try waits that much longer again. */
  retryMs?: number;
}

/**
 * Where a node serves its API: an http or https URL, without a trailing slash, such as
 * https://sciencejournal.ai. Throws for anything else.
 */
export function nodeUrl(input: string): string {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new MonitorError(`${input} isn't a URL; give the node's address, such as https://sciencejournal.ai`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new MonitorError(`${input} isn't an http or https URL`);
  if (url.search || url.hash) throw new MonitorError(`${input} has a query or fragment; give just the node's address`);
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

/**
 * GETs `url`, trying again a request that failed in a way that may pass, and returns the
 * answer's text; null for a 404 when `missing` allows one.
 */
export async function getText(url: string, accept: string, options: HttpOptions = {}, missing = false): Promise<string | null> {
  const { fetch: get = fetch, timeoutMs = 30_000, attempts = 3, retryMs = 1000 } = options;
  for (let attempt = 1; ; attempt++) {
    const retry = attempt < attempts;
    let response: Response;
    try {
      response = await get(url, { headers: { accept }, signal: AbortSignal.timeout(timeoutMs) });
    } catch (error) {
      if (retry) {
        await pause(retryMs * attempt);
        continue;
      }
      throw new MonitorError(`GET ${url} failed: ${reason(error)}`);
    }
    const text = await response.text();
    if (response.ok) return text;
    if (missing && response.status === 404) return null;
    if (retry && (response.status === 429 || response.status >= 500)) {
      await pause(retryMs * attempt);
      continue;
    }
    throw new MonitorError(`GET ${url} answered ${response.status}${errorMessage(text)}`);
  }
}

/** A node's public log API over HTTP. Answers are read as strict I-JSON, and checkpoints as text. */
export function httpSource(node: string, options: HttpOptions = {}): LogSource {
  const base = nodeUrl(node);

  async function read(path: string): Promise<unknown> {
    const url = `${base}${path}`;
    const text = (await getText(url, "application/json", options))!;
    try {
      return parseJson(text);
    } catch (error) {
      if (!(error instanceof JsonError)) throw error;
      throw new MonitorError(`GET ${url} answered with something other than I-JSON: ${error.message}`);
    }
  }

  return {
    log: () => read("/api/v1/log"),
    entries: (start, end) => read(`/api/v1/log/entries?start=${start}&end=${end}`),
    signedEntry: (index) => read(`/api/v1/log/entries/${index}/signed`),
    consistencyProof: (first, second) => read(`/api/v1/log/proofs/consistency?first=${first}&second=${second}`),
    checkpoint: (size) => getText(`${base}/api/v1/log/checkpoint${size === undefined ? "" : `?size=${size}`}`, "text/plain", options, true),
    receipt: (index) => read(`/api/v1/log/entries/${index}`),
  };
}

/**
 * Where a witness serves the checkpoint it last cosigned for a log (c2sp.org/tlog-witness):
 * under its monitoring prefix, by the SHA-256 of the log's origin in hex.
 */
export function witnessCheckpoint(prefix: string, options: HttpOptions = {}): (origin: string) => Promise<string | null> {
  const base = nodeUrl(prefix);
  return (origin) => getText(`${base}/${sha256Hex(origin)}/checkpoint`, "text/plain", options, true);
}

/** The `error` a node puts in a failed answer, if it gave one. */
function errorMessage(text: string): string {
  try {
    const body = JSON.parse(text) as { error?: unknown };
    return typeof body.error === "string" ? `: ${body.error}` : "";
  } catch {
    return "";
  }
}

function reason(error: unknown): string {
  if (!(error instanceof Error)) return String(error);
  // fetch reports network failures as "fetch failed" with the real reason as the cause.
  const cause = error.cause instanceof Error ? ` (${error.cause.message})` : "";
  return `${error.message}${cause}`;
}

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
