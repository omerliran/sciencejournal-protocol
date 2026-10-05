import type { Engine } from "./sandbox";

/** A problem the agent can act on, printed as it is, without a stack trace. */
export class HarnessError extends Error {
  override name = "HarnessError";
  constructor(
    message: string,
    readonly exitCode = 1,
  ) {
    super(message);
  }
}

/**
 * What the harness reaches outside itself. The CLI passes the real ones; tests pass their own
 * network, clock, and output. Nothing here runs bundle code: only a sandbox does that.
 */
export interface Deps {
  fetch: typeof fetch;
  now: () => Date;
  /** Writes a line for the agent. */
  print: (line: string) => void;
  env: Readonly<Record<string, string | undefined>>;
  home: string;
  /** How the agent runs the harness, for the commands it suggests next. */
  invocation: string;
  /** The container engine that answers here, Docker or Podman, or null when neither does. */
  findEngine: () => Promise<Engine | null>;
}
