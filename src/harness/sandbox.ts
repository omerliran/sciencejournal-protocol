import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { basename, extname, join } from "node:path";
import { shellQuote } from "./format";
import { HarnessError } from "./context";
import { cloneTree, under } from "./files";
import { judgeDockerfile, rocqImage, type JudgeImage } from "./judge";

// The sandbox. Bundle code is someone else's code, so the harness runs it only in a container:
// no network, no added privileges, bounded processes, memory, CPU, and time, as the user who
// runs the harness rather than as root, seeing nothing of the machine but a copy of the work.
// Building the image may use the network, since installing what env/ declares needs it.

/** A container engine that answers. */
export interface Engine {
  command: "docker" | "podman";
  version: string;
  /** Whether the engine itself runs unprivileged, which changes how a run gets the user's files. */
  rootless: boolean;
  /** Whether Docker builds through BuildKit's buildx, which can keep an image in its own cache. */
  buildx: boolean;
  cpus: number;
  memoryBytes: number;
}

/** Where the image a run uses comes from, in the order the harness looks. */
export type ImagePlan =
  | { from: "given"; ref: string }
  | { from: "Dockerfile"; file: string }
  | { from: "requirements"; file: string; base: string }
  | { from: "conda"; file: string; base: string }
  /** The judge's own image for a proof check: the pinned checker and nothing of the work's. */
  | { from: "judge"; image: JudgeImage };

/** The official Python image, from the registry the node's own image comes from. */
export const PYTHON_IMAGE = "public.ecr.aws/docker/library/python:3.12-slim";
export const CONDA_IMAGE = "ghcr.io/mamba-org/micromamba:2";

export interface CommandPlan {
  command: string;
  /** The verifier's command, the bundle's code/run, the computations' files, or each proof's checker. */
  from: "given" | "code/run" | "produced_by" | "checker";
  files: string[];
}

export interface Limits {
  /** Wall-clock minutes before the run is stopped. */
  minutes: number;
  memory: string;
  cpus: number;
  pids: number;
}

/** Where a run's output goes, each piece with the stream it came on. */
export interface OutputSink {
  write(chunk: Uint8Array | string, stream?: "stdout" | "stderr"): void;
}

export interface ImageInfo {
  plan: ImagePlan;
  ref: string;
  id: string;
  /** The registry digests the image is known by, when it came from a registry. */
  digests: string[];
  /** Whether an image built earlier from the same inputs was used again. */
  reused: boolean;
  /**
   * The home of the user the image runs as, when that isn't root: a run keeps it, so tools
   * installed there, such as opam's or elan's, still find themselves.
   */
  home?: string;
  seconds: number;
}

export interface RunResult {
  /** The command's exit code; null when the run was stopped. */
  exitCode: number | null;
  timedOut: boolean;
  outOfMemory: boolean;
  startedAt: string;
  finishedAt: string;
  seconds: number;
}

/** What runs bundle code. The harness uses a container engine; nothing else runs bundle code. */
export interface Sandbox {
  engine: { name: string; version: string };
  /** The CPUs and memory available, which the default limits are taken from. */
  capacity: { cpus: number; memoryBytes: number };
  /** The image a run uses: given, pulled, or built from the bundle's env/. */
  image(plan: ImagePlan, context: { workspace: string; scratch: string; key: string }, log: OutputSink): Promise<ImageInfo>;
  run(request: { image: ImageInfo; workspace: string; command: string; limits: Limits }, log: OutputSink): Promise<RunResult>;
}

/** An image that didn't build or couldn't be fetched. */
export class ImageError extends HarnessError {
  override name = "ImageError";
}

/** Docker if it answers, else Podman; null when neither does. */
export async function findEngine(preferred?: string): Promise<Engine | null> {
  if (preferred !== undefined && preferred !== "docker" && preferred !== "podman") {
    throw new HarnessError(`--engine is docker or podman, not ${preferred}`);
  }
  for (const command of preferred ? [preferred as Engine["command"]] : (["docker", "podman"] as const)) {
    const format =
      command === "docker"
        ? "{{.ServerVersion}}|{{.NCPU}}|{{.MemTotal}}|{{json .SecurityOptions}}"
        : "{{.Version.Version}}|{{.Host.CPUs}}|{{.Host.MemTotal}}|{{.Host.Security.Rootless}}";
    const info = await capture(command, ["info", "--format", format]);
    if (info.code !== 0) continue;
    const [version, cpus, memory, security] = info.stdout.trim().split("|");
    return {
      command,
      version,
      rootless: command === "docker" ? security.includes("name=rootless") : security === "true",
      buildx: command === "docker" && (await capture(command, ["buildx", "version"])).code === 0,
      cpus: Number(cpus) || 1,
      memoryBytes: Number(memory) || 2 ** 30,
    };
  }
  return null;
}

const BUILD_FILES = ["env/Dockerfile", "env/Containerfile"];
const REQUIREMENTS = "env/requirements.txt";
const CONDA_FILES = ["env/environment.yml", "env/environment.yaml"];

/**
 * The image to run in: the one given; else env/Dockerfile or env/Containerfile, built with the
 * verification inputs as its context; else env/requirements.txt installed on the official
 * Python image; else env/environment.yml installed on a micromamba image. Null when the bundle
 * declares none of these, and the agent has to say.
 */
export function planImage(paths: ReadonlySet<string>, given?: string): ImagePlan | null {
  if (given) return { from: "given", ref: given };
  const dockerfile = BUILD_FILES.find((file) => paths.has(file));
  if (dockerfile) return { from: "Dockerfile", file: dockerfile };
  if (paths.has(REQUIREMENTS)) return { from: "requirements", file: REQUIREMENTS, base: PYTHON_IMAGE };
  const conda = CONDA_FILES.find((file) => paths.has(file));
  if (conda) return { from: "conda", file: conda, base: CONDA_IMAGE };
  return null;
}

export function describePlan(plan: ImagePlan): string {
  switch (plan.from) {
    case "given":
      return "the image given with --image";
    case "Dockerfile":
      return `built from ${plan.file}, with code/, env/, data/, and proofs/ as its context`;
    case "requirements":
      return `${plan.file} installed with pip on ${plan.base}`;
    case "conda":
      return `${plan.file} installed with micromamba on ${plan.base}`;
    case "judge":
      return plan.image.checker === "lean4"
        ? `the judge's image, built from ${plan.image.toolchain}${plan.image.mathlib ? ` and Mathlib at ${plan.image.mathlib}` : ""} alone`
        : `the judge's image, Rocq's official ${rocqImage(plan.image.version)}`;
  }
}

/** What runs a file of each kind, by its extension. */
const INTERPRETERS: Record<string, string> = {
  ".py": "python3",
  ".r": "Rscript",
  ".jl": "julia",
  ".sh": "sh",
  ".bash": "bash",
  ".js": "node",
  ".mjs": "node",
  ".cjs": "node",
};

/**
 * The command to run, from the bundle's root: the one given; else code/run, run with sh as
 * Code Ocean runs its capsules; else each file the claims' computations name as produced_by,
 * in the order they first appear, with the interpreter its extension or its first line names.
 */
export function planCommand(
  paths: ReadonlySet<string>,
  producedBy: readonly string[],
  given: string | undefined,
  firstLine: (path: string) => string | undefined,
): CommandPlan {
  if (given) return { command: given, from: "given", files: [] };
  if (paths.has("code/run")) return { command: "sh code/run", from: "code/run", files: ["code/run"] };
  const files = [...new Set(producedBy)];
  if (files.length === 0) {
    throw new HarnessError("Nothing names code to run: no claim's evidence has a computation. Give a command with --command.");
  }
  const steps = files.map((file) => {
    if (!paths.has(file)) throw new HarnessError(`${file}, which a computation names, isn't in the bundle`);
    const interpreter = INTERPRETERS[extname(file).toLowerCase()];
    if (interpreter) return `${interpreter} ${shellQuote(file)}`;
    const shebang = /^#!\s*(\S.*)$/.exec(firstLine(file) ?? "")?.[1]?.trim();
    if (shebang) return `${shebang} ${shellQuote(file)}`;
    throw new HarnessError(`The harness can't tell what runs ${file}. Give a command with --command.`);
  });
  return { command: steps.length === 1 ? steps[0] : ["set -e", ...steps].join("; "), from: "produced_by", files };
}

/** The limits a run gets: the declared minutes times 1.5, and most of the engine's machine. */
export function limitsFor(
  capacity: Sandbox["capacity"],
  declaredMinutes: number,
  given: Partial<Limits> = {},
): Limits {
  if (given.memory !== undefined && !/^[0-9]+(\.[0-9]+)?[bkmg]?$/i.test(given.memory)) {
    throw new HarnessError(`--memory takes an amount such as 8g or 512m, not ${given.memory}`);
  }
  for (const [name, value] of Object.entries({ minutes: given.minutes, cpus: given.cpus, pids: given.pids })) {
    if (value !== undefined && !(value > 0 && Number.isFinite(value))) throw new HarnessError(`--${name} takes a positive number`);
  }
  return {
    minutes: given.minutes ?? declaredMinutes * 1.5,
    memory: given.memory ?? `${Math.max(512, Math.floor((capacity.memoryBytes * 0.75) / 2 ** 20))}m`,
    cpus: given.cpus ?? capacity.cpus,
    pids: given.pids ?? 4096,
  };
}

/** The arguments that run `command` in the sandbox: everything the run may and may not do. */
export function runArguments(
  engine: Pick<Engine, "command" | "rootless">,
  request: { name: string; image: string; workspace: string; command: string; limits: Limits; home?: string },
  user: { uid: number; gid: number } | null,
): string[] {
  if (request.workspace.includes(",")) {
    throw new HarnessError(`The workspace's path can't hold a comma, which the engine's mount syntax splits on: ${request.workspace}`);
  }
  const { limits } = request;
  return [
    "run",
    "--name",
    request.name,
    "--init",
    "--network",
    "none",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--pids-limit",
    String(limits.pids),
    "--memory",
    limits.memory,
    "--memory-swap",
    limits.memory,
    "--cpus",
    String(limits.cpus),
    ...asUser(engine, user, request.home),
    "--tmpfs",
    "/tmp:rw,exec,nosuid,nodev",
    "--mount",
    `type=bind,source=${request.workspace},target=/work`,
    "--workdir",
    "/work",
    request.image,
    "sh",
    "-c",
    request.command,
  ];
}

/**
 * Runs as the harness's own user, so whatever the run writes belongs to them and nothing it
 * does is root's. A rootless engine already maps the container's root to that user; Podman
 * does it with keep-id. HOME stays the image user's when the image runs as someone other than
 * root, where tools such as opam and elan keep their installs; otherwise, since root's home is
 * private, it is /tmp. Caches go to /tmp either way, which is the run's own.
 */
function asUser(engine: Pick<Engine, "command" | "rootless">, user: { uid: number; gid: number } | null, home?: string): string[] {
  if (!user) return [];
  const env = ["--env", `HOME=${home ?? "/tmp"}`, "--env", "XDG_CACHE_HOME=/tmp/.cache"];
  if (engine.rootless) return engine.command === "podman" ? ["--userns", "keep-id", ...env] : [];
  return ["--user", `${user.uid}:${user.gid}`, ...env];
}

/** The generated Dockerfile for an environment declared by a lockfile rather than a Dockerfile. */
export function environmentDockerfile(plan: Extract<ImagePlan, { from: "requirements" | "conda" }>): string {
  const file = basename(plan.file);
  if (plan.from === "requirements") {
    return [
      `FROM ${plan.base}`,
      "ENV PIP_DISABLE_PIP_VERSION_CHECK=1",
      "COPY env/ /opt/sj-env/",
      `RUN pip install --no-cache-dir --root-user-action=ignore -r /opt/sj-env/${file}`,
      "",
    ].join("\n");
  }
  return [
    `FROM ${plan.base}`,
    "COPY --chown=$MAMBA_USER:$MAMBA_USER env/ /tmp/sj-env/",
    `RUN micromamba install --yes --name base --file /tmp/sj-env/${file} && micromamba clean --all --yes`,
    "",
  ].join("\n");
}

const BUILD_MINUTES = 60;

/**
 * How to build an image into the engine's own store. A buildx builder of another driver keeps
 * what it builds in its cache unless told to load it.
 */
export function buildCommand(engine: Pick<Engine, "command" | "buildx">): string[] {
  return engine.buildx ? ["buildx", "build", "--load", "--progress", "plain"] : ["build"];
}

/** The sandbox on a container engine. */
export function containerSandbox(engine: Engine): Sandbox {
  const run = (args: string[], log: OutputSink, minutes: number) => stream(engine.command, args, log, minutes);
  const inspect = async (ref: string) => {
    const result = await capture(engine.command, ["image", "inspect", "--format", "{{.Id}}|{{json .RepoDigests}}", ref]);
    if (result.code !== 0) return null;
    const [id, digests] = result.stdout.trim().split("|");
    return { id, digests: (JSON.parse(digests || "null") as string[] | null) ?? [] };
  };
  /**
   * The home of the user an image runs as, when it isn't root, read by running the image's own
   * shell with every limit a run has. Undefined for root, or an image without a shell.
   */
  const imageHome = async (id: string): Promise<string | undefined> => {
    const user = (await capture(engine.command, ["image", "inspect", "--format", "{{.Config.User}}", id])).stdout.trim();
    if (user === "" || /^(root|0)(:.*)?$/.test(user)) return undefined;
    const probe = await capture(engine.command, [
      "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
      "--pids-limit", "64", "--memory", "256m", "--entrypoint", "/bin/sh", id, "-c", 'printf %s "$HOME"',
    ]);
    const home = probe.stdout.trim();
    return probe.code === 0 && /^\/[^\s]*$/.test(home) && home !== "/" ? home : undefined;
  };

  return {
    engine: { name: engine.command, version: engine.version },
    capacity: { cpus: engine.cpus, memoryBytes: engine.memoryBytes },

    async image(plan, { workspace, scratch, key }, log) {
      const started = Date.now();
      const done = async (ref: string, found: { id: string; digests: string[] }, reused: boolean): Promise<ImageInfo> => {
        const home = await imageHome(found.id);
        return { plan, ref, ...found, reused, ...(home && { home }), seconds: (Date.now() - started) / 1000 };
      };
      const pulled = plan.from === "given" ? plan.ref : plan.from === "judge" && plan.image.checker === "rocq" ? rocqImage(plan.image.version) : null;
      if (pulled) {
        const present = await inspect(pulled);
        if (present) return done(pulled, present, true);
        const pull = await run(["pull", pulled], log, BUILD_MINUTES);
        const found = pull.code === 0 ? await inspect(pulled) : null;
        if (!found) throw new ImageError(`Couldn't pull ${pulled} (exit code ${pull.code}); see build.log`);
        return done(pulled, found, false);
      }
      const tag = `sj-harness:${key}`;
      const built = await inspect(tag);
      if (built) return done(tag, built, true);
      let file: string;
      let context: string;
      if (plan.from === "Dockerfile") {
        file = under(workspace, plan.file);
        context = workspace;
      } else if (plan.from === "judge" && plan.image.checker === "lean4") {
        // Built from the pinned checker alone: nothing of the work is in its context.
        await mkdir(scratch, { recursive: true });
        file = join(scratch, "Dockerfile");
        await writeFile(file, judgeDockerfile(plan.image));
        context = scratch;
      } else if (plan.from === "requirements" || plan.from === "conda") {
        await cloneTree(join(workspace, "env"), join(scratch, "env"));
        file = join(scratch, "Dockerfile");
        await writeFile(file, environmentDockerfile(plan));
        context = scratch;
      } else {
        throw new ImageError(`The harness can't prepare an image ${describePlan(plan)}`);
      }
      const result = await run([...buildCommand(engine), "--tag", tag, "--file", file, context], log, BUILD_MINUTES);
      const found = result.code === 0 ? await inspect(tag) : null;
      if (!found) {
        const why = result.timedOut ? `took more than ${BUILD_MINUTES} minutes` : `failed with exit code ${result.code}`;
        throw new ImageError(`The image ${describePlan(plan)} ${why}; see build.log`);
      }
      return done(tag, found, false);
    },

    async run({ image, workspace, command, limits }, log) {
      const name = `sj-harness-${randomBytes(8).toString("hex")}`;
      const user = typeof process.getuid === "function" && typeof process.getgid === "function"
        ? { uid: process.getuid(), gid: process.getgid() }
        : null;
      const args = runArguments(engine, { name, image: image.id, workspace, command, limits, home: image.home }, user);
      // Stopping the harness stops the run: the container doesn't outlive it.
      const stop = () => {
        spawnSync(engine.command, ["rm", "--force", name], { stdio: "ignore" });
        process.exit(130);
      };
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
      const startedAt = new Date();
      try {
        const result = await stream(engine.command, args, log, limits.minutes, () =>
          capture(engine.command, ["rm", "--force", name]).then(() => undefined),
        );
        const finishedAt = new Date();
        const state = await capture(engine.command, ["inspect", "--format", "{{.State.OOMKilled}}", name]);
        return {
          exitCode: result.timedOut ? null : result.code,
          timedOut: result.timedOut,
          outOfMemory: state.stdout.trim() === "true",
          startedAt: startedAt.toISOString(),
          finishedAt: finishedAt.toISOString(),
          seconds: (finishedAt.getTime() - startedAt.getTime()) / 1000,
        };
      } finally {
        await capture(engine.command, ["rm", "--force", name]);
        process.removeListener("SIGINT", stop);
        process.removeListener("SIGTERM", stop);
      }
    },
  };
}

/** Runs an engine command to completion and returns what it printed. Never for bundle code. */
async function capture(command: string, args: string[], seconds = 60): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve) => {
    let stdout = "";
    let settled = false;
    const finish = (code: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout });
    };
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "ignore"] });
    const timer = setTimeout(() => child.kill("SIGKILL"), seconds * 1000);
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString("utf8")));
    child.on("error", () => finish(null));
    child.on("close", (code) => finish(code));
  });
}

/**
 * Runs an engine command, writing everything it prints to `log`, and stops it after `minutes`:
 * with `stop` when given (which stops the container itself), else by killing the command.
 */
function stream(
  command: string,
  args: string[],
  log: OutputSink,
  minutes: number,
  stop?: () => Promise<void>,
): Promise<{ code: number | null; timedOut: boolean }> {
  return new Promise((resolve) => {
    let timedOut = false;
    let settled = false;
    const finish = (code: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, timedOut });
    };
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    const timer = setTimeout(() => {
      timedOut = true;
      if (stop) void stop();
      else child.kill("SIGKILL");
    }, minutes * 60_000);
    child.stdout.on("data", (chunk: Buffer) => log.write(chunk, "stdout"));
    child.stderr.on("data", (chunk: Buffer) => log.write(chunk, "stderr"));
    child.on("error", (error) => {
      log.write(`${error.message}\n`, "stderr");
      finish(null);
    });
    child.on("close", (code) => finish(code));
  });
}
