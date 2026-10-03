import { describe, expect, it } from "vitest";
import {
  buildCommand,
  CONDA_IMAGE,
  environmentDockerfile,
  limitsFor,
  planCommand,
  planImage,
  PYTHON_IMAGE,
  runArguments,
  type Limits,
} from "./sandbox";

const paths = (...list: string[]) => new Set(list);

describe("planImage", () => {
  it("takes the image given, then a Dockerfile, a Containerfile, requirements.txt, and environment.yml, in that order", () => {
    const all = ["env/Dockerfile", "env/Containerfile", "env/requirements.txt", "env/environment.yml"];
    expect(planImage(paths(...all), "rocker/r-ver:4.4")).toEqual({ from: "given", ref: "rocker/r-ver:4.4" });
    expect(planImage(paths(...all))).toEqual({ from: "Dockerfile", file: "env/Dockerfile" });
    expect(planImage(paths(...all.slice(1)))).toEqual({ from: "Dockerfile", file: "env/Containerfile" });
    expect(planImage(paths(...all.slice(2)))).toEqual({ from: "requirements", file: "env/requirements.txt", base: PYTHON_IMAGE });
    expect(planImage(paths(...all.slice(3)))).toEqual({ from: "conda", file: "env/environment.yml", base: CONDA_IMAGE });
    expect(planImage(paths("env/environment.yaml"))).toEqual({ from: "conda", file: "env/environment.yaml", base: CONDA_IMAGE });
  });

  it("has nothing to offer a bundle that declares no environment, or one somewhere else", () => {
    expect(planImage(paths("code/run", "code/requirements.txt", "env/lock.txt"))).toBeNull();
  });
});

describe("environmentDockerfile", () => {
  it("installs requirements.txt with pip on the Python image, from env/ as a whole", () => {
    const dockerfile = environmentDockerfile({ from: "requirements", file: "env/requirements.txt", base: PYTHON_IMAGE });
    expect(dockerfile.split("\n")).toEqual([
      `FROM ${PYTHON_IMAGE}`,
      "ENV PIP_DISABLE_PIP_VERSION_CHECK=1",
      "COPY env/ /opt/sj-env/",
      "RUN pip install --no-cache-dir --root-user-action=ignore -r /opt/sj-env/requirements.txt",
      "",
    ]);
  });

  it("installs environment.yml into micromamba's base environment", () => {
    const dockerfile = environmentDockerfile({ from: "conda", file: "env/environment.yaml", base: CONDA_IMAGE });
    expect(dockerfile).toContain(`FROM ${CONDA_IMAGE}\n`);
    expect(dockerfile).toContain("micromamba install --yes --name base --file /tmp/sj-env/environment.yaml");
  });
});

describe("planCommand", () => {
  const noShebang = () => undefined;

  it("runs the command given, else code/run with sh", () => {
    const bundle = paths("code/run", "code/eval.py");
    expect(planCommand(bundle, ["code/eval.py"], "make all", noShebang)).toEqual({ command: "make all", from: "given", files: [] });
    expect(planCommand(bundle, ["code/eval.py"], undefined, noShebang)).toEqual({ command: "sh code/run", from: "code/run", files: ["code/run"] });
  });

  it("else runs each file the computations name, once, in order of first appearance, with its interpreter", () => {
    const bundle = paths("code/fit.R", "code/eval.py", "code/plot.jl", "code/a b.sh", "code/stats.mjs");
    const plan = planCommand(
      bundle,
      ["code/eval.py", "code/fit.R", "code/eval.py", "code/plot.jl", "code/a b.sh", "code/stats.mjs"],
      undefined,
      noShebang,
    );
    expect(plan).toEqual({
      command: "set -e; python3 code/eval.py; Rscript code/fit.R; julia code/plot.jl; sh 'code/a b.sh'; node code/stats.mjs",
      from: "produced_by",
      files: ["code/eval.py", "code/fit.R", "code/plot.jl", "code/a b.sh", "code/stats.mjs"],
    });
    expect(planCommand(paths("code/eval.py"), ["code/eval.py"], undefined, noShebang).command).toBe("python3 code/eval.py");
  });

  it("reads a file's first line for its interpreter when its name doesn't say", () => {
    const plan = planCommand(paths("code/analyze"), ["code/analyze"], undefined, () => "#!/usr/bin/env python3");
    expect(plan.command).toBe("/usr/bin/env python3 code/analyze");
  });

  it("asks for a command when it can't tell what runs a file, or there is nothing to run", () => {
    expect(() => planCommand(paths("code/model.do"), ["code/model.do"], undefined, noShebang)).toThrow(/--command/);
    expect(() => planCommand(paths("code/x.py"), [], undefined, noShebang)).toThrow(/--command/);
    expect(() => planCommand(paths(), ["code/x.py"], undefined, noShebang)).toThrow(/isn't in the bundle/);
  });
});

describe("limitsFor", () => {
  const capacity = { cpus: 8, memoryBytes: 16 * 2 ** 30 };

  it("gives a run the declared minutes times 1.5 and most of the engine's machine", () => {
    expect(limitsFor(capacity, 30)).toEqual({ minutes: 45, memory: "12288m", cpus: 8, pids: 4096 });
  });

  it("takes what the verifier says instead, and refuses what makes no sense", () => {
    expect(limitsFor(capacity, 30, { minutes: 5, memory: "2g", cpus: 2, pids: 64 })).toEqual({ minutes: 5, memory: "2g", cpus: 2, pids: 64 });
    expect(() => limitsFor(capacity, 30, { memory: "lots" })).toThrow(/--memory/);
    expect(() => limitsFor(capacity, 30, { cpus: 0 })).toThrow(/--cpus/);
    expect(() => limitsFor(capacity, 30, { minutes: Number.NaN })).toThrow(/--minutes/);
  });
});

describe("runArguments", () => {
  const limits: Limits = { minutes: 45, memory: "8g", cpus: 4, pids: 1024 };
  const request = { name: "sj-harness-1", image: "sha256:abc", workspace: "/jobs/job-1/workspace", command: "sh code/run", limits };

  it("runs with no network, no privileges, bounded processes, memory, and CPU, as the user, in a copy of the work", () => {
    const args = runArguments({ command: "docker", rootless: false }, request, { uid: 501, gid: 20 });
    const value = (flag: string) => args[args.indexOf(flag) + 1];
    expect(args[0]).toBe("run");
    expect(value("--network")).toBe("none");
    expect(value("--cap-drop")).toBe("ALL");
    expect(value("--security-opt")).toBe("no-new-privileges");
    expect([value("--pids-limit"), value("--memory"), value("--memory-swap"), value("--cpus")]).toEqual(["1024", "8g", "8g", "4"]);
    expect([value("--user"), value("--env")]).toEqual(["501:20", "HOME=/tmp"]);
    expect(value("--mount")).toBe("type=bind,source=/jobs/job-1/workspace,target=/work");
    expect(value("--workdir")).toBe("/work");
    expect(args).not.toContain("--privileged");
    expect(args.slice(-4)).toEqual(["sha256:abc", "sh", "-c", "sh code/run"]);
  });

  it("lets a rootless engine map the user itself", () => {
    expect(runArguments({ command: "docker", rootless: true }, request, { uid: 501, gid: 20 })).not.toContain("--user");
    const podman = runArguments({ command: "podman", rootless: true }, request, { uid: 501, gid: 20 });
    expect(podman.slice(podman.indexOf("--userns"), podman.indexOf("--userns") + 2)).toEqual(["--userns", "keep-id"]);
    expect(podman).not.toContain("--user");
  });

  it("refuses a workspace path the mount syntax would split", () => {
    expect(() => runArguments({ command: "docker", rootless: false }, { ...request, workspace: "/jobs/a,b/workspace" }, null)).toThrow(/comma/);
  });
});

describe("buildCommand", () => {
  it("loads what buildx builds into the engine's own store, whatever the builder", () => {
    expect(buildCommand({ command: "docker", buildx: true })).toEqual(["buildx", "build", "--load", "--progress", "plain"]);
    expect(buildCommand({ command: "docker", buildx: false })).toEqual(["build"]);
    expect(buildCommand({ command: "podman", buildx: false })).toEqual(["build"]);
  });
});
