import { describe, expect, it } from "vitest";
import { signObject } from "./entries";
import {
  checkRecord,
  createRecord,
  recordDigest,
  resolveTask,
  taskId,
  TaskEntrySchema,
  toUnits,
  type LoggedObservation,
  type TaskEntry,
} from "./fieldwork";
import { generateKeyPair, keyDigest } from "./signing";

const operator = generateKeyPair();

function task(overrides: Record<string, unknown> = {}): TaskEntry {
  return signObject(
    {
      type: "task",
      operator_key_digest: keyDigest(operator.publicKey),
      title: "Water temperature at the pier",
      instructions: "Lower the thermometer 10 cm below the surface at the end of the pier and wait a minute.",
      fields: ["ecology"],
      place: { name: "Lake Merritt pier, Oakland", lat: 37.8044, lon: -122.2585, radius_m: 100 },
      opens_at: "2026-10-03T00:00:00Z",
      closes_at: "2026-10-10T00:00:00Z",
      measurements: [
        { key: "temp_c", label: "Water temperature", kind: "number", unit: "°C", decimals: 1, tolerance: 0.5, min: -5, max: 45 },
        { key: "clarity", label: "Clarity", kind: "choice", options: ["clear", "murky"] },
        { key: "notes", label: "Notes", kind: "text" },
      ],
      replicas: 3,
      max_observations: 5,
      ...overrides,
    } as Omit<TaskEntry, "sig">,
    operator.secretKey,
  );
}

const TASK = task();
const ID = taskId(TASK);

let next = 0;
function observed(values: Record<string, number | string>, extra: Partial<LoggedObservation> = {}): LoggedObservation {
  next += 1;
  return {
    index: next,
    timestamp: `2026-10-04T12:00:${String(next % 60).padStart(2, "0")}Z`,
    observer: `obs:${next.toString(16).padStart(64, "0")}`,
    record: createRecord(ID, values),
    ...extra,
  };
}
const DURING = new Date("2026-10-05T00:00:00Z");
const AFTER = new Date("2026-10-10T00:00:00Z");

describe("tasks", () => {
  it("accept a well-formed task", () => {
    expect(TaskEntrySchema.safeParse(TASK).success).toBe(true);
  });

  it.each([
    ["a window over 90 days", { closes_at: "2027-01-02T00:00:00Z" }, "/closes_at"],
    ["a window that closes before it opens", { closes_at: "2026-10-02T00:00:00Z" }, "/closes_at"],
    ["fewer allowed observations than replicas", { replicas: 4, max_observations: 3 }, "/max_observations"],
    ["a single replica", { replicas: 1 }, "/replicas"],
    ["only text to record", { measurements: [{ key: "notes", label: "Notes", kind: "text" }] }, "/measurements"],
    [
      "repeated measurement keys",
      { measurements: [TASK.measurements[0], { ...TASK.measurements[0], label: "Again" }] },
      "/measurements",
    ],
    [
      "a tolerance finer than the decimals",
      { measurements: [{ ...TASK.measurements[0], tolerance: 0.25 }] },
      "/measurements/0/tolerance",
    ],
    ["a range that ends before it starts", { measurements: [{ ...TASK.measurements[0], min: 10, max: 5 }] }, "/measurements/0/max"],
    ["repeated choices", { measurements: [{ key: "c", label: "C", kind: "choice", options: ["a", "a"] }] }, "/measurements/0/options"],
    ["an unknown field", { reward: 5 }, ""],
  ])("reject %s", (_, overrides, path) => {
    const result = TaskEntrySchema.safeParse({ ...TASK, ...overrides });
    expect(result.success).toBe(false);
    const paths = result.error!.issues.map((issue) => `/${issue.path.join("/")}`.replace(/\/$/, ""));
    expect(paths).toContain(path);
  });

  it("are named by their content, not their signature", () => {
    const resigned = signObject({ ...TASK, sig: undefined }, generateKeyPair().secretKey);
    expect(taskId(resigned)).toBe(ID);
    expect(taskId(task({ replicas: 2 }))).not.toBe(ID);
    expect(ID).toMatch(/^task:[0-9a-f]{64}$/);
  });
});

describe("toUnits", () => {
  it.each([
    [18.6, 1, 186],
    [-3.25, 2, -325],
    [7, 0, 7],
    [0, 3, 0],
  ])("counts %d in units of %d decimals", (value, decimals, units) => {
    expect(toUnits(value, decimals)).toBe(units);
  });

  it.each([
    [0.1 + 0.2, 1],
    [2.5, 0],
    [1e300, 0],
  ])("rejects %d with %d decimals", (value, decimals) => {
    expect(toUnits(value, decimals)).toBeNull();
  });
});

describe("records", () => {
  it("accept every number and choice, with optional text", () => {
    expect(checkRecord(TASK, createRecord(ID, { temp_c: 18.5, clarity: "clear" }))).toEqual([]);
    expect(checkRecord(TASK, createRecord(ID, { temp_c: 18.5, clarity: "clear", notes: "Windy" }))).toEqual([]);
  });

  it("report each problem at its value", () => {
    const issues = checkRecord(TASK, createRecord(ID, { temp_c: 18.55, clarity: "green", extra: 1 }));
    expect(issues.map(({ path }) => path)).toEqual(["/values/extra", "/values/temp_c", "/values/clarity"]);
    expect(checkRecord(TASK, createRecord(ID, { clarity: "clear", constructor: 1 })).map(({ path }) => path)).toEqual([
      "/values/constructor",
      "/values/temp_c",
    ]);
    expect(checkRecord(TASK, createRecord(ID, { temp_c: 99, clarity: "clear", notes: " " }))).toHaveLength(2);
  });

  it("must name their task", () => {
    expect(checkRecord(TASK, createRecord(taskId(task({ replicas: 2 })), { temp_c: 1, clarity: "clear" }))).toEqual([
      { path: "/task", message: "Names a different task" },
    ]);
  });

  it("get a fresh nonce, so equal values seal to different digests", () => {
    const a = createRecord(ID, { temp_c: 18.5, clarity: "clear" });
    const b = createRecord(ID, { temp_c: 18.5, clarity: "clear" });
    expect(a.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(recordDigest(a)).not.toBe(recordDigest(b));
  });
});

describe("resolveTask", () => {
  it("stays open until k observations match", () => {
    const observations = [observed({ temp_c: 18.0, clarity: "clear" }), observed({ temp_c: 18.2, clarity: "clear" })];
    expect(resolveTask(TASK, observations, DURING)).toEqual({ status: "open" });
  });

  it("corroborates on the observation that completes a matching set, with median values", () => {
    const observations = [
      observed({ temp_c: 18.0, clarity: "clear" }),
      observed({ temp_c: 25.0, clarity: "clear" }),
      observed({ temp_c: 18.4, clarity: "clear", notes: "Ducks nearby" }),
      observed({ temp_c: 18.1, clarity: "clear" }),
    ];
    expect(resolveTask(TASK, observations, DURING)).toEqual({
      status: "corroborated",
      closed_at: observations[3].timestamp,
      corroborating: [observations[0].index, observations[2].index, observations[3].index],
      values: { temp_c: 18.1, clarity: "clear" },
    });
  });

  it("compares numbers exactly at the tolerance, where floating point would not", () => {
    // 18.6 - 18.1 is 0.5000000000000071 in binary floating point.
    const pair = task({ replicas: 2 });
    const pairId = taskId(pair);
    const observations = [observed({ temp_c: 18.1, clarity: "clear" }), observed({ temp_c: 18.6, clarity: "clear" })].map(
      (o) => ({ ...o, record: { ...o.record, task: pairId } }),
    );
    expect(resolveTask(pair, observations, DURING)).toMatchObject({
      status: "corroborated",
      values: { temp_c: 18.35 },
    });
  });

  it("needs every choice to match", () => {
    const observations = [
      observed({ temp_c: 18.0, clarity: "clear" }),
      observed({ temp_c: 18.0, clarity: "murky" }),
      observed({ temp_c: 18.0, clarity: "clear" }),
    ];
    expect(resolveTask(TASK, observations, DURING)).toEqual({ status: "open" });
  });

  it("anchors the set on one observation, so its spread can reach twice the tolerance", () => {
    const observations = [
      observed({ temp_c: 18.0, clarity: "clear" }),
      observed({ temp_c: 18.5, clarity: "clear" }),
      observed({ temp_c: 19.0, clarity: "clear" }),
    ];
    expect(resolveTask(TASK, observations, DURING)).toMatchObject({
      status: "corroborated",
      values: { temp_c: 18.5 },
    });
  });

  it("is unresolved at the maximum, or once the window ends", () => {
    const scattered = [10, 12, 14, 16, 18].map((temp_c) => observed({ temp_c, clarity: "clear" }));
    expect(resolveTask(TASK, scattered, DURING)).toEqual({ status: "unresolved", closed_at: scattered[4].timestamp });
    expect(resolveTask(TASK, scattered.slice(0, 2), AFTER)).toEqual({ status: "unresolved", closed_at: TASK.closes_at });
  });

  it("counts each observer once, inside the window, with a valid record, in log order", () => {
    const first = observed({ temp_c: 18.0, clarity: "clear" });
    const observations = [
      observed({ temp_c: 18.0, clarity: "clear" }, { observer: first.observer }),
      observed({ temp_c: 18.0, clarity: "clear" }, { timestamp: "2026-10-02T23:59:59Z" }),
      observed({ temp_c: 18.0, clarity: "clear" }, { timestamp: TASK.closes_at }),
      observed({ temp_c: 18.0, clarity: "clear", extra: 1 }),
      observed({ temp_c: 18.1, clarity: "clear" }),
      first,
    ];
    expect(resolveTask(TASK, observations, DURING)).toEqual({ status: "open" });
    const third = observed({ temp_c: 18.2, clarity: "clear" });
    expect(resolveTask(TASK, [third, ...observations], DURING)).toMatchObject({
      status: "corroborated",
      corroborating: [first.index, observations[4].index, third.index],
      values: { temp_c: 18.1 },
    });
  });
});
