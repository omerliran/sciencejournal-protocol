import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { operatorId, signObject } from "./entries";
import { monitorLog, type MonitorOptions, type WitnessView } from "./monitor";
import { MemoryLog } from "./monitor/memory-log";
import { cosignNote, NOTE_SIGNATURE_TYPES, noteVerifier, parseNote } from "./notes";
import { generateKeyPair } from "./signing";

// A log's checkpoints are its tree heads in the form witnesses cosign. The monitor checks them
// against the heads it verified, checks any cosignatures from witnesses it was given, and holds
// the log to what each witness says it last cosigned: a log can't show witnesses one history and
// monitors another.

const agents = [generateKeyPair(), generateKeyPair(), generateKeyPair()].map((keys, i) =>
  signObject({ type: "key" as const, key: keys.publicKey, name: `Agent ${i}`, model_families: ["family-a"] }, keys.secretKey),
);

async function logOf(count: number, log = new MemoryLog(), from = 0): Promise<MemoryLog> {
  for (let i = from; i < from + count; i++) await log.append({ operator: operatorId(agents[i].key), entry: agents[i] });
  return log;
}

const seed = new Uint8Array(32).fill(7);
const witnessKey = noteVerifier("witness.example/w1", NOTE_SIGNATURE_TYPES.cosignature, ed25519.getPublicKey(seed));
const TIME = BigInt(1_790_000_000);

/** A cosignature line from the witness on the log's checkpoint of `size`. */
const cosign = (log: MemoryLog, size: number, key = seed) => cosignNote(parseNote(log.checkpoint(size)!).text, "witness.example/w1", key, TIME);

const check = (log: MemoryLog, options: MonitorOptions = {}, source = log.source()) => monitorLog(source, null, options);

describe("checkpoints and witnesses", () => {
  it("checks the checkpoint beside the verified head, signed by the key the log's key vouches for", async () => {
    const log = await logOf(2);
    const { report } = await check(log);
    expect(report.problems).toEqual([]);
    expect(report.witnessing).toEqual({ origin: log.origin, keys: [log.checkpointKey], served: [], witnesses: [] });
  });

  it("finds a checkpoint that isn't the signed tree head, or keys the log's key didn't sign", async () => {
    const log = await logOf(2);
    const other = await logOf(2, new MemoryLog(log.secretKey), 1);
    // The node serves another tree's checkpoint beside this head.
    const wrong = await check(log, {}, log.source({ checkpoint: async (size) => other.checkpoint(size) }));
    expect(wrong.report.problems.map((p) => p.check)).toContain("checkpoint");
    expect(wrong.report.problems[0].reason).toMatch(/the tree head says/);

    const stranger = generateKeyPair();
    const keys = signObject({ type: "checkpoint_keys" as const, log: log.id, origin: log.origin, keys: [log.checkpointKey] }, stranger.secretKey);
    const info = { log: log.id, public_key: log.publicKey, tree_head: log.head(), checkpoint_keys: keys };
    const unsigned = await check(log, {}, log.source({ log: async () => JSON.parse(JSON.stringify(info)) }));
    expect(unsigned.report.problems).toMatchObject([{ check: "checkpoint", reason: expect.stringMatching(/aren't signed by the log's key/) }]);
  });

  it("notes a node that serves no checkpoints, which isn't a problem in itself", async () => {
    const log = await logOf(1);
    const info = { log: log.id, public_key: log.publicKey, tree_head: log.head() };
    const { report } = await check(log, {}, log.source({ log: async () => JSON.parse(JSON.stringify(info)) }));
    expect(report.problems).toEqual([]);
    expect(report.unchecked).toContain("The node serves no checkpoint keys, so its checkpoints weren't checked.");
  });

  it("serves the newest witnessed checkpoint, whose cosignatures from witnesses it was given must verify", async () => {
    const log = await logOf(2);
    log.cosignatures.set(1, [cosign(log, 1)]);
    await logOf(1, log, 2);
    const witness: WitnessView = { verifier: witnessKey };
    const { report } = await check(log, { witnesses: [witness] });
    expect(report.problems).toEqual([]);
    expect(report.witnessing?.served).toEqual([{ witness: "witness.example/w1", size: 1, timestamp: Number(TIME) }]);

    // A cosignature line that names the witness but doesn't verify.
    log.cosignatures.set(1, [cosign(log, 2)]);
    const bad = await check(log, { witnesses: [witness] });
    expect(bad.report.problems).toMatchObject([{ check: "checkpoint", reason: expect.stringMatching(/witness\.example\/w1 .* doesn't verify/) }]);
  });

  it("holds the log to the checkpoint a witness says it last cosigned", async () => {
    const log = await logOf(3);
    const shown = (text: string | null) => ({ verifier: witnessKey, checkpoint: async (origin: string) => (origin === log.origin ? text : null) });
    // The witness cosigned an earlier head of this history: consistent.
    const honest = await check(log, { witnesses: [shown(`${log.checkpoint(2)}${cosign(log, 2)}`)] });
    expect(honest.report.problems).toEqual([]);
    expect(honest.report.witnessing?.witnesses).toEqual([{ witness: "witness.example/w1", size: 2, timestamp: Number(TIME) }]);

    // The log showed the witness the same entries in another order: a fork at the size this monitor verified.
    const forked = await logOf(2, new MemoryLog(log.secretKey), 1);
    await logOf(1, forked, 0);
    await logOf(1, forked, 0);
    const split = await check(log, { witnesses: [shown(`${forked.checkpoint(3)}${cosign(forked, 3)}`)] });
    expect(split.report.problems).toMatchObject([{ check: "fork", reason: expect.stringMatching(/witness\.example\/w1 cosigned/) }]);

    // And a bigger tree that doesn't extend this one fails its consistency proof.
    const larger = await check(log, { witnesses: [shown(`${forked.checkpoint(4)}${cosign(forked, 4)}`)] }, log.source({
      consistencyProof: async () => ({ proof: [] }),
    }));
    expect(larger.report.problems.map((p) => p.check)).toEqual(["consistency"]);
  });

  it("ignores what a witness serves without its own valid cosignature, saying so", async () => {
    const log = await logOf(2);
    const view = (text: string | null): WitnessView => ({ verifier: witnessKey, checkpoint: async () => text });
    const none = await check(log, { witnesses: [view(null)] });
    expect(none.report.unchecked).toContain("witness.example/w1 has cosigned no checkpoint of this log.");
    const unsigned = await check(log, { witnesses: [view(log.checkpoint(1))] });
    expect(unsigned.report.problems).toEqual([]);
    expect(unsigned.report.unchecked.join(" ")).toMatch(/without a valid cosignature of its own/);
  });
});
