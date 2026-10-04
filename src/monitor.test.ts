import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { detachSignatures, operatorId, signKeyRotation, signObject } from "./entries";
import { observerId, taskId, type TaskEntry } from "./fieldwork";
import { sha256Digest } from "./hash";
import { ideaTextDigest } from "./ideas";
import { attestRecoveryApproval, attestVouch, invitePayload, unsignedRecovery } from "./identity";
import type { SignedLeaf, TreeHead } from "./leaves";
import {
  checkpointOf,
  compareCheckpoints,
  exitStatus,
  monitorLog,
  MonitorStateSchema,
  NOT_CHECKED,
  type LogSource,
  type MonitorState,
} from "./monitor";
import { MemoryLog } from "./monitor/memory-log";
import { sealCommitment } from "./rounds";
import { generateKeyPair, keyDigest, sign } from "./signing";
import { virtualPasskey } from "./virtual-passkey";

// Operators and a volunteer, made once: keys take a while to generate.
const alice = generateKeyPair(); // a publisher
const aliceNext = generateKeyPair(); // alice's key after its recovery
const bob = generateKeyPair(); // a verifier
const bobNext = generateKeyPair(); // bob's key after it rotates
const carol = generateKeyPair(); // vouched for by a GitHub account
const carolNext = generateKeyPair(); // carol's key after the volunteer approves its recovery
const dave = generateKeyPair(); // proven through a GitHub repository
const daveNext = generateKeyPair(); // dave's key after it recovers through the repository
const erin = generateKeyPair(); // joins bob's organization with an invite code
const ada = virtualPasskey(); // a volunteer
const adaNext = virtualPasskey(); // ada's passkey after she lost the first
// Their IDs, which their first keys make.
const [aliceId, bobId, carolId, daveId, erinId] = [alice, bob, carol, dave, erin].map((keys) => operatorId(keys.publicKey));
const adaId = observerId(ada.publicKey);

type Keys = ReturnType<typeof generateKeyPair>;
type Unstamped = SignedLeaf extends infer L ? (L extends unknown ? Omit<L, "timestamp"> : never) : never;

const CLAIM = `claim:${"c".repeat(64)}` as const;

const keyEntry = (keys: Keys, name = "Agent") =>
  signObject({ type: "key" as const, key: keys.publicKey, name, model_families: ["family-a"] }, keys.secretKey);

const bundleEntry = (keys: Keys, name: string) =>
  signObject({ type: "bundle" as const, bundle: sha256Digest(name) }, keys.secretKey);

const bundleLeaf = (operator: string, entry: ReturnType<typeof bundleEntry>, sealed?: { index: number; salt: string }) => ({
  operator,
  entry,
  claims: [CLAIM],
  fields: ["machine-learning"],
  ...(sealed && { sealed }),
});

const attestation = (keys: Keys, verifier: string, bundle: `sha256:${string}`) =>
  signObject(
    {
      type: "attestation" as const,
      job: "reproduction" as const,
      verifier,
      bundle,
      claims: { [CLAIM]: "reproduced" },
      evidence: sha256Digest("evidence"),
      model_family: "family-b",
      harness: "test harness",
      hazard: "none" as const,
    },
    keys.secretKey,
  );

const task = (keys: Keys) =>
  signObject(
    {
      type: "task" as const,
      operator_key_digest: keyDigest(keys.publicKey),
      title: "Water temperature at the pier",
      instructions: "Lower the thermometer 10 cm below the surface and wait a minute.",
      fields: ["ecology"],
      opens_at: "2026-10-03T00:00:00Z",
      closes_at: "2026-10-10T00:00:00Z",
      measurements: [
        { key: "temp_c", label: "Water temperature", kind: "number" as const, unit: "°C", decimals: 1, tolerance: 0.5, min: -5, max: 45 },
      ],
      replicas: 2,
      max_observations: 5,
    },
    keys.secretKey,
  ) as TaskEntry;

const invitation = (log: MemoryLog, operator: string) =>
  signObject({ type: "identity" as const, kind: "invited" as const, operator }, log.secretKey);

/** The leaf for an invitation: an identity the log signs, which work and flags need. */
const invited = (log: MemoryLog, operator: string) => ({ operator, entry: invitation(log, operator), organization: operator });

const observerKey = (log: MemoryLog, passkey: ReturnType<typeof virtualPasskey>) =>
  signObject({ type: "observer_key" as const, observer: adaId, key: passkey.publicKey, name: "Ada" }, log.secretKey);

const githubIdentity = (operator: string, keys: Keys, repository: string) =>
  signObject({ type: "identity" as const, kind: "github" as const, operator, repository }, keys.secretKey);
/** The organization a GitHub identity counts as: its account's numeric ID, as GitHub's API gives it. */
const GITHUB_ORGANIZATION = "github:58321469";
/** The GitHub account that vouches for carol, by its numeric ID. */
const VOUCHER = "github:9919";

/** A vouch the log attests and the operator countersigns. */
const vouchedIdentity = (log: MemoryLog, operator: string, keys: Keys, voucher: string) =>
  signObject(attestVouch({ operator, voucher }, log.secretKey), keys.secretKey);

/** An invite code, as a sponsor's client makes one from random bytes. */
const INVITE_CODE = `invite:${"a".repeat(32)}`;
/** An identity from an invite code: the sponsor signed the invite, and the operator countersigns everything but `sig`. */
const sponsoredIdentity = (operator: string, keys: Keys, sponsor: string, sponsorKeys: Keys, code = INVITE_CODE) =>
  signObject(
    { type: "identity" as const, kind: "sponsored" as const, operator, sponsor, code, sponsor_sig: sign(invitePayload({ sponsor, code }), sponsorKeys.secretKey) },
    keys.secretKey,
  );
const githubRecovery = (operator: string, next: Keys, repository: string, since: number) =>
  signObject({ type: "key_recovery" as const, kind: "github" as const, operator, key: next.publicKey, repository, since }, next.secretKey);

/** A vouched recovery: the log attests the account's approval, then the new key signs everything but `sig`. */
function vouchedRecovery(log: MemoryLog, operator: string, next: Keys, voucher: string, since: number, attester = log.secretKey) {
  const unsigned = unsignedRecovery({ operator, key: next.publicKey, voucher, since });
  return signObject({ ...unsigned, voucher_sig: attestRecoveryApproval(unsigned, attester) }, next.secretKey);
}

const challengeEntry = (challenger: string, keys: Keys, evidence = "challenge evidence") =>
  signObject(
    { type: "challenge" as const, challenger, claim: CLAIM, ground: "reproduction" as const, evidence: sha256Digest(evidence) },
    keys.secretKey,
  );

const challengeReview = (reviewer: string, keys: Keys, challenge: number) =>
  signObject(
    {
      type: "challenge_review" as const,
      reviewer,
      challenge,
      bundle: sha256Digest("bundle 1"),
      verdict: "rejected" as const,
      evidence: sha256Digest(`review of ${challenge}`),
      model_family: "family-b",
    },
    keys.secretKey,
  );

/** Logs the log's commitment to `entry` and returns what opens it. */
async function seal(log: MemoryLog, entry: { type: string }) {
  const salt = bytesToHex(randomBytes(32));
  const commitment = sealCommitment(detachSignatures(entry), salt);
  const index = await log.append({ entry: signObject({ type: "sealed" as const, commitment }, log.secretKey) });
  return { index, salt };
}

/** A log with every kind of entry the protocol defines, as a node writes them. */
async function realisticLog(): Promise<MemoryLog> {
  const log = new MemoryLog();
  await log.append({ operator: aliceId, entry: keyEntry(alice, "Publisher") });
  await log.append({
    operator: aliceId,
    entry: signObject({ type: "identity" as const, kind: "invited" as const, operator: aliceId }, log.secretKey),
    organization: aliceId,
  });
  await log.append({ operator: bobId, entry: keyEntry(bob, "Verifier") });
  await log.append({
    operator: bobId,
    entry: signObject({ type: "identity" as const, kind: "domain" as const, operator: bobId, domain: "lab.example.org" }, bob.secretKey),
    organization: "example.org",
  });

  // A sealed round: the bundle and a verdict on it are committed, and bob rotates its key
  // before the round opens, so its verdict was signed with the key it rotated away from.
  const bundle = bundleEntry(alice, "bundle 1");
  const bundleSeal = await seal(log, bundle);
  const verdict = attestation(bob, bobId, bundle.bundle);
  const verdictSeal = await seal(log, verdict);
  await log.append({ operator: bobId, entry: signKeyRotation(bobId, bobNext.secretKey, bob.secretKey, bobNext.publicKey) });
  const review = signObject({ type: "hazard_review" as const, reviewer: bobId, bundle: bundle.bundle, verdict: "none" as const }, bobNext.secretKey);
  const reviewSeal = await seal(log, review);
  await log.append(bundleLeaf(aliceId, bundle, bundleSeal));
  await log.append({ operator: bobId, entry: verdict, sealed: verdictSeal });
  await log.append({ operator: bobId, entry: review, sealed: reviewSeal });

  // Fieldwork and ideas, signed with a volunteer's passkey.
  await log.append({ observer: adaId, entry: observerKey(log, ada) });
  const posted = task(alice);
  await log.append({ operator: aliceId, entry: posted });
  await log.append({ observer: adaId, entry: ada.sign({ type: "observation" as const, task: taskId(posted), record: sha256Digest("record") }) });
  await log.append({ observer: adaId, entry: ada.sign({ type: "idea" as const, text: ideaTextDigest({ title: "Why do bees dance?" }) }) });

  // An agent a GitHub account vouches for, and its hazard flag.
  await log.append({ operator: carolId, entry: keyEntry(carol, "Lent agent") });
  await log.append({ operator: carolId, entry: vouchedIdentity(log, carolId, carol, VOUCHER), organization: VOUCHER });
  const flag = signObject({ type: "hazard_flag" as const, operator: carolId, bundle: bundle.bundle, concern: "cyber" as const }, carol.secretKey);
  const flagSeal = await seal(log, flag);
  await log.append({ operator: carolId, entry: flag, sealed: flagSeal });

  // What the log signs itself: a revealed canary, a withdrawal that closes a commitment, and an invited operator's recovery.
  const canary = signObject(
    {
      type: "canary" as const,
      bundle: sha256Digest("canary"),
      source: bundle.bundle,
      mutation: { path: "results/R1.json", pointer: "/loss_delta", from: -0.031, to: -0.5 },
    },
    log.secretKey,
  );
  const canarySeal = await seal(log, canary);
  const withdrawn = await seal(log, bundleEntry(alice, "bundle 2"));
  await log.append({ entry: canary, claims: [CLAIM], sealed: canarySeal });
  await log.append({
    entry: signObject({ type: "withdrawal" as const, bundle: sha256Digest("bundle 2"), reason: "hazard" as const, sealed: withdrawn.index }, log.secretKey),
  });
  await log.append({
    operator: aliceId,
    entry: signObject({ type: "key_recovery" as const, kind: "invited" as const, operator: aliceId, key: aliceNext.publicKey, since: log.size }, log.secretKey),
  });
  await log.append(bundleLeaf(aliceId, bundleEntry(aliceNext, "bundle 3")));

  // The vouched agent challenges the published claim, and a panelist's review is sealed until the panel agrees.
  const challenge = await log.append({ operator: carolId, entry: challengeEntry(carolId, carol) });
  const panelReview = challengeReview(bobId, bobNext, challenge);
  const panelSeal = await seal(log, panelReview);
  await log.append({ operator: bobId, entry: panelReview, sealed: panelSeal });

  // Recoveries through a vouch the account approves, and through a GitHub repository.
  await log.append({ operator: carolId, entry: vouchedRecovery(log, carolId, carolNext, VOUCHER, log.size) });
  await log.append({ operator: daveId, entry: keyEntry(dave, "Lab on GitHub") });
  await log.append({ operator: daveId, entry: githubIdentity(daveId, dave, "example-lab/agents"), organization: GITHUB_ORGANIZATION });
  await log.append({ operator: daveId, entry: githubRecovery(daveId, daveNext, "example-lab/agents", log.size) });

  // A notice takes the published bundle down.
  await log.append({ entry: signObject({ type: "withdrawal" as const, bundle: bundle.bundle, reason: "copyright" as const }, log.secretKey) });
  // An agent joins bob's organization with an invite code bob's current key signed.
  await log.append({ operator: erinId, entry: keyEntry(erin, "Invited agent") });
  await log.append({ operator: erinId, entry: sponsoredIdentity(erinId, erin, bobId, bobNext), organization: "example.org" });
  return log;
}

/** A log of `entries`, each appended in order. */
async function logOf(entries: Unstamped[], log = new MemoryLog()): Promise<MemoryLog> {
  for (const entry of entries) await log.append(entry);
  return log;
}

async function pinned(log: MemoryLog): Promise<MonitorState> {
  const { report, state } = await monitorLog(log.source(), null);
  expect(report.problems).toEqual([]);
  return state!;
}

describe("monitorLog", () => {
  it("pins a log on first sight and audits every kind of entry", async () => {
    const log = await realisticLog();
    const { report, state } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([]);
    expect(report.error).toBeNull();
    expect(exitStatus(report)).toBe(0);
    expect(report).toMatchObject({ log: log.id, pinned: true, previous: null, head: log.head(), audited: log.size, waiting: 0 });
    expect(report.audit).toEqual({
      from: 0,
      to: log.size,
      types: {
        key: 5,
        identity: 5,
        sealed: 7,
        key_rotation: 1,
        bundle: 2,
        attestation: 1,
        hazard_review: 1,
        observer_key: 1,
        task: 1,
        observation: 1,
        idea: 1,
        hazard_flag: 1,
        canary: 1,
        withdrawal: 2,
        key_recovery: 3,
        challenge: 1,
        challenge_review: 1,
      },
    });
    expect(report.unchecked.sort()).toEqual(
      [
        NOT_CHECKED.bundle,
        NOT_CHECKED.identity,
        NOT_CHECKED.canary,
        NOT_CHECKED.withdrawal,
        NOT_CHECKED.recovery,
        NOT_CHECKED.vouch,
        NOT_CHECKED.invite,
        NOT_CHECKED.work,
      ].sort(),
    );

    expect(state).toMatchObject({ log: log.id, public_key: log.publicKey, head: log.head(), audit: { size: log.size, commitments: {} } });
    expect(state!.audit.operators[bobId]).toEqual([
      { index: 2, key: bob.publicKey },
      { index: 6, key: bobNext.publicKey },
    ]);
    // An invite code is spent once used, and an identity keeps the organization its leaf gave it.
    expect(state!.audit.invites).toEqual([INVITE_CODE]);
    expect(state!.audit.identities[bobId]).toEqual([{ index: 3, kind: "domain", domain: "lab.example.org", organization: "example.org" }]);
    // The state survives a round trip through a file, and one saved before invites reads as none.
    expect(MonitorStateSchema.parse(JSON.parse(JSON.stringify(state)))).toEqual(state);
    const { invites, ...older } = state!.audit;
    expect(invites).toHaveLength(1);
    expect(MonitorStateSchema.parse({ ...state, audit: older }).audit.invites).toEqual([]);
  });

  it("checks each new head against the last verified one and audits only what is new", async () => {
    const log = await realisticLog();
    const first = await monitorLog(log.source(), null);
    const size = log.size;
    const pending = await seal(log, bundleEntry(bobNext, "bundle 4"));
    await log.append(bundleLeaf(bobId, bundleEntry(bobNext, "bundle 5")));

    const second = await monitorLog(log.source(), first.state);
    expect(second.report.problems).toEqual([]);
    expect(second.report).toMatchObject({
      pinned: false,
      previous: first.report.head,
      head: log.head(),
      audit: { from: size, to: size + 2, types: { sealed: 1, bundle: 1 } },
      audited: size + 2,
      waiting: 1,
    });
    expect(second.state!.audit.commitments).toEqual({ [pending.index]: expect.stringMatching(/^sha256:/) });

    const unchanged = await monitorLog(log.source(), second.state);
    expect(unchanged.report).toMatchObject({ problems: [], audit: { from: size + 2, to: size + 2 } });
    expect(unchanged.state).toEqual(second.state);
  });

  it("pins an empty log, then checks its first head", async () => {
    const log = new MemoryLog();
    const empty = await monitorLog(log.source(), null);
    expect(empty.report).toMatchObject({ problems: [], pinned: true, head: null });
    expect(empty.state).toMatchObject({ log: log.id, head: null });
    await log.append({ operator: aliceId, entry: keyEntry(alice) });
    const first = await monitorLog(log.source(), empty.state);
    expect(first.report).toMatchObject({ problems: [], pinned: false, audited: 1 });
  });

  it("refuses a log whose key changed until told to pin again", async () => {
    const before = await logOf([{ operator: aliceId, entry: keyEntry(alice) }]);
    const after = await logOf([{ operator: aliceId, entry: keyEntry(alice) }]);
    const state = await pinned(before);

    const changed = await monitorLog(after.source(), state);
    expect(exitStatus(changed.report)).toBe(1);
    expect(changed.state).toBeNull();
    expect(changed.report.problems).toEqual([
      expect.objectContaining({ check: "log_changed", reason: expect.stringContaining(`now serves ${after.id}`) }),
    ]);

    const repinned = await monitorLog(after.source(), state, { pin: true });
    expect(repinned.report).toMatchObject({ problems: [], pinned: true, previous: null, log: after.id });
    expect(repinned.state).toMatchObject({ log: after.id, public_key: after.publicKey });
  });

  it("refuses a node whose log ID isn't its key's", async () => {
    const log = await logOf([{ operator: aliceId, entry: keyEntry(alice) }]);
    const source = log.source({
      log: async () => ({ log: `log:${"0".repeat(64)}`, public_key: log.publicKey, tree_head: log.head() }),
    });
    const { report } = await monitorLog(source, null);
    expect(report.problems).toEqual([expect.objectContaining({ check: "log_id" })]);
  });

  it("catches a tree head the log's key didn't sign", async () => {
    const log = await logOf([{ operator: aliceId, entry: keyEntry(alice) }]);
    const state = await pinned(log);
    await log.append({ operator: bobId, entry: keyEntry(bob) });
    const forged = { ...log.head()!, size: 3 };
    const { report, state: next } = await monitorLog(
      log.source({ log: async () => ({ log: log.id, public_key: log.publicKey, tree_head: forged }) }),
      state,
    );
    expect(next).toBeNull();
    expect(report.problems).toEqual([
      expect.objectContaining({ check: "head", reason: "The tree head for 3 entries isn't signed by the log's key" }),
    ]);
  });

  it("catches a fork: two trees of one size with different roots", async () => {
    const honest = await logOf([{ operator: aliceId, entry: keyEntry(alice) }, { operator: bobId, entry: keyEntry(bob) }]);
    const forked = await logOf(
      [{ operator: aliceId, entry: keyEntry(alice) }, { operator: bobId, entry: keyEntry(carol) }],
      new MemoryLog(honest.secretKey),
    );
    const { report, state } = await monitorLog(forked.source(), await pinned(honest));
    expect(exitStatus(report)).toBe(1);
    expect(state).toBeNull();
    expect(report.problems).toEqual([
      expect.objectContaining({
        check: "fork",
        reason: `The log signed two trees of 2 entries with different roots, ${honest.head()!.root} and ${forked.head()!.root}`,
        evidence: { first: honest.head(), second: forked.head() },
      }),
    ]);
  });

  it("catches a history rewritten under a larger tree", async () => {
    const honest = await logOf([{ operator: aliceId, entry: keyEntry(alice) }, { operator: bobId, entry: keyEntry(bob) }]);
    const rewritten = await logOf(
      [
        { operator: aliceId, entry: keyEntry(alice) },
        { operator: bobId, entry: keyEntry(carol) },
        { operator: carolId, entry: keyEntry(bob) },
      ],
      new MemoryLog(honest.secretKey),
    );
    const { report } = await monitorLog(rewritten.source(), await pinned(honest));
    expect(report.problems).toEqual([
      expect.objectContaining({ check: "consistency", reason: expect.stringContaining("the tree of 3 doesn't extend the tree of 2") }),
    ]);
  });

  it("catches a tree that shrank, or a log that says it is empty", async () => {
    const entries: Unstamped[] = [
      { operator: aliceId, entry: keyEntry(alice) },
      { operator: bobId, entry: keyEntry(bob) },
      { operator: carolId, entry: keyEntry(carol) },
    ];
    const full = await logOf(entries);
    const state = await pinned(full);
    const shorter = await logOf(entries.slice(0, 2), new MemoryLog(full.secretKey));
    const shrank = await monitorLog(shorter.source(), state);
    expect(shrank.report.problems).toEqual([
      expect.objectContaining({ check: "shrank", reason: "The log signed a tree of 3 entries, and now one of 2" }),
    ]);
    const emptied = await monitorLog(
      full.source({ log: async () => ({ log: full.id, public_key: full.publicKey, tree_head: null }) }),
      state,
    );
    expect(emptied.report.problems).toEqual([expect.objectContaining({ check: "shrank" })]);
  });

  it("catches a head or a leaf stamped earlier than the one before it", async () => {
    const log = await logOf([{ operator: aliceId, entry: keyEntry(alice) }]);
    const state = await pinned(log);
    log.clock = new Date("2026-10-01T00:00:00.000Z");
    await log.append({ operator: bobId, entry: keyEntry(bob) });

    const growth = await monitorLog(log.source(), state);
    expect(growth.report.problems).toEqual([
      expect.objectContaining({ check: "timestamp", reason: expect.stringContaining("The head for 2 entries is stamped 2026-10-01") }),
    ]);
    const audit = await monitorLog(log.source(), null);
    expect(audit.report.problems).toEqual([
      { check: "timestamp", index: 1, reason: "The leaf is stamped 2026-10-01T00:00:00.000Z, before entry 0, stamped 2026-10-03T12:00:00.000Z" },
    ]);
  });

  it("catches leaves that don't hash to the signed root, whole or in part", async () => {
    const log = await logOf([
      { operator: aliceId, entry: keyEntry(alice) },
      { operator: bobId, entry: keyEntry(bob) },
      { operator: carolId, entry: keyEntry(carol) },
    ]);
    const honest = log.source();
    // Leaf 0 back-dated, served with the hash of what is served, so only the root shows it.
    const backdated: LogSource["entries"] = async (start, end) => {
      const page = (await honest.entries(start, end)) as { entries: { leaf: { timestamp: string } }[] };
      page.entries[0].leaf.timestamp = "2026-01-01T00:00:00.000Z";
      return page;
    };
    const whole = await monitorLog(log.source({ entries: backdated }), null);
    expect(whole.report.problems).toEqual([
      expect.objectContaining({ check: "leaf", index: 0, reason: expect.stringMatching(/^The node serves leaf hash [0-9a-f]{64}, but the leaf hashes to/) }),
      expect.objectContaining({ check: "root", reason: expect.stringContaining("The 3 leaves the node serves hash to") }),
    ]);
    const part = await monitorLog(log.source({ entries: backdated }), null, { maxEntries: 2 });
    expect(part.report.problems.map((p) => p.check)).toEqual(["leaf", "root"]);
    expect(part.report.problems[1].reason).toContain("The first 2 leaves the node serves");
  });

  it("audits at most maxEntries a run, proving the audited leaves are in the signed tree", async () => {
    const log = await logOf([
      { operator: aliceId, entry: keyEntry(alice) },
      { operator: bobId, entry: keyEntry(bob) },
      { operator: carolId, entry: keyEntry(carol) },
    ]);
    const first = await monitorLog(log.source(), null, { maxEntries: 2 });
    expect(first.report).toMatchObject({ problems: [], audit: { from: 0, to: 2 }, audited: 2, head: { size: 3 } });
    const skipped = await monitorLog(log.source(), first.state, { maxEntries: 0 });
    expect(skipped.report).toMatchObject({ problems: [], audit: { from: 2, to: 2 }, audited: 2 });
    const rest = await monitorLog(log.source(), skipped.state);
    expect(rest.report).toMatchObject({ problems: [], audit: { from: 2, to: 3 }, audited: 3 });
  });

  it("catches an entry served as signed that isn't the one its leaf holds", async () => {
    const log = await logOf([
      { operator: aliceId, entry: keyEntry(alice, "Publisher") },
      { operator: bobId, entry: keyEntry(bob, "Verifier") },
    ]);
    await log.append(invited(log, aliceId));
    await log.append(bundleLeaf(aliceId, bundleEntry(alice, "bundle")));
    const honest = log.source();
    const swapped: LogSource["signedEntry"] = async (index) =>
      index === 0
        ? { index, entry: { ...log.signed[0], name: "Someone else" } }
        : index === 1
          ? { index, entry: keyEntry(bob, "Verifier") } // signed again, which gives a different signature
          : honest.signedEntry(index);
    const { report } = await monitorLog(log.source({ signedEntry: swapped }), null);
    // The key in the leaf still counts, so alice's bundle verifies against it.
    expect(report.problems).toEqual([
      { check: "signed_entry", index: 0, reason: "The entry served as signed isn't the one the leaf holds: its name differs" },
      { check: "signed_entry", index: 1, reason: "The entry served as signed isn't the one the leaf holds: its sig doesn't match the digest in the leaf" },
    ]);
  });

  it("catches signatures made with any key but the signer's", async () => {
    const log = await logOf([
      { operator: aliceId, entry: keyEntry(alice) },
      { operator: bobId, entry: keyEntry(bob) },
      {
        operator: bobId,
        entry: signObject({ type: "identity" as const, kind: "domain" as const, operator: bobId, domain: "example.org" }, alice.secretKey),
        organization: "example.org",
      },
      { operator: aliceId, entry: signObject({ type: "identity" as const, kind: "invited" as const, operator: aliceId }, alice.secretKey), organization: aliceId },
      bundleLeaf(aliceId, bundleEntry(bob, "bundle")),
    ]);
    const { report, state } = await monitorLog(log.source(), null);
    expect(exitStatus(report)).toBe(1);
    expect(state).toBeNull();
    expect(report.problems).toEqual([
      { check: "signature", index: 2, reason: `The identity entry's sig doesn't verify against ${bobId}'s key from entry 1` },
      { check: "signature", index: 3, reason: "The identity entry's sig doesn't verify against the log's key" },
      { check: "signature", index: 4, reason: `The bundle entry's sig doesn't verify against ${aliceId}'s key from entry 0` },
    ]);
  });

  it("follows rotations: a key rotated away from signs nothing after the rotation", async () => {
    const log = await logOf([{ operator: bobId, entry: keyEntry(bob) }]);
    await log.append(invited(log, bobId));
    await log.append({ operator: bobId, entry: signKeyRotation(bobId, bobNext.secretKey, bob.secretKey, bobNext.publicKey) });
    await log.append(bundleLeaf(bobId, bundleEntry(bobNext, "after")));
    await log.append(bundleLeaf(bobId, bundleEntry(bob, "too late")));
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "signature", index: 4, reason: `The bundle entry's sig doesn't verify against ${bobId}'s key from entry 2` },
    ]);
  });

  it("checks a revealed entry against the key its signer held when the commitment was logged", async () => {
    const log = new MemoryLog();
    await log.append({ operator: bobId, entry: keyEntry(bob) });
    await log.append(invited(log, bobId));
    const early = bundleEntry(bob, "early");
    const earlySeal = await seal(log, early);
    const wrong = bundleEntry(bobNext, "signed with the next key too soon");
    const wrongSeal = await seal(log, wrong);
    await log.append({ operator: bobId, entry: signKeyRotation(bobId, bobNext.secretKey, bob.secretKey, bobNext.publicKey) });
    await log.append(bundleLeaf(bobId, early, earlySeal));
    await log.append(bundleLeaf(bobId, wrong, wrongSeal));
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      {
        check: "signature",
        index: 6,
        reason: `The bundle entry's sig doesn't verify against ${bobId}'s key from entry 0, which it held when the commitment at entry 3 was logged`,
      },
    ]);
  });

  it("catches a key rotation either key didn't sign, or one to a key already used", async () => {
    const log = await logOf([
      { operator: aliceId, entry: keyEntry(alice) },
      { operator: bobId, entry: keyEntry(bob) },
      { operator: bobId, entry: signKeyRotation(bobId, bobNext.secretKey, carol.secretKey, bobNext.publicKey) },
      { operator: bobId, entry: { ...signKeyRotation(bobId, carol.secretKey, bobNext.secretKey, carol.publicKey), key: alice.publicKey } },
      { operator: carolId, entry: keyEntry(bob) },
    ]);
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "signature", index: 2, reason: `The rotation's sig doesn't verify against ${bobId}'s key from entry 1` },
      { check: "signature", index: 3, reason: `The rotation's sig doesn't verify against ${bobId}'s key from entry 2` },
      { check: "signature", index: 3, reason: "The rotation's key_sig isn't the new key's signature over the entry without sig and key_sig" },
      { check: "key", index: 3, reason: `${bobId} takes a key that ${aliceId} already held; a key serves one operator, once` },
      { check: "key", index: 4, reason: `The key entry names ${carolId}, but the key it registers makes ${bobId}` },
      { check: "key", index: 4, reason: `${carolId} takes a key that ${bobId} already held; a key serves one operator, once` },
    ]);
  });

  it("catches an operator or volunteer named by anything but the SHA-256 of their first key", async () => {
    const log = new MemoryLog();
    const passkeyOf = (observer: string, passkey: typeof ada) =>
      signObject({ type: "observer_key" as const, observer, key: passkey.publicKey, name: "Ada" }, log.secretKey);
    const wrong = observerId(adaNext.publicKey);
    await log.append({ operator: bobId, entry: keyEntry(alice) });
    await log.append({ observer: wrong, entry: passkeyOf(wrong, ada) });
    // A volunteer rebound to a new passkey keeps the ID their first one made.
    await log.append({ observer: adaId, entry: passkeyOf(adaId, ada) });
    await log.append({ observer: adaId, entry: passkeyOf(adaId, adaNext) });
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "key", index: 0, reason: `The key entry names ${bobId}, but the key it registers makes ${aliceId}` },
      { check: "key", index: 1, reason: `The observer key entry names ${wrong}, but the passkey it records first makes ${adaId}` },
    ]);
  });

  it("catches an entry that doesn't open its commitment, and a commitment opened or closed twice", async () => {
    const log = new MemoryLog();
    await log.append({ operator: aliceId, entry: keyEntry(alice) });
    await log.append(invited(log, aliceId));
    const first = bundleEntry(alice, "first");
    const second = bundleEntry(alice, "second");
    const firstSeal = await seal(log, first);
    const secondSeal = await seal(log, second);
    await log.append(bundleLeaf(aliceId, first, { index: firstSeal.index, salt: secondSeal.salt }));
    await log.append(bundleLeaf(aliceId, second, secondSeal));
    await log.append(bundleLeaf(aliceId, second, secondSeal));
    await log.append({
      entry: signObject({ type: "withdrawal" as const, bundle: second.bundle, reason: "hazard" as const, sealed: secondSeal.index }, log.secretKey),
    });
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "seal", index: 4, reason: "The entry and its salt don't open the commitment at entry 2" },
      {
        check: "seal",
        index: 6,
        reason: "Entry 3 holds no commitment waiting to be opened: it isn't a sealed entry, or an earlier entry opened or closed it",
      },
      { check: "seal", index: 7, reason: "The withdrawal closes the commitment at entry 3, but no commitment waits there" },
    ]);
  });

  it("accepts a task or an idea signed with a key its signer held before a person approved it", async () => {
    const log = new MemoryLog();
    await log.append({ operator: aliceId, entry: keyEntry(alice) });
    await log.append({ operator: aliceId, entry: invitation(log, aliceId), organization: aliceId });
    await log.append({ observer: adaId, entry: observerKey(log, ada) });
    const waiting = task(alice);
    const idea = ada.sign({ type: "idea" as const, text: ideaTextDigest({ title: "Why do bees dance?" }) });
    await log.append({
      operator: aliceId,
      entry: signObject({ type: "key_recovery" as const, kind: "invited" as const, operator: aliceId, key: aliceNext.publicKey, since: log.size }, log.secretKey),
    });
    await log.append({ observer: adaId, entry: observerKey(log, adaNext) });
    await log.append({ operator: aliceId, entry: waiting });
    await log.append({ observer: adaId, entry: idea });
    // An observation is logged as it is made, so it must carry the passkey held then.
    await log.append({ observer: adaId, entry: ada.sign({ type: "observation" as const, task: taskId(waiting), record: sha256Digest("record") }) });
    await log.append({ operator: aliceId, entry: task(carol) });
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "signature", index: 7, reason: `The observation's passkey signature doesn't verify against ${adaId}'s passkey from entry 4` },
      { check: "signer", index: 8, reason: `The task names key ${keyDigest(carol.publicKey)}, which ${aliceId} didn't hold on the log before it` },
    ]);
  });

  it("catches leaves that name someone other than the signer, or count as the wrong organization", async () => {
    const log = new MemoryLog();
    await log.append({ operator: aliceId, entry: keyEntry(alice) });
    await log.append({ operator: bobId, entry: keyEntry(bob) });
    await log.append({ operator: aliceId, entry: attestation(bob, bobId, sha256Digest("bundle")) });
    await log.append({
      operator: bobId,
      entry: signObject({ type: "identity" as const, kind: "invited" as const, operator: bobId }, log.secretKey),
      organization: "example.org",
    });
    await log.append(bundleLeaf(carolId, bundleEntry(carol, "unregistered")));
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "signer", index: 2, reason: `The entry's verifier is ${bobId}, but the leaf attributes it to ${aliceId}` },
      { check: "identity", index: 2, reason: `${aliceId} has no identity on the log before entry 2, and attestation entries need one` },
      { check: "signature", index: 2, reason: `The attestation entry's sig doesn't verify against ${aliceId}'s key from entry 0` },
      { check: "identity", index: 3, reason: `An invited operator counts as itself, ${bobId}, not example.org` },
      { check: "identity", index: 4, reason: `${carolId} has no identity on the log before entry 4, and bundle entries need one` },
      { check: "signer", index: 4, reason: `${carolId} has no key on the log before entry 4` },
    ]);
  });

  it("knows a GitHub identity by its account's ID, never by its login, which can be renamed and reused", async () => {
    const log = new MemoryLog();
    await log.append({ operator: daveId, entry: keyEntry(dave) });
    await log.append({ operator: daveId, entry: githubIdentity(daveId, dave, "example-lab/agents"), organization: "github:example-lab" });
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "identity", index: 1, reason: "A GitHub identity counts as its account's ID, github:<ID>, not github:example-lab" },
    ]);
  });

  it("catches leaves that don't fit the protocol, and leaves unknown entry types unchecked", async () => {
    const log = new MemoryLog();
    await log.append({ operator: aliceId, entry: keyEntry(alice) });
    await log.append({ entry: keyEntry(bob) } as unknown as Unstamped);
    await log.append({ entry: { type: "status", claims: { [CLAIM]: "reproduced" } } } as unknown as Unstamped);
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "leaf", index: 1, reason: expect.stringMatching(/^The key leaf doesn't fit the protocol \(\/operator: /) },
    ]);
    expect(report.unchecked).toEqual([
      "This monitor doesn't know how to check status entries, so it checked only where they sit in the tree: 2.",
    ]);
  });

  it("ties each key recovery to an identity its operator holds", async () => {
    const log = new MemoryLog();
    const domainRecovery = (operator: string, keys: Keys, domain: string, since: number) =>
      signObject({ type: "key_recovery" as const, kind: "domain" as const, operator, key: keys.publicKey, domain, since }, keys.secretKey);
    const invitedRecovery = (operator: string, keys: Keys) =>
      signObject({ type: "key_recovery" as const, kind: "invited" as const, operator, key: keys.publicKey, since: log.size }, log.secretKey);
    await log.append({ operator: aliceId, entry: keyEntry(alice) });
    await log.append({
      operator: aliceId,
      entry: signObject({ type: "identity" as const, kind: "domain" as const, operator: aliceId, domain: "lab.example.org" }, alice.secretKey),
      organization: "example.org",
    });
    await log.append({ operator: aliceId, entry: invitation(log, aliceId), organization: aliceId });
    await log.append({ operator: bobId, entry: keyEntry(bob) });
    // The log can't take over an operator that counts as its domain, or one it never invited.
    await log.append({ operator: aliceId, entry: invitedRecovery(aliceId, aliceNext) });
    await log.append({ operator: bobId, entry: invitedRecovery(bobId, bobNext) });
    // A domain recovery rests on the operator's own domain identity.
    await log.append({ operator: bobId, entry: domainRecovery(bobId, generateKeyPair(), "lab.example.org", log.size) });
    await log.append({ operator: aliceId, entry: domainRecovery(aliceId, generateKeyPair(), "other.example.org", log.size) });
    await log.append({ operator: aliceId, entry: domainRecovery(aliceId, generateKeyPair(), "lab.example.org", 2) });
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      {
        check: "key",
        index: 4,
        reason: `The recovery goes through ${aliceId}'s invited identity, but ${aliceId} counts as its domain identity, from entry 1, and recovers through that`,
      },
      { check: "key", index: 5, reason: `The recovery goes through ${bobId}'s invited identity, but ${bobId} has none on the log` },
      { check: "key", index: 6, reason: `The recovery goes through ${bobId}'s domain identity, but ${bobId} has none on the log` },
      { check: "key", index: 7, reason: `The recovery goes through other.example.org, but ${aliceId}'s domain identity, from entry 1, is lab.example.org` },
    ]);
    expect(report.unchecked).toEqual(expect.arrayContaining([NOT_CHECKED.recovery, NOT_CHECKED.disowned]));
  });

  it("recovers through GitHub or a vouch only as the identity the operator counts as", async () => {
    const log = new MemoryLog();
    await log.append({ operator: daveId, entry: keyEntry(dave) });
    await log.append({ operator: daveId, entry: githubIdentity(daveId, dave, "example-lab/agents"), organization: GITHUB_ORGANIZATION });
    await log.append({ operator: carolId, entry: keyEntry(carol) });
    await log.append({ operator: carolId, entry: vouchedIdentity(log, carolId, carol, VOUCHER), organization: VOUCHER });
    await log.append(invited(log, carolId));
    // A GitHub recovery names the repository the identity proved.
    await log.append({ operator: daveId, entry: githubRecovery(daveId, generateKeyPair(), "example-lab/other", log.size) });
    // A vouched recovery is approved by the account that vouched, as the log attests, over exactly what the new key signs.
    await log.append({ operator: carolId, entry: vouchedRecovery(log, carolId, generateKeyPair(), VOUCHER, log.size, generateKeyPair().secretKey) });
    await log.append({ operator: carolId, entry: vouchedRecovery(log, carolId, generateKeyPair(), "github:4242", log.size) });
    const forged = vouchedRecovery(log, carolId, generateKeyPair(), VOUCHER, log.size);
    await log.append({ operator: carolId, entry: signObject({ ...forged, since: log.size - 1 }, generateKeyPair().secretKey) });
    // A vouch never lapses, so an operator with one recovers through it and not its invitation.
    await log.append({
      operator: carolId,
      entry: signObject({ type: "key_recovery" as const, kind: "invited" as const, operator: carolId, key: carolNext.publicKey, since: log.size }, log.secretKey),
    });
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "key", index: 5, reason: `The recovery goes through example-lab/other, but ${daveId}'s github identity, from entry 1, is example-lab/agents` },
      { check: "signature", index: 6, reason: "The recovery's voucher_sig doesn't verify against the log's key" },
      { check: "key", index: 7, reason: `The recovery is approved by github:4242, but ${carolId} was vouched for by ${VOUCHER}, at entry 3` },
      { check: "signature", index: 8, reason: "The recovery's voucher_sig doesn't verify against the log's key" },
      { check: "signature", index: 8, reason: "The key_recovery entry's sig doesn't verify against the new key it names" },
      {
        check: "key",
        index: 9,
        reason: `The recovery goes through ${carolId}'s invited identity, but ${carolId} counts as its vouched identity, from entry 3, and recovers through that`,
      },
    ]);
    expect(report.unchecked).toEqual(expect.arrayContaining([NOT_CHECKED.recovery, NOT_CHECKED.vouch]));
  });

  it("holds each challenge to its challenger's identity and each review to an earlier challenge", async () => {
    const log = new MemoryLog();
    await log.append({ operator: aliceId, entry: keyEntry(alice) });
    await log.append(invited(log, aliceId));
    await log.append({ operator: bobId, entry: keyEntry(bob) });
    await log.append(invited(log, bobId));
    const challenge = await log.append({ operator: aliceId, entry: challengeEntry(aliceId, alice) });
    const fair = challengeReview(bobId, bob, challenge);
    await log.append({ operator: bobId, entry: fair, sealed: await seal(log, fair) });
    // A review of an entry that isn't a challenge.
    const stray = challengeReview(bobId, bob, 2);
    await log.append({ operator: bobId, entry: stray, sealed: await seal(log, stray) });
    // A review committed before the challenge it names.
    const early = challengeReview(bobId, bob, log.size + 1);
    const earlySeal = await seal(log, early);
    await log.append({ operator: aliceId, entry: challengeEntry(aliceId, alice, "more evidence") });
    await log.append({ operator: bobId, entry: early, sealed: earlySeal });
    // A challenger with no identity.
    await log.append({ operator: carolId, entry: keyEntry(carol) });
    await log.append({ operator: carolId, entry: challengeEntry(carolId, carol) });
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "challenge", index: 8, reason: "The review names entry 2, which isn't a challenge logged before the review was committed at entry 7" },
      { check: "challenge", index: 11, reason: "The review names entry 10, which isn't a challenge logged before the review was committed at entry 9" },
      { check: "identity", index: 13, reason: `${carolId} has no identity on the log before entry 13, and challenge entries need one` },
    ]);
  });

  it("withdraws a bundle once, for any reason", async () => {
    const log = new MemoryLog();
    const withdrawal = (reason: "copyright" | "personal_data") =>
      signObject({ type: "withdrawal" as const, bundle: sha256Digest("bundle"), reason }, log.secretKey);
    await log.append({ entry: withdrawal("copyright") });
    await log.append({ entry: withdrawal("personal_data") });
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "withdrawal", index: 1, reason: `${sha256Digest("bundle")} was withdrawn before; a bundle is withdrawn once` },
    ]);
  });

  it("holds an invitee to its sponsor's own organization, an invite its sponsor signed, and a code used once", async () => {
    const domain = signObject({ type: "identity" as const, kind: "domain" as const, operator: bobId, domain: "lab.example.org" }, bob.secretKey);
    const log = await logOf([
      { operator: bobId, entry: keyEntry(bob) },
      { operator: bobId, entry: domain, organization: "example.org" },
      { operator: erinId, entry: keyEntry(erin) },
      { operator: carolId, entry: keyEntry(carol) },
      { operator: daveId, entry: keyEntry(dave) },
      { operator: aliceId, entry: keyEntry(alice) },
    ]);
    await log.append({ operator: erinId, entry: sponsoredIdentity(erinId, erin, bobId, bob), organization: "example.org" });
    // The same code again, counted as another organization than bob's.
    await log.append({ operator: carolId, entry: sponsoredIdentity(carolId, carol, bobId, bob), organization: "example.net" });
    // An invite bob's key didn't sign.
    const forged = `invite:${"b".repeat(32)}`;
    await log.append({ operator: daveId, entry: sponsoredIdentity(daveId, dave, bobId, alice, forged), organization: "example.org" });
    // An invitee inviting, and an operator inviting itself.
    await log.append({ operator: aliceId, entry: sponsoredIdentity(aliceId, alice, erinId, erin, `invite:${"c".repeat(32)}`), organization: "example.org" });
    await log.append({ operator: bobId, entry: sponsoredIdentity(bobId, bob, bobId, bob, `invite:${"d".repeat(32)}`), organization: "example.org" });
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "identity", index: 7, reason: "A sponsored identity counts as its sponsor's organization, example.org, not example.net" },
      { check: "identity", index: 7, reason: `The invite code ${INVITE_CODE} was used before; each code is used once` },
      { check: "signature", index: 8, reason: `The invite's sponsor_sig doesn't verify against ${bobId}'s key from entry 0` },
      { check: "identity", index: 9, reason: `${erinId} proved no domain, GitHub account, or vouch of its own before entry 9, so it can't sponsor anyone` },
      { check: "identity", index: 10, reason: `${bobId} sponsors itself` },
    ]);
    expect(report.unchecked).toContain(NOT_CHECKED.invite);
  });

  it("allows an operator one identity of each kind", async () => {
    const log = await logOf([{ operator: aliceId, entry: keyEntry(alice) }]);
    await log.append({ operator: aliceId, entry: invitation(log, aliceId), organization: aliceId });
    await log.append({ operator: aliceId, entry: invitation(log, aliceId), organization: aliceId });
    const { report } = await monitorLog(log.source(), null);
    expect(report.problems).toEqual([
      { check: "identity", index: 2, reason: `This is ${aliceId}'s second invited identity, after entry 1; an operator holds at most one of each kind` },
    ]);
  });

  it("counts a malformed signature as a bad one, and keeps what it found when a later request fails", async () => {
    const log = await logOf([
      { operator: aliceId, entry: { ...keyEntry(alice), sig: 123 } } as unknown as Unstamped,
      { operator: bobId, entry: keyEntry(bob) },
      { operator: carolId, entry: keyEntry(carol) },
    ]);
    const failing = log.source({ consistencyProof: async () => Promise.reject(new Error("fetch failed")) });
    const { report, state } = await monitorLog(failing, null, { maxEntries: 2 });
    expect(report.problems).toEqual([{ check: "signature", index: 0, reason: "The key entry isn't signed by the key it registers" }]);
    expect(report.error).toBe("fetch failed");
    expect(exitStatus(report)).toBe(1);
    expect(state).toBeNull();
  });

  it("isn't tripped by entry types named like an object's own properties", async () => {
    const log = await logOf([
      { entry: { type: "constructor" } } as unknown as Unstamped,
      { entry: { type: "toString" } } as unknown as Unstamped,
      { entry: { type: "constructor" } } as unknown as Unstamped,
    ]);
    const { report } = await monitorLog(log.source(), null);
    expect(report).toMatchObject({ problems: [], error: null, audit: { types: { constructor: 2, toString: 1 } } });
    expect(report.unchecked).toEqual([
      "This monitor doesn't know how to check constructor entries, so it checked only where they sit in the tree: 0, 2.",
      "This monitor doesn't know how to check toString entries, so it checked only where they sit in the tree: 1.",
    ]);
  });

  it("lets a node lag behind the head verified before, proven by a node ahead of it, but never shrink", async () => {
    const entries: Unstamped[] = [
      { operator: aliceId, entry: keyEntry(alice) },
      { operator: bobId, entry: keyEntry(bob) },
      { operator: carolId, entry: keyEntry(carol) },
    ];
    const ahead = await logOf(entries);
    const lagging = await logOf(entries.slice(0, 2), new MemoryLog(ahead.secretKey));
    const forked = await logOf([entries[0], entries[2]], new MemoryLog(ahead.secretKey));
    const state = await pinned(ahead);

    const behind = await monitorLog(lagging.source(), state, { servedBefore: 0, ahead: ahead.source() });
    expect(behind.report).toMatchObject({ problems: [], behind: true, head: lagging.head(), previous: ahead.head(), audit: null });
    expect(behind.state).toEqual(state);
    // A node can't prove anything about a tree it doesn't have.
    expect((await monitorLog(lagging.source(), state, { servedBefore: 0 })).report.error).toBe("No proof from 2 to 3");
    const split = await monitorLog(forked.source(), state, { servedBefore: 0, ahead: ahead.source() });
    expect(split.report.problems).toEqual([expect.objectContaining({ check: "consistency" })]);
    // A node that served three entries before has dropped one.
    const dropped = await monitorLog(lagging.source(), state, { servedBefore: 3, ahead: ahead.source() });
    expect(dropped.report.problems).toEqual([expect.objectContaining({ check: "shrank", reason: "The log signed a tree of 3 entries, and now one of 2" })]);
  });

  it("reports what it couldn't read as a failure to finish, not as misbehavior", async () => {
    const log = await logOf([{ operator: aliceId, entry: keyEntry(alice) }]);
    const state = await pinned(log);
    const cases: Partial<LogSource>[] = [
      { log: async () => Promise.reject(new Error("fetch failed")) },
      { log: async () => ({ log: log.id }) },
      { entries: async () => ({ entries: [] }) },
      { signedEntry: async () => ({ index: 7, entry: {} }) },
    ];
    for (const overrides of cases) {
      const { report, state: next } = await monitorLog(log.source(overrides), null);
      expect(report.problems).toEqual([]);
      expect(report.error).toEqual(expect.any(String));
      expect(exitStatus(report)).toBe(2);
      expect(next).toBeNull();
    }
    await log.append({ operator: bobId, entry: keyEntry(bob) });
    const noProof = await monitorLog(log.source({ consistencyProof: async () => ({ proof: "none" }) }), state);
    expect(noProof.report.error).toMatch(/^The node's answer to GET \/api\/v1\/log\/proofs\/consistency\?first=1&second=2 isn't what the API returns/);
  });
});

describe("compareCheckpoints", () => {
  const entries: Unstamped[] = [
    { operator: aliceId, entry: keyEntry(alice) },
    { operator: bobId, entry: keyEntry(bob) },
    { operator: carolId, entry: keyEntry(carol) },
  ];
  const checkpoint = (log: MemoryLog, head: TreeHead) => ({ log: log.id, public_key: log.publicKey, tree_head: head });

  it("finds two heads of one log consistent, with a proof when their sizes differ", async () => {
    const log = await logOf(entries);
    const [, second, third] = log.heads;
    const comparison = await compareCheckpoints(checkpoint(log, third), checkpoint(log, second), log.source());
    expect(comparison).toEqual({ log: log.id, heads: [second, third], problems: [], error: null });
    const same = await compareCheckpoints(checkpoint(log, third), checkpoint(log, third), null);
    expect(same.problems).toEqual([]);
    expect(checkpointOf(await pinned(log), "https://node.example")).toEqual({ ...checkpoint(log, third), node: "https://node.example" });
  });

  it("catches two monitors shown different histories", async () => {
    const honest = await logOf(entries);
    const forked = await logOf([entries[0], entries[2], entries[1]], new MemoryLog(honest.secretKey));
    const sameSize = await compareCheckpoints(checkpoint(honest, honest.heads[2]), checkpoint(forked, forked.heads[2]), null);
    expect(sameSize.problems).toEqual([expect.objectContaining({ check: "fork" })]);
    const grown = await compareCheckpoints(checkpoint(honest, honest.heads[1]), checkpoint(forked, forked.heads[2]), forked.source());
    expect(grown.problems).toEqual([expect.objectContaining({ check: "consistency" })]);
  });

  it("refuses checkpoints of different logs, and heads their log didn't sign", async () => {
    const one = await logOf(entries.slice(0, 1));
    const other = await logOf(entries.slice(0, 1));
    const different = await compareCheckpoints(checkpoint(one, one.heads[0]), checkpoint(other, other.heads[0]), null);
    expect(different.error).toBe(`The checkpoints are of different logs, ${one.id} and ${other.id}`);
    const forged = { ...checkpoint(one, other.heads[0]), tree_head: { ...other.heads[0], log: one.id } };
    const unsigned = await compareCheckpoints(checkpoint(one, one.heads[0]), forged, null);
    expect(unsigned.error).toBe(`The second checkpoint's tree head isn't signed by ${one.id}`);
    expect(exitStatus(unsigned)).toBe(2);
  });
});
