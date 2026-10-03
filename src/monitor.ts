import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { z } from "zod";
import { canonicalJson } from "./canonical";
import {
  detachSignatures,
  DomainSchema,
  keyRotationPayload,
  matchesLeafEntry,
  operatorId,
  OperatorIdSchema,
  PublicKeySchema,
  SIGNATURE_FIELDS,
  verifyObject,
  type Detached,
  type KeyRotationEntry,
} from "./entries";
import { observerId, ObserverIdSchema } from "./fieldwork";
import { DigestSchema, type Digest } from "./hash";
import {
  RepositorySchema,
  verifyRecoveryApproval,
  verifyVouch,
  type IdentityEntry,
  type KeyRecoveryEntry,
  type VouchedRecoveryEntry,
  type Vouch,
} from "./identity";
import { leafBytes, LogLeafSchema, logId, TreeHeadSchema, type LogLeaf, type TreeHead } from "./leaves";
import { extendRange, leafHash, rangeRoot, verifyConsistency } from "./merkle";
import { verifyPasskeyObject, type PasskeySignature } from "./passkey";
import { verifyTreeGrowth } from "./receipts";
import { sealCommitment, type SealReveal } from "./rounds";
import { keyDigest, verify } from "./signing";
import { toIssues } from "./validate";
import { IDENTITY_KINDS } from "./vocabulary";

// A log monitor: what an independent party runs to check that a log never rewrote history.
// It pins the log's key on first sight, checks every signed tree head it sees against the
// last one it verified, and audits each entry: the leaves hash to the signed root, each entry
// as signed matches its leaf, each signature verifies against the key its signer held, and
// each revealed entry opens the commitment logged for it. Everything here reads a node
// through a `LogSource` and keeps no state of its own, so it runs in a page as well as in the
// command-line monitor.

/** What a monitor reads: a node's public log API, each answer as parsed JSON. */
export interface LogSource {
  /** GET /api/v1/log: the log's ID, its public key, and its latest signed tree head. */
  log(): Promise<unknown>;
  /** GET /api/v1/log/entries?start=&end=: the leaves [start, end), at most 100. */
  entries(start: number, end: number): Promise<unknown>;
  /** GET /api/v1/log/entries/{index}/signed: an entry as its signer signed it. */
  signedEntry(index: number): Promise<unknown>;
  /** GET /api/v1/log/proofs/consistency?first=&second= */
  consistencyProof(first: number, second: number): Promise<unknown>;
}

/** The most entries a node serves in one page. */
export const ENTRIES_PER_PAGE = 100;

/**
 * Ways a log can misbehave, each a check a monitor runs. Any of them means the log can't be
 * trusted as it stands: a command-line monitor exits with status 1.
 */
export const PROBLEMS = {
  log_id: "The node's log ID isn't log: and the SHA-256 of its public key",
  log_changed: "The node serves a different log or key than the one pinned",
  head: "A tree head isn't signed by the log's key, or names another log",
  shrank: "A tree head is smaller than one the log signed before",
  fork: "The log signed two different trees of the same size",
  timestamp: "A tree head or a leaf is stamped earlier than one before it",
  consistency: "A consistency proof between two signed tree heads doesn't verify",
  root: "The leaves the node serves don't hash to the signed root",
  leaf: "A leaf doesn't fit the protocol, or the node serves the wrong hash for it",
  signed_entry: "The entry served as signed isn't the one its leaf holds",
  signature: "A signature doesn't verify against the key that must have made it",
  signer: "A leaf names someone other than the entry's signer, or a signer with no key on the log",
  key: "A key entry, rotation, or recovery the protocol doesn't allow, or an operator or observer ID that isn't the SHA-256 of its first key",
  seal: "A revealed entry doesn't open its commitment, or a commitment is opened or closed twice",
  identity: "An identity the protocol doesn't allow, or an entry from an operator without the identity it needs",
  withdrawal: "A bundle withdrawn twice",
  challenge: "A challenge review that names no earlier challenge",
} as const;
export type ProblemCheck = keyof typeof PROBLEMS;

export interface Problem {
  check: ProblemCheck;
  /** The log index of the entry it concerns, when it concerns one. */
  index?: number;
  /** Exactly what is wrong. */
  reason: string;
  /** What shows it, such as two tree heads the log signed for one size. */
  evidence?: unknown;
}

/** An operational failure: the monitor couldn't read what it needed, so it couldn't finish. */
export class MonitorError extends Error {
  override name = "MonitorError";
}

// --- State ---------------------------------------------------------------------------

const HexHashSchema = z.string().regex(/^[0-9a-f]{64}$/, "Expected 32 bytes in hex");

/** When a signer got a key: the index of the entry that gave it, and the key. */
const KeyChangeSchema = z.strictObject({ index: z.number().int().nonnegative(), key: z.string() });
type KeyChange = z.infer<typeof KeyChangeSchema>;

/** An identity on the log: the entry that gave it, its kind, and what it rests on, which a recovery must go through. */
const IdentityRecordSchema = z.strictObject({
  index: z.number().int().nonnegative(),
  kind: z.enum(IDENTITY_KINDS),
  domain: DomainSchema.optional(),
  repository: RepositorySchema.optional(),
  observer: ObserverIdSchema.optional(),
});
type IdentityRecord = z.infer<typeof IdentityRecordSchema>;

/** How far an audit has read the log, and what it must remember to read on. */
export const AuditStateSchema = z.strictObject({
  /** Entries [0, size) have been audited. */
  size: z.number().int().nonnegative(),
  /** The compact range over the audited leaves: perfect subtree roots, largest first, in hex. */
  range: z.array(HexHashSchema),
  /** The last audited leaf's timestamp. */
  timestamp: z.iso.datetime().nullable(),
  /** Each operator's keys in log order: its key entry, then each rotation and recovery. */
  operators: z.record(OperatorIdSchema, z.array(KeyChangeSchema).min(1)),
  /** Each operator's identities, which its key recoveries rest on. */
  identities: z.record(OperatorIdSchema, z.array(IdentityRecordSchema).min(1)),
  /** Each observer's passkeys in log order, from their observer key entries. */
  observers: z.record(ObserverIdSchema, z.array(KeyChangeSchema).min(1)),
  /** Commitments not yet opened or closed, by the index of the sealed entry that holds each. */
  commitments: z.record(z.string().regex(/^(0|[1-9][0-9]*)$/), DigestSchema),
  /** The indexes of the challenges logged, which their reviews name. */
  challenges: z.array(z.number().int().nonnegative()),
  /** The bundles withdrawn, each of which can be withdrawn only once. */
  withdrawn: z.array(DigestSchema),
});
export type AuditState = z.infer<typeof AuditStateSchema>;

/** What a monitor keeps between runs: the pinned log, the last verified head, and its audit. */
export const MonitorStateSchema = z
  .strictObject({
    log: z.string(),
    public_key: PublicKeySchema,
    head: TreeHeadSchema.nullable(),
    audit: AuditStateSchema,
  })
  .refine((state) => state.log === logId(state.public_key), "The log ID doesn't match the key")
  .refine((state) => state.audit.size <= (state.head?.size ?? 0), "The audit reaches past the verified head");
export type MonitorState = z.infer<typeof MonitorStateSchema>;

function newState(log: string, publicKey: MonitorState["public_key"]): MonitorState {
  return {
    log,
    public_key: publicKey,
    head: null,
    audit: {
      size: 0,
      range: [],
      timestamp: null,
      operators: {},
      identities: {},
      observers: {},
      commitments: {},
      challenges: [],
      withdrawn: [],
    },
  };
}

// --- Answers from the node -----------------------------------------------------------

const LogInfoSchema = z.object({ log: z.string(), public_key: z.string(), tree_head: z.unknown() });
const JsonObjectSchema = z.record(z.string(), z.unknown());
const EntriesSchema = z.object({
  entries: z.array(z.object({ index: z.number().int(), leaf: JsonObjectSchema, leaf_hash: z.string() })),
});
const SignedEntrySchema = z.object({ index: z.number().int(), entry: JsonObjectSchema });
const ConsistencySchema = z.object({ proof: z.array(HexHashSchema) });

function answer<T>(schema: z.ZodType<T>, value: unknown, request: string): T {
  const parsed = schema.safeParse(value);
  if (parsed.success) return parsed.data;
  const issues = toIssues(parsed.error).map((issue) => `${issue.path || "/"}: ${issue.message}`);
  throw new MonitorError(`The node's answer to ${request} isn't what the API returns (${issues.join("; ")})`);
}

async function fetchProof(source: LogSource, first: number, second: number): Promise<string[]> {
  const request = `GET /api/v1/log/proofs/consistency?first=${first}&second=${second}`;
  return answer(ConsistencySchema, await source.consistencyProof(first, second), request).proof;
}

// --- Tree heads ----------------------------------------------------------------------

/**
 * Checks that `second` extends `first`, two heads the same log signed: it is no smaller, the
 * same size has the same root, it isn't stamped earlier, and a consistency proof from the
 * node shows the first tree is a prefix of the second. Each failure is a problem; `source`
 * may be null when the sizes are equal and no proof is needed.
 */
export async function checkGrowth(
  first: TreeHead,
  second: TreeHead,
  publicKey: string,
  source: LogSource | null,
): Promise<Problem[]> {
  const evidence = { first, second };
  if (second.size < first.size) {
    return [{ check: "shrank", reason: `The log signed a tree of ${first.size} entries, and now one of ${second.size}`, evidence }];
  }
  const problems: Problem[] = [];
  if (Date.parse(second.timestamp) < Date.parse(first.timestamp)) {
    problems.push({
      check: "timestamp",
      reason: `The head for ${second.size} entries is stamped ${second.timestamp}, before the head for ${first.size} stamped ${first.timestamp}`,
      evidence,
    });
  }
  if (second.size === first.size) {
    if (second.root !== first.root) {
      problems.push({ check: "fork", reason: `The log signed two trees of ${first.size} entries with different roots, ${first.root} and ${second.root}`, evidence });
    }
    return problems;
  }
  if (!source) throw new MonitorError("A node is needed to fetch the consistency proof between heads of different sizes");
  const proof = await fetchProof(source, first.size, second.size);
  if (!verifyTreeGrowth(first, second, proof, publicKey)) {
    problems.push({
      check: "consistency",
      reason: `The consistency proof from ${first.size} to ${second.size} entries doesn't verify: the tree of ${second.size} doesn't extend the tree of ${first.size}`,
      evidence: { ...evidence, proof },
    });
  }
  return problems;
}

/** Why a tree head isn't the pinned log's, or null if its signature and log ID check. */
function headProblem(head: TreeHead, log: string, publicKey: string): Problem | null {
  if (head.log !== log) return { check: "head", reason: `The tree head names ${head.log}, not ${log}`, evidence: { head } };
  if (!verifyObject(head, publicKey)) {
    return { check: "head", reason: `The tree head for ${head.size} entries isn't signed by the log's key`, evidence: { head } };
  }
  return null;
}

// --- Auditing entries ----------------------------------------------------------------

/** Each leaf's schema, by the type of entry it holds. */
const LEAF_SCHEMAS: ReadonlyMap<string, z.ZodType> = new Map(
  (LogLeafSchema as unknown as z.ZodUnion<z.ZodObject[]>).options.map((option) => [
    entryTypeOf(option.shape.entry as z.ZodType),
    option,
  ]),
);

function entryTypeOf(schema: z.ZodType): string {
  if (schema instanceof z.ZodDiscriminatedUnion) return entryTypeOf((schema.options as z.ZodType[])[0]);
  return ((schema as z.ZodObject).shape.type as z.ZodLiteral<string>).value;
}

/** What the log attests that only content kept off the log can show, so no monitor checks it. */
export const NOT_CHECKED = {
  bundle: "A bundle leaf's claim IDs, field tags, and the bundle it replaces come from the bundle's files, which the monitor doesn't fetch.",
  canary: "A canary leaf's claim IDs come from the canary bundle's files, which the monitor doesn't fetch.",
  identity: "A domain or GitHub identity rests on a DNS record or a repository file that can change after it is logged, so the organization the log derived from it isn't rechecked.",
  withdrawal: "A withdrawal of sealed work closes a commitment that hides the bundle, so the monitor can't match the two.",
  recovery: "A domain or GitHub recovery rests on a DNS record or a repository file naming the new key when it was logged, and a GitHub one on who owned the repository then, all of which can change after.",
  vouch: "A vouch counts only while its volunteer is approved, which the log doesn't show, so an operator with a vouch that recovered on its invitation may have been entitled to.",
  work: "An attestation, review, flag, or challenge names a bundle or a claim, and only the node's jobs say who could take that work. The monitor indexes neither, so it checks each one's signer, identity, and commitment, and that a challenge review names an earlier challenge.",
  disowned: "A key recovery may disown only recent entries; the monitor checks that it disowns nothing after itself, not how far back it reaches.",
} as const;
type Note = keyof typeof NOT_CHECKED;

// The loose shape of a leaf that passed its schema, for reading the fields its type has.
interface Leaf {
  timestamp: string;
  operator?: string;
  observer?: string;
  organization?: string;
  sealed?: SealReveal;
  entry: { type: string } & Record<string, unknown>;
}
type Signed = { type: string; sig: string } & Record<string, unknown>;
type PasskeySigned = { type: string; sig: PasskeySignature };

/**
 * Audits a log's entries one at a time, in order, from where an earlier audit stopped. Each
 * entry is its leaf, the hash the node serves for it, and the entry as signed. Problems
 * accumulate rather than stopping the audit, so one run reports all of them.
 */
export class LogAuditor {
  readonly problems: Problem[] = [];
  // Maps, not plain objects: entry types come from the log, and one named "constructor" or
  // "__proto__" must not reach an object's prototype.
  /** How many entries of each type this auditor has read. */
  readonly types = new Map<string, number>();
  /** Entries whose type this monitor doesn't know, by type: only their place in the tree is checked. */
  readonly unknown = new Map<string, number[]>();
  readonly notes = new Set<Note>();

  private size: number;
  private readonly range: Uint8Array[];
  private timestamp: string | null;
  private readonly operators: Map<string, KeyChange[]>;
  private readonly identities: Map<string, IdentityRecord[]>;
  private readonly observers: Map<string, KeyChange[]>;
  private readonly commitments: Map<number, Digest>;
  private readonly challenges: Set<number>;
  private readonly withdrawn: Set<string>;
  /** Which operator first held each key, retired keys included. */
  private readonly holders = new Map<string, string>();

  constructor(
    private readonly logKey: string,
    state: AuditState,
  ) {
    this.size = state.size;
    this.range = state.range.map(hexToBytes);
    this.timestamp = state.timestamp;
    this.operators = new Map(Object.entries(state.operators).map(([id, keys]) => [id, [...keys]]));
    this.identities = new Map(Object.entries(state.identities).map(([id, held]) => [id, [...held]]));
    this.observers = new Map(Object.entries(state.observers).map(([id, keys]) => [id, [...keys]]));
    this.commitments = new Map(Object.entries(state.commitments).map(([index, digest]) => [Number(index), digest]));
    this.challenges = new Set(state.challenges);
    this.withdrawn = new Set(state.withdrawn);
    for (const [operator, keys] of this.operators) for (const { key } of keys) this.holders.set(key, operator);
  }

  /** How many entries have been audited, this run and before. */
  get audited(): number {
    return this.size;
  }

  /** The Merkle root over every audited leaf. */
  root(): Uint8Array {
    return rangeRoot(this.range);
  }

  /** The last audited leaf's timestamp. */
  get lastTimestamp(): string | null {
    return this.timestamp;
  }

  /** How many commitments wait to be opened. */
  get waiting(): number {
    return this.commitments.size;
  }

  state(): AuditState {
    // Sorted by ID, so the same log always saves the same state.
    const record = <T>(map: Map<string, T>) => Object.fromEntries([...map].sort(([a], [b]) => (a < b ? -1 : 1)));
    return {
      size: this.size,
      range: this.range.map(bytesToHex),
      timestamp: this.timestamp,
      operators: record(this.operators),
      identities: record(this.identities),
      observers: record(this.observers),
      commitments: Object.fromEntries([...this.commitments].sort(([a], [b]) => a - b).map(([i, d]) => [String(i), d])),
      challenges: [...this.challenges].sort((a, b) => a - b),
      withdrawn: [...this.withdrawn].sort() as Digest[],
    };
  }

  /** Audits entry `index`, which must be the next one. */
  add(index: number, leaf: Record<string, unknown>, servedHash: string, signed: Record<string, unknown>): void {
    if (index !== this.size) throw new MonitorError(`Expected entry ${this.size} next, not entry ${index}`);
    const hash = leafHash(leafBytes(leaf as LogLeaf));
    extendRange(this.range, this.size, hash);
    this.size += 1;
    if (bytesToHex(hash) !== servedHash) {
      this.problem(index, "leaf", `The node serves leaf hash ${servedHash}, but the leaf hashes to ${bytesToHex(hash)}`);
    }

    const type = (leaf.entry as { type?: unknown } | undefined)?.type;
    if (typeof type !== "string") return this.problem(index, "leaf", "The leaf holds no entry with a type");
    this.types.set(type, (this.types.get(type) ?? 0) + 1);
    const schema = LEAF_SCHEMAS.get(type);
    if (!schema) return this.unknownType(index, type);
    const parsed = schema.safeParse(leaf);
    if (!parsed.success) {
      const issues = toIssues(parsed.error).map((issue) => `${issue.path || "/"}: ${issue.message}`);
      return this.problem(index, "leaf", `The ${type} leaf doesn't fit the protocol (${issues.join("; ")})`);
    }
    const checked = leaf as unknown as Leaf;
    if (this.timestamp !== null && Date.parse(checked.timestamp) < Date.parse(this.timestamp)) {
      this.problem(index, "timestamp", `The leaf is stamped ${checked.timestamp}, before entry ${index - 1}, stamped ${this.timestamp}`);
    }
    this.timestamp = checked.timestamp;

    // The leaf, which the tree fixes, says who holds which key and which commitments wait.
    // Its signatures can be checked only when the entry served as signed is the leaf's.
    let verifiable: Signed | null = signed as Signed;
    if (!matchesLeafEntry(signed, checked.entry)) {
      const differences = entryDifferences(signed, checked.entry).join("; ");
      this.problem(index, "signed_entry", `The entry served as signed isn't the one the leaf holds: ${differences}`);
      verifiable = null;
    }
    this.check(index, checked, verifiable);
  }

  private check(index: number, leaf: Leaf, signed: Signed | null): void {
    const { entry } = leaf;
    // An entry revealed from a commitment was signed when its commitment was logged.
    const signedAt = leaf.sealed ? this.open(index, leaf) : index;
    const operator = leaf.operator!;
    const type = entry.type as LogLeaf["entry"]["type"];
    switch (type) {
      case "key":
        return this.register(index, operator, entry.key as string, signed);
      case "key_rotation":
        return this.rotate(index, operator, entry as unknown as Detached<KeyRotationEntry>, signed);
      case "key_recovery":
        return this.recover(index, operator, entry as unknown as Detached<KeyRecoveryEntry>, signed);
      // Publishing, every job, a flag, and a challenge each need an identity on the log first.
      case "bundle":
        this.notes.add("bundle");
        this.requireIdentity(index, entry.type, operator, signedAt);
        return this.signedByOperator(index, entry.type, signed, operator, signedAt);
      case "attestation":
        this.notes.add("work");
        this.names(index, "verifier", entry.verifier, operator);
        this.requireIdentity(index, entry.type, operator, signedAt);
        return this.signedByOperator(index, entry.type, signed, operator, signedAt);
      case "hazard_review":
        this.notes.add("work");
        this.names(index, "reviewer", entry.reviewer, operator);
        this.requireIdentity(index, entry.type, operator, signedAt);
        return this.signedByOperator(index, entry.type, signed, operator, signedAt);
      case "hazard_flag":
        this.notes.add("work");
        this.names(index, "operator", entry.operator, operator);
        this.requireIdentity(index, entry.type, operator, signedAt);
        return this.signedByOperator(index, entry.type, signed, operator, signedAt);
      case "challenge":
        this.notes.add("work");
        this.names(index, "challenger", entry.challenger, operator);
        this.requireIdentity(index, entry.type, operator, index);
        this.challenges.add(index);
        return this.signedByOperator(index, entry.type, signed, operator, index);
      case "challenge_review": {
        // A panelist reviews a challenge already on the log, so it comes before the review's commitment.
        this.notes.add("work");
        this.names(index, "reviewer", entry.reviewer, operator);
        const challenge = entry.challenge as number;
        if (!this.challenges.has(challenge) || challenge >= signedAt) {
          this.problem(index, "challenge", `The review names entry ${challenge}, which isn't a challenge logged before the review was committed at entry ${signedAt}`);
        }
        this.requireIdentity(index, entry.type, operator, signedAt);
        return this.signedByOperator(index, entry.type, signed, operator, signedAt);
      }
      case "citation_check":
      case "duplicate_check":
        this.notes.add("work");
        this.names(index, "checker", entry.checker, operator);
        this.requireIdentity(index, entry.type, operator, signedAt);
        return this.signedByOperator(index, entry.type, signed, operator, signedAt);
      case "preregistration":
        this.names(index, "operator", entry.operator, operator);
        this.requireIdentity(index, entry.type, operator, index);
        return this.signedByOperator(index, entry.type, signed, operator, index);
      case "identity":
        return this.identity(index, leaf, entry as unknown as Detached<IdentityEntry>, signed);
      case "task":
        return this.task(index, operator, entry.operator_key_digest as string, signed);
      case "observer_key":
        this.names(index, "observer", entry.observer, leaf.observer!);
        this.signedByLog(index, entry.type, signed);
        // A volunteer's first passkey makes their ID; one rebound to a new passkey keeps it.
        if (!this.observers.has(leaf.observer!) && leaf.observer !== observerId(entry.key as string)) {
          this.problem(index, "key", `The observer key entry names ${leaf.observer}, but the passkey it records first makes ${observerId(entry.key as string)}`);
        }
        return this.addKey(this.observers, leaf.observer!, index, entry.key as string);
      case "observation":
        return this.observation(index, leaf.observer!, signed);
      case "idea":
        return this.idea(index, leaf.observer!, signed);
      case "sealed":
        this.signedByLog(index, entry.type, signed);
        this.commitments.set(index, entry.commitment as Digest);
        return;
      case "canary":
        this.notes.add("canary");
        return this.signedByLog(index, entry.type, signed);
      case "withdrawal": {
        this.signedByLog(index, entry.type, signed);
        const bundle = entry.bundle as Digest;
        if (this.withdrawn.has(bundle)) this.problem(index, "withdrawal", `${bundle} was withdrawn before; a bundle is withdrawn once`);
        this.withdrawn.add(bundle);
        if (entry.sealed !== undefined) {
          this.notes.add("withdrawal");
          this.close(index, entry.sealed as number);
        }
        return;
      }
      default: {
        // A leaf type the schema gained without a check here stops the build, not the audit.
        const unchecked: never = type;
        return this.unknownType(index, unchecked);
      }
    }
  }

  private unknownType(index: number, type: string): void {
    const indexes = this.unknown.get(type);
    if (indexes) indexes.push(index);
    else this.unknown.set(type, [index]);
  }

  /** Checks that a revealed entry opens a waiting commitment; returns where that was logged. */
  private open(index: number, leaf: Leaf): number {
    const { index: at, salt } = leaf.sealed!;
    if (at >= index) {
      this.problem(index, "seal", `The entry opens a commitment at entry ${at}, which doesn't come before it`);
      return at;
    }
    const commitment = this.commitments.get(at);
    if (commitment === undefined) {
      this.problem(index, "seal", `Entry ${at} holds no commitment waiting to be opened: it isn't a sealed entry, or an earlier entry opened or closed it`);
    } else if (sealCommitment(leaf.entry, salt) !== commitment) {
      this.problem(index, "seal", `The entry and its salt don't open the commitment at entry ${at}`);
    }
    this.commitments.delete(at);
    return at;
  }

  /** A withdrawal of sealed work closes its commitment, which then never opens. */
  private close(index: number, at: number): void {
    if (!this.commitments.delete(at)) {
      this.problem(index, "seal", `The withdrawal closes the commitment at entry ${at}, but no commitment waits there`);
    }
  }

  private register(index: number, operator: string, key: string, signed: Signed | null): void {
    if (operator !== operatorId(key)) {
      this.problem(index, "key", `The key entry names ${operator}, but the key it registers makes ${operatorId(key)}`);
    }
    const existing = this.operators.get(operator);
    if (existing) {
      this.problem(index, "key", `${operator} already registered a key at entry ${existing[0].index}; an operator changes keys only by rotation or recovery`);
    } else {
      this.requireFreeKey(index, operator, key);
      this.operators.set(operator, [{ index, key }]);
      this.holders.set(key, operator);
    }
    if (signed && !verifyObject(signed, key)) this.problem(index, "signature", "The key entry isn't signed by the key it registers");
  }

  private rotate(index: number, operator: string, entry: Detached<KeyRotationEntry>, signed: Signed | null): void {
    this.names(index, "operator", entry.operator, operator);
    const held = this.keyOf(operator, index);
    if (!held) {
      this.problem(index, "signer", `${operator} has no key on the log to rotate from`);
    } else if (signed && !verifyObject(signed, held.key)) {
      this.problem(index, "signature", `The rotation's sig doesn't verify against ${operator}'s key from entry ${held.index}`);
    }
    if (signed && !verify(signed.key_sig as string, keyRotationPayload(entry), entry.key)) {
      this.problem(index, "signature", "The rotation's key_sig isn't the new key's signature over the entry without sig and key_sig");
    }
    this.changeKey(index, operator, entry.key);
  }

  /**
   * A recovery comes from the identity the operator counts as, the firmest one it holds, so
   * it must rest on an identity the log already holds and never a weaker one than another
   * it holds: a domain, then a GitHub account, then a vouch, then an invitation.
   */
  private recover(index: number, operator: string, entry: Detached<KeyRecoveryEntry>, signed: Signed | null): void {
    this.names(index, "operator", entry.operator, operator);
    if (!this.operators.has(operator)) this.problem(index, "signer", `${operator} has no key on the log to recover`);
    if (entry.since > index) {
      this.problem(index, "key", `The recovery disowns entries from ${entry.since}, past the log's size when it was logged (${index})`);
    } else if (entry.since < index) {
      this.notes.add("disowned");
    }
    const held = this.identities.get(operator) ?? [];
    const kind = entry.kind;
    const through = held.find((identity) => identity.kind === kind);
    const firmer = held.find((identity) => IDENTITY_KINDS.indexOf(identity.kind) < IDENTITY_KINDS.indexOf(kind));
    // Whether a vouch still stands depends on its volunteer, which the log doesn't show.
    if (firmer && !(kind === "invited" && firmer.kind === "vouched")) {
      this.problem(index, "key", `The recovery goes through ${operator}'s ${kind} identity, but ${operator} counts as its ${firmer.kind} identity, from entry ${firmer.index}, and recovers through that`);
    } else if (firmer) {
      this.notes.add("vouch");
    }
    if (!through) {
      this.problem(index, "key", `The recovery goes through ${operator}'s ${kind} identity, but ${operator} has none on the log`);
    }
    switch (kind) {
      case "domain":
      case "github": {
        this.notes.add("recovery");
        const named = kind === "domain" ? entry.domain : entry.repository;
        const proven = kind === "domain" ? through?.domain : through?.repository;
        if (through && proven !== named) {
          this.problem(index, "key", `The recovery goes through ${named}, but ${operator}'s ${kind} identity, from entry ${through.index}, is ${proven}`);
        }
        this.signedByNewKey(index, entry, signed);
        break;
      }
      case "vouched": {
        if (through && through.observer !== entry.observer) {
          this.problem(index, "key", `The recovery is approved by ${entry.observer}, but ${operator} was vouched for by ${through.observer}, at entry ${through.index}`);
        }
        const voucher = latest(this.observers.get(entry.observer), index);
        if (!voucher) {
          this.problem(index, "signer", `${entry.observer} has no passkey on the log to approve the recovery with`);
        } else if (signed && !verifyRecoveryApproval(signed as unknown as VouchedRecoveryEntry, voucher.key)) {
          this.problem(index, "signature", `The recovery's voucher_sig doesn't verify against ${entry.observer}'s passkey from entry ${voucher.index}`);
        }
        this.signedByNewKey(index, entry, signed);
        break;
      }
      case "invited":
        this.signedByLog(index, entry.type, signed);
        break;
      default: {
        // A recovery kind the schema gained without a rule here stops the build, not the audit.
        const unchecked: never = kind;
        this.unknownType(index, `key_recovery (${String(unchecked)})`);
      }
    }
    this.changeKey(index, operator, entry.key);
  }

  /** A recovery by the operator's own proof is signed by the new key it names, over everything but `sig`. */
  private signedByNewKey(index: number, entry: Detached<KeyRecoveryEntry>, signed: Signed | null): void {
    if (signed && !verifyObject(signed, entry.key)) {
      this.problem(index, "signature", "The key_recovery entry's sig doesn't verify against the new key it names");
    }
  }

  private changeKey(index: number, operator: string, key: string): void {
    this.requireFreeKey(index, operator, key);
    this.addKey(this.operators, operator, index, key);
    if (!this.holders.has(key)) this.holders.set(key, operator);
  }

  /** A new key must be one no operator holds or has retired, the operator itself included. */
  private requireFreeKey(index: number, operator: string, key: string): void {
    const holder = this.holders.get(key);
    if (holder) {
      this.problem(index, "key", `${operator} takes a key that ${holder === operator ? "it" : holder} already held; a key serves one operator, once`);
    }
  }

  private addKey(map: Map<string, KeyChange[]>, id: string, index: number, key: string): void {
    const keys = map.get(id);
    if (keys) keys.push({ index, key });
    else map.set(id, [{ index, key }]);
  }

  private identity(index: number, leaf: Leaf, entry: Detached<IdentityEntry>, signed: Signed | null): void {
    const operator = leaf.operator!;
    this.names(index, "operator", entry.operator, operator);
    const held = this.identities.get(operator) ?? [];
    const same = held.find((identity) => identity.kind === entry.kind);
    if (same) {
      this.problem(index, "identity", `This is ${operator}'s second ${entry.kind} identity, after entry ${same.index}; an operator holds at most one of each kind`);
    } else {
      this.identities.set(operator, [
        ...held,
        {
          index,
          kind: entry.kind,
          ...(entry.kind === "domain" && { domain: entry.domain }),
          ...(entry.kind === "github" && { repository: entry.repository }),
          ...(entry.kind === "vouched" && { observer: entry.observer }),
        },
      ]);
    }
    switch (entry.kind) {
      case "domain":
      case "github":
        this.notes.add("identity");
        return this.signedByOperator(index, entry.type, signed, operator, index);
      case "vouched": {
        if (leaf.organization !== entry.observer) {
          this.problem(index, "identity", `A vouched identity counts as the volunteer, ${entry.observer}, not ${leaf.organization}`);
        }
        const voucher = latest(this.observers.get(entry.observer), index);
        if (!voucher) {
          this.problem(index, "signer", `${entry.observer} has no passkey on the log to vouch with`);
        } else if (signed && !verifyVouch(signed as unknown as Vouch, voucher.key)) {
          this.problem(index, "signature", `The vouch's voucher_sig doesn't verify against ${entry.observer}'s passkey from entry ${voucher.index}`);
        }
        return this.signedByOperator(index, entry.type, signed, operator, index);
      }
      case "invited":
        if (leaf.organization !== operator) {
          this.problem(index, "identity", `An invited operator counts as itself, ${operator}, not ${leaf.organization}`);
        }
        return this.signedByLog(index, entry.type, signed);
      default: {
        // An identity kind the schema gained without a rule here stops the build, not the audit.
        const unchecked: never = entry;
        this.unknownType(index, `identity (${String((unchecked as { kind: unknown }).kind)})`);
      }
    }
  }

  /**
   * A task waits for a person's approval before it is logged, so its operator may have
   * changed keys since signing it. It names its key by digest, which must be a key the
   * operator held on the log before the task.
   */
  private task(index: number, operator: string, named: string, signed: Signed | null): void {
    const held = (this.operators.get(operator) ?? []).find((change) => change.index < index && keyDigest(change.key) === named);
    if (!held) {
      return this.problem(index, "signer", `The task names key ${named}, which ${operator} didn't hold on the log before it`);
    }
    if (signed && !verifyObject(signed, held.key)) {
      this.problem(index, "signature", `The task's sig doesn't verify against the key it names, ${operator}'s key from entry ${held.index}`);
    }
  }

  private observation(index: number, observer: string, signed: Signed | null): void {
    const held = latest(this.observers.get(observer), index);
    if (!held) return this.problem(index, "signer", `${observer} has no passkey on the log`);
    if (signed && !verifyPasskeyObject(signed as unknown as PasskeySigned, held.key)) {
      this.problem(index, "signature", `The observation's passkey signature doesn't verify against ${observer}'s passkey from entry ${held.index}`);
    }
  }

  /**
   * An idea waits for a person's approval before it is logged, so a volunteer who lost their
   * passkey in between signed it with the one before: any passkey they held on the log counts.
   */
  private idea(index: number, observer: string, signed: Signed | null): void {
    const keys = (this.observers.get(observer) ?? []).filter((change) => change.index < index);
    if (keys.length === 0) return this.problem(index, "signer", `${observer} has no passkey on the log`);
    if (signed && !keys.some(({ key }) => verifyPasskeyObject(signed as unknown as PasskeySigned, key))) {
      this.problem(index, "signature", `The idea's passkey signature doesn't verify against any passkey ${observer} held on the log before it`);
    }
  }

  /** The entry needs its operator to have proven an identity on the log before position `at`. */
  private requireIdentity(index: number, type: string, operator: string, at: number): void {
    if (!(this.identities.get(operator) ?? []).some((identity) => identity.index < at)) {
      this.problem(index, "identity", `${operator} has no identity on the log before entry ${at}, and ${type} entries need one`);
    }
  }

  /** The entry is signed by the key `operator` held at log position `at`. */
  private signedByOperator(index: number, type: string, signed: Signed | null, operator: string, at: number): void {
    const held = this.keyOf(operator, at);
    if (!held) return this.problem(index, "signer", `${operator} has no key on the log before entry ${at}`);
    if (signed && !verifyObject(signed, held.key)) {
      const when = at === index ? "" : `, which it held when the commitment at entry ${at} was logged`;
      this.problem(index, "signature", `The ${type} entry's sig doesn't verify against ${operator}'s key from entry ${held.index}${when}`);
    }
  }

  private signedByLog(index: number, type: string, signed: Signed | null): void {
    if (signed && !verifyObject(signed, this.logKey)) {
      this.problem(index, "signature", `The ${type} entry's sig doesn't verify against the log's key`);
    }
  }

  /** The leaf must attribute the entry to the signer the entry names. */
  private names(index: number, field: string, named: unknown, attributed: string): void {
    if (named !== attributed) {
      this.problem(index, "signer", `The entry's ${field} is ${String(named)}, but the leaf attributes it to ${attributed}`);
    }
  }

  /** The key `operator` held at log position `at`: the last one an entry before it gave it. */
  private keyOf(operator: string, at: number): KeyChange | null {
    return latest(this.operators.get(operator), at);
  }

  private problem(index: number, check: ProblemCheck, reason: string): void {
    this.problems.push({ check, index, reason });
  }
}

function latest(keys: readonly KeyChange[] | undefined, at: number): KeyChange | null {
  let held: KeyChange | null = null;
  for (const change of keys ?? []) if (change.index < at) held = change;
  return held;
}

/** How an entry as signed differs from the leaf's entry: fields, and signatures by their digests. */
function entryDifferences(signed: Record<string, unknown>, leafEntry: Record<string, unknown>): string[] {
  const detached = detachSignatures(signed) as Record<string, unknown>;
  const names = [...new Set([...Object.keys(detached), ...Object.keys(leafEntry)])].sort();
  return names.flatMap((name) => {
    if (!(name in detached)) return [`it has no ${name}`];
    if (!(name in leafEntry)) return [`it has ${name}, which the leaf doesn't`];
    if (canonicalJson(detached[name]) === canonicalJson(leafEntry[name])) return [];
    return (SIGNATURE_FIELDS as readonly string[]).includes(name) ? [`its ${name} doesn't match the digest in the leaf`] : [`its ${name} differs`];
  });
}

// --- A monitor run -------------------------------------------------------------------

export interface MonitorOptions {
  /** Pin the log the node serves now, even if it isn't the pinned one. */
  pin?: boolean;
  /** The most new entries to audit in this run; 0 skips the audit. All of them by default. */
  maxEntries?: number;
  /** How many signed entries to fetch at once. */
  concurrency?: number;
  /**
   * The largest tree this node served before, when the saved state may be another node's
   * view of the same log. A smaller head from it means it dropped entries; a head smaller
   * only than the saved one means it lags behind, which is fine if the saved head extends
   * it. By default, the saved head's size, as when the saved state is this node's own.
   */
  servedBefore?: number;
  /**
   * A node that serves the saved head, to prove a lagging node's head is a prefix of it: a
   * node can't prove anything about a tree it doesn't have. By default, the node itself.
   */
  ahead?: LogSource;
}

export interface MonitorReport {
  /** The log the node serves, once known. */
  log: string | null;
  /** Whether this run pinned the log: the first run, or one told to pin again. */
  pinned: boolean;
  /** The last verified tree head before this run. */
  previous: TreeHead | null;
  /** The tree head this run checked. */
  head: TreeHead | null;
  /** Whether the node lags behind: its head is older than the last one verified, which extends it. */
  behind: boolean;
  /** The entries this run audited, [from, to), and how many of each type. */
  audit: { from: number; to: number; types: Record<string, number> } | null;
  /** How many entries have been audited in all, this run and before. */
  audited: number;
  /** Commitments still waiting to be opened. */
  waiting: number;
  /** Ways the log misbehaved. */
  problems: Problem[];
  /** What wasn't checked, and why. */
  unchecked: string[];
  /** Why the run couldn't finish, if it couldn't. */
  error: string | null;
}

export interface MonitorResult {
  report: MonitorReport;
  /** The state to keep for the next run; null when this run didn't verify everything it read. */
  state: MonitorState | null;
}

/** 0 when everything checked, 1 when the log misbehaved, 2 when the monitor couldn't finish. */
export function exitStatus(report: { problems: readonly Problem[]; error: string | null }): 0 | 1 | 2 {
  return report.problems.length > 0 ? 1 : report.error !== null ? 2 : 0;
}

/**
 * One run of a monitor. On first sight it pins the log: its ID must be `log:` and the SHA-256
 * of its key. Then it checks the latest tree head's signature, checks that the head extends
 * the last one it verified, and audits the entries added since, up to `maxEntries`. The state
 * it returns replaces the saved one only when everything checked.
 */
export async function monitorLog(
  source: LogSource,
  saved: MonitorState | null,
  options: MonitorOptions = {},
): Promise<MonitorResult> {
  const report: MonitorReport = {
    log: saved?.log ?? null,
    pinned: false,
    previous: saved?.head ?? null,
    head: null,
    behind: false,
    audit: null,
    audited: saved?.audit.size ?? 0,
    waiting: Object.keys(saved?.audit.commitments ?? {}).length,
    problems: [],
    unchecked: [],
    error: null,
  };
  let state: MonitorState | null = null;
  try {
    state = await run(source, saved, options, report);
  } catch (error) {
    report.error = error instanceof Error ? error.message : String(error);
  }
  return { report, state: exitStatus(report) === 0 ? state : null };
}

async function run(
  source: LogSource,
  saved: MonitorState | null,
  options: MonitorOptions,
  report: MonitorReport,
): Promise<MonitorState | null> {
  const info = answer(LogInfoSchema, await source.log(), "GET /api/v1/log");
  report.log = info.log;
  if (info.log !== logId(info.public_key)) {
    report.problems.push({ check: "log_id", reason: `The node calls its log ${info.log}, but its key's ID is ${logId(info.public_key)}` });
    return null;
  }
  const key = PublicKeySchema.safeParse(info.public_key);
  if (!key.success) throw new MonitorError("The node's public key isn't a key this protocol uses");

  let state = saved;
  if (state && (state.log !== info.log || state.public_key !== info.public_key)) {
    if (!options.pin) {
      report.problems.push({
        check: "log_changed",
        reason: `The node now serves ${info.log}, but the pinned log is ${state.log}. Pin again only if you trust the change: a different key is a different log.`,
        evidence: { pinned: { log: state.log, public_key: state.public_key }, served: { log: info.log, public_key: info.public_key } },
      });
      return null;
    }
    state = null;
  }
  if (!state) {
    state = newState(info.log, key.data);
    report.pinned = true;
    report.previous = null;
    report.audited = 0;
    report.waiting = 0;
  }

  if (info.tree_head === null) {
    if (state.head) {
      report.problems.push({ check: "shrank", reason: `The node says the log is empty, but it signed a tree of ${state.head.size} entries`, evidence: { first: state.head } });
      return null;
    }
    return state;
  }
  const head = answer(TreeHeadSchema, info.tree_head, "GET /api/v1/log (its tree_head)");
  report.head = head;
  const invalid = headProblem(head, state.log, state.public_key);
  if (invalid) {
    report.problems.push(invalid);
    return null;
  }
  if (state.head) {
    const before = Math.min(options.servedBefore ?? state.head.size, state.head.size);
    if (head.size < state.head.size && head.size >= before) {
      // This node lags behind another that serves the same log; the head verified before must extend its head.
      report.problems.push(...(await checkGrowth(head, state.head, state.public_key, options.ahead ?? source)));
      if (report.problems.length > 0) return null;
      report.behind = true;
      return state;
    }
    if (head.size < before && before < state.head.size) {
      report.problems.push({ check: "shrank", reason: `This node served a tree of ${before} entries, and now one of ${head.size}`, evidence: { head } });
      return null;
    }
    report.problems.push(...(await checkGrowth(state.head, head, state.public_key, source)));
    if (report.problems.length > 0) return null;
  }

  const audit = await auditEntries(source, state, head, options, report);
  return { ...state, head, audit };
}

async function auditEntries(
  source: LogSource,
  state: MonitorState,
  head: TreeHead,
  options: MonitorOptions,
  report: MonitorReport,
): Promise<AuditState> {
  const auditor = new LogAuditor(state.public_key, state.audit);
  const from = auditor.audited;
  const to = Math.min(head.size, from + Math.max(0, options.maxEntries ?? Infinity));
  try {
    await readEntries(source, auditor, from, to, options.concurrency ?? 8);
  } finally {
    // What the audit found stands even if a later request failed: misbehavior outranks a failure to finish.
    report.audit = { from, to: auditor.audited, types: Object.fromEntries(auditor.types) };
    report.audited = auditor.audited;
    report.waiting = auditor.waiting;
    report.problems.push(...auditor.problems);
    report.unchecked.push(...[...auditor.notes].map((note) => NOT_CHECKED[note]));
    for (const [type, indexes] of auditor.unknown) {
      report.unchecked.push(
        `This monitor doesn't know how to check ${type} entries, so it checked only where they sit in the tree: ${indexes.join(", ")}.`,
      );
    }
  }

  if (to > from) {
    const root = auditor.root();
    if (to === head.size) {
      if (bytesToHex(root) !== head.root) {
        report.problems.push({
          check: "root",
          reason: `The ${head.size} leaves the node serves hash to ${bytesToHex(root)}, not the signed root ${head.root}`,
          evidence: { head },
        });
      }
    } else {
      // A partial audit: the leaves read so far must be a prefix of the signed tree.
      const proof = await fetchProof(source, to, head.size);
      if (!verifyConsistency(to, head.size, root, hexToBytes(head.root), proof.map(hexToBytes))) {
        report.problems.push({
          check: "root",
          reason: `The first ${to} leaves the node serves (root ${bytesToHex(root)}) aren't a prefix of the signed tree of ${head.size}`,
          evidence: { head, proof },
        });
      }
    }
  }
  const last = auditor.lastTimestamp;
  if (last !== null && Date.parse(last) > Date.parse(head.timestamp)) {
    report.problems.push({
      check: "timestamp",
      index: auditor.audited - 1,
      reason: `The leaf is stamped ${last}, after the tree head that holds it, stamped ${head.timestamp}`,
    });
  }
  return auditor.state();
}

/** Feeds the auditor entries [from, to), a page of leaves and their signed entries at a time. */
async function readEntries(source: LogSource, auditor: LogAuditor, from: number, to: number, concurrency: number): Promise<void> {
  for (let start = from; start < to; start += ENTRIES_PER_PAGE) {
    const end = Math.min(start + ENTRIES_PER_PAGE, to);
    const request = `GET /api/v1/log/entries?start=${start}&end=${end}`;
    const { entries } = answer(EntriesSchema, await source.entries(start, end), request);
    const indexes = entries.map((entry) => entry.index);
    if (indexes.length !== end - start || indexes.some((index, i) => index !== start + i)) {
      throw new MonitorError(`The node's answer to ${request} holds entries [${indexes.join(", ")}]`);
    }
    const signed = await inParallel(indexes, concurrency, async (index) => {
      const answered = answer(SignedEntrySchema, await source.signedEntry(index), `GET /api/v1/log/entries/${index}/signed`);
      if (answered.index !== index) throw new MonitorError(`The node answered for entry ${answered.index} when asked for entry ${index}`);
      return answered.entry;
    });
    entries.forEach((entry, i) => auditor.add(entry.index, entry.leaf, entry.leaf_hash, signed[i]));
  }
}

/** Runs `work` on each item with at most `limit` at once, keeping the results in order. */
async function inParallel<T, R>(items: readonly T[], limit: number, work: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await work(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

// --- Checkpoints ---------------------------------------------------------------------

/**
 * A verified tree head, with the key that signed it, for comparing out of band. Two monitors
 * that compare checkpoints catch a log showing different histories to different readers.
 */
export const CheckpointSchema = z.strictObject({
  log: z.string(),
  public_key: PublicKeySchema,
  tree_head: TreeHeadSchema,
  /** Where the head was read, so a comparison knows where to ask for a proof. */
  node: z.string().optional(),
});
export type Checkpoint = z.infer<typeof CheckpointSchema>;

/** The last verified head in a monitor's state, as a checkpoint; null before any head verified. */
export function checkpointOf(state: MonitorState, node?: string): Checkpoint | null {
  if (!state.head) return null;
  return { log: state.log, public_key: state.public_key, tree_head: state.head, ...(node && { node }) };
}

export interface Comparison {
  log: string | null;
  /** The smaller head, then the larger. */
  heads: [TreeHead, TreeHead] | null;
  problems: Problem[];
  error: string | null;
}

/**
 * Checks two checkpoints of one log against each other: each head is the log's, and the
 * larger extends the smaller, by a consistency proof from `source` when their sizes differ.
 * Checkpoints of different logs, or ones the log didn't sign, are errors rather than problems:
 * they say nothing about the log.
 */
export async function compareCheckpoints(a: Checkpoint, b: Checkpoint, source: LogSource | null): Promise<Comparison> {
  const comparison: Comparison = { log: null, heads: null, problems: [], error: null };
  try {
    for (const [name, checkpoint] of [["first", a], ["second", b]] as const) {
      if (checkpoint.log !== logId(checkpoint.public_key)) {
        throw new MonitorError(`The ${name} checkpoint names ${checkpoint.log}, but its key's ID is ${logId(checkpoint.public_key)}`);
      }
      if (headProblem(checkpoint.tree_head, checkpoint.log, checkpoint.public_key)) {
        throw new MonitorError(`The ${name} checkpoint's tree head isn't signed by ${checkpoint.log}`);
      }
    }
    if (a.log !== b.log) throw new MonitorError(`The checkpoints are of different logs, ${a.log} and ${b.log}`);
    comparison.log = a.log;
    const [first, second] = [a.tree_head, b.tree_head].sort((x, y) => x.size - y.size);
    comparison.heads = [first, second];
    comparison.problems = await checkGrowth(first, second, a.public_key, source);
  } catch (error) {
    comparison.error = error instanceof Error ? error.message : String(error);
  }
  return comparison;
}
