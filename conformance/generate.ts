// Writes the conformance vectors to the directory given on the command line, using the
// protocol library. Everything is deterministic: test keys come from fixed strings, and the
// ML-DSA half of each signature uses FIPS 204's deterministic variant, so rerunning this
// produces identical files. The conformance bundles on the ledger hold what each version of
// this generator wrote.
//
// Every invalid case is first checked to be rejected by the library, so the vectors can't
// encode a rule the implementation doesn't enforce.
//
//   npx tsx generate.ts <output directory>

import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  assignClaimIds,
  BundleLayoutError,
  bundleSigningObject,
  canonicalJson,
  ClaimsFileSchema,
  consistencyProof,
  declaredInputs,
  detachLeaf,
  digestBundle,
  EMPTY_ROOT,
  inclusionProof,
  JsonError,
  keyDigest,
  leafBytes,
  leafHash,
  memorySource,
  parseJson,
  publicKeyOf,
  ResultError,
  rootHash,
  SIGNATURE_ALGORITHM,
  signatureDigest,
  signingPayload,
  verify,
  verifyConsistency,
  verifyInclusion,
  type Claim,
  type Digest,
  type PublicKey,
  type Signature,
  type SignedLeaf,
} from "@sciencejournal/protocol";

const data = process.argv[2];
if (!data) {
  console.error("Usage: tsx generate.ts <output directory>");
  process.exit(1);
}
mkdirSync(data, { recursive: true });

/** Throws unless `check` reports the case invalid: a guard on every negative vector. */
function mustReject(name: string, check: () => boolean) {
  let accepted: boolean;
  try {
    accepted = check();
  } catch (error) {
    if (error instanceof JsonError || error instanceof BundleLayoutError || error instanceof ResultError) return;
    throw error;
  }
  if (accepted) throw new Error(`The reference implementation accepts the invalid case "${name}"`);
}
const write = (name: string, value: unknown) =>
  writeFileSync(join(data, name), `${JSON.stringify(value, null, 2)}\n`);

/** A test key: never used for anything but these vectors. Its two seeds are a SHA-512. */
function testKey(n: number) {
  const secretKey = sha512(utf8ToBytes(`sciencejournal conformance test key ${n}`));
  return { secret_key: bytesToHex(secretKey), public_key: publicKeyOf(secretKey), secretKey };
}

/**
 * Signs like the library's `sign`, but with FIPS 204's deterministic ML-DSA so the vectors
 * reproduce byte for byte. Signers should keep the default, hedged variant; a verifier
 * can't tell the two apart.
 */
function sign(message: Uint8Array, secretKey: Uint8Array): Signature {
  const ed = ed25519.sign(message, secretKey.subarray(0, 32));
  const ml = ml_dsa44.sign(message, ml_dsa44.keygen(secretKey.subarray(32)).secretKey, { extraEntropy: false });
  return `${SIGNATURE_ALGORITHM}:${bytesToHex(ed)}${bytesToHex(ml)}`;
}

// --- Claim IDs ---------------------------------------------------------------------------

const INPUTS_A: Digest = `sha256:${bytesToHex(sha256(utf8ToBytes("verification inputs A")))}`;
const INPUTS_B: Digest = `sha256:${bytesToHex(sha256(utf8ToBytes("verification inputs B")))}`;
const EXTERNAL = `claim:${bytesToHex(sha256(utf8ToBytes("a claim already on the ledger")))}`;

const claim = (overrides: Partial<Claim> & Pick<Claim, "local_id">): Claim => ({
  type: "theoretical",
  core: true,
  statement: `Statement ${overrides.local_id}.`,
  evidence: [],
  depends_on: [],
  confidence: 0.5,
  ...overrides,
});

// Each case gives the declared value of every result its claims name, as results/*.json
// would hold them; a claim with evidence binds the values it names.
const claimCases: {
  name: string;
  claims: Claim[] | string;
  verification_inputs: Digest;
  results: Record<string, unknown>;
}[] = [
  {
    name: "one theoretical claim, no evidence, so the verification inputs don't matter",
    claims: [claim({ local_id: "T1", statement: "Every finite group of prime order is cyclic." })],
    verification_inputs: INPUTS_A,
    results: {},
  },
  {
    name: "an empirical claim binds the verification inputs",
    claims: [
      claim({
        local_id: "E1",
        type: "empirical",
        statement: "Method X lowers validation loss vs. baseline Y on dataset Z across 5 seeds.",
        evidence: [{ result: "R1.loss_delta", produced_by: "code/eval.py", tolerance: 0.002 }],
        falsified_if: "A re-run with 5 fresh seeds yields no significant improvement.",
        confidence: 0.8,
      }),
    ],
    verification_inputs: INPUTS_A,
    results: { "R1.loss_delta": -0.031 },
  },
  {
    name: "the same empirical claim with different verification inputs gets a different ID",
    claims: [
      claim({
        local_id: "E1",
        type: "empirical",
        statement: "Method X lowers validation loss vs. baseline Y on dataset Z across 5 seeds.",
        evidence: [{ result: "R1.loss_delta", produced_by: "code/eval.py", tolerance: 0.002 }],
        falsified_if: "A re-run with 5 fresh seeds yields no significant improvement.",
        confidence: 0.8,
      }),
    ],
    verification_inputs: INPUTS_B,
    results: { "R1.loss_delta": -0.031 },
  },
  {
    name: "the same empirical claim with a corrected result gets a different ID",
    claims: [
      claim({
        local_id: "E1",
        type: "empirical",
        statement: "Method X lowers validation loss vs. baseline Y on dataset Z across 5 seeds.",
        evidence: [{ result: "R1.loss_delta", produced_by: "code/eval.py", tolerance: 0.002 }],
        falsified_if: "A re-run with 5 fresh seeds yields no significant improvement.",
        confidence: 0.8,
      }),
    ],
    verification_inputs: INPUTS_A,
    results: { "R1.loss_delta": -0.029 },
  },
  {
    name: "local dependencies declared out of order, repeated, and mixed with a ledger ID",
    claims: [
      claim({ local_id: "C3", depends_on: ["C2", EXTERNAL, "C1", "C2"] }),
      claim({ local_id: "C1" }),
      claim({ local_id: "C2", depends_on: ["C1"] }),
    ],
    verification_inputs: INPUTS_A,
    results: {},
  },
  {
    name: "a claim without evidence inherits the inputs through an empirical dependency",
    claims: [
      claim({
        local_id: "E1",
        type: "empirical",
        evidence: [{ result: "R2.accuracy", produced_by: "code/run.py" }],
      }),
      claim({ local_id: "T1", depends_on: ["E1"] }),
    ],
    verification_inputs: INPUTS_B,
    results: { "R2.accuracy": 0.9137 },
  },
  {
    name: "non-ASCII text, quotes, and a control character in strings",
    claims: [
      claim({
        local_id: "U1",
        type: "methodological",
        statement: 'Ångström-scale "naïve" estimates in 東京 data hold\tat ≥ 2σ 😀.',
        falsified_if: "A line break\nin a falsification test.",
      }),
    ],
    verification_inputs: INPUTS_A,
    results: {},
  },
  {
    name: "two claims reading different results: correcting one result changes only its reader (first)",
    claims: [
      claim({ local_id: "A1", type: "empirical", evidence: [{ result: "R6.speedup", produced_by: "code/bench.py", tolerance: 0.05 }] }),
      claim({ local_id: "A2", type: "empirical", evidence: [{ result: "R6.memory_mb", produced_by: "code/bench.py", tolerance: 1 }] }),
    ],
    verification_inputs: INPUTS_A,
    results: { "R6.speedup": 1.84, "R6.memory_mb": 512 },
  },
  {
    name: "two claims reading different results: correcting one result changes only its reader (second)",
    claims: [
      claim({ local_id: "A1", type: "empirical", evidence: [{ result: "R6.speedup", produced_by: "code/bench.py", tolerance: 0.05 }] }),
      claim({ local_id: "A2", type: "empirical", evidence: [{ result: "R6.memory_mb", produced_by: "code/bench.py", tolerance: 1 }] }),
    ],
    verification_inputs: INPUTS_A,
    results: { "R6.speedup": 1.79, "R6.memory_mb": 512 },
  },
  {
    name: "a measurement binds the value read from its raw record",
    claims: [
      claim({
        local_id: "M1",
        type: "empirical",
        statement: "Compound K melts at 151.8 °C at atmospheric pressure.",
        evidence: [{ result: "R7.melting_point_c", measured: "data/dsc/run1.csv", tolerance: 0.5 }],
      }),
    ],
    verification_inputs: INPUTS_A,
    results: { "R7.melting_point_c": 151.8 },
  },
  {
    name: "a proof binds the verification inputs and no results",
    claims: [
      claim({
        local_id: "P1",
        statement: "Every finite group of prime order is cyclic.",
        evidence: [{ proof: "proofs/PrimeOrder.lean", theorem: "PrimeOrder.cyclic_of_prime_card", checker: "lean4" }],
      }),
    ],
    verification_inputs: INPUTS_B,
    results: {},
  },
  {
    name: "results that aren't numbers, and one result named twice, which binds once",
    claims: [
      claim({
        local_id: "V1",
        type: "empirical",
        evidence: [
          { result: "R8.series.2", produced_by: "code/run.py" },
          { result: "R8.meta", produced_by: "code/run.py" },
          { result: "R8.label", measured: "data/notes.txt" },
          { result: "R8.none", produced_by: "code/run.py" },
          { result: "R8.series.2", produced_by: "code/other.py" },
        ],
      }),
    ],
    verification_inputs: INPUTS_A,
    results: { "R8.series.2": 0.25, "R8.meta": { runs: [1, 2.5], ok: true }, "R8.label": "Ångström", "R8.none": null },
  },
];

// These claims.json files are written the way Python's json.dumps writes floats, which is
// where hand-rolled serializers most often part ways with RFC 8785.
const pythonWritten = (claim: string) =>
  `[{"local_id": ${claim}, "core": true, "depends_on": [], "falsified_if": "The listed result is not reproduced."}]`;
claimCases.push(
  {
    name: "whole-number floats, as Python writes them",
    claims: pythonWritten(
      `"N1", "type": "negative_result", "statement": "Treatment T has no effect on outcome O.", "evidence": [{"result": "R3.effect", "produced_by": "code/run.py", "tolerance": 0.0}], "confidence": 1.0`,
    ),
    verification_inputs: INPUTS_A,
    results: { "R3.effect": 1 },
  },
  {
    name: "very small numbers, as Python writes them",
    claims: pythonWritten(
      `"N2", "type": "empirical", "statement": "Estimator E converges at the predicted rate.", "evidence": [{"result": "R4.a", "produced_by": "code/run.py", "tolerance": 1e-07}, {"result": "R4.b", "produced_by": "code/run.py", "tolerance": 1e-05}, {"result": "R4.c", "produced_by": "code/run.py", "tolerance": 1.5e-10}, {"result": "R4.d", "produced_by": "code/run.py", "tolerance": 5e-324}], "confidence": 0.0001`,
    ),
    verification_inputs: INPUTS_A,
    results: { "R4.a": 1e-7, "R4.b": 0.00001, "R4.c": 1.5e-10, "R4.d": 5e-324 },
  },
  {
    name: "very large numbers and binary-fraction artifacts, as Python writes them",
    claims: pythonWritten(
      `"N3", "type": "empirical", "statement": "Simulation S conserves energy to the stated tolerance.", "evidence": [{"result": "R5.a", "produced_by": "code/run.py", "tolerance": 1e+16}, {"result": "R5.b", "produced_by": "code/run.py", "tolerance": 1e+21}, {"result": "R5.c", "produced_by": "code/run.py", "tolerance": 123456789.125}], "confidence": 0.30000000000000004`,
    ),
    verification_inputs: INPUTS_A,
    results: { "R5.a": 1e16, "R5.b": 1e21, "R5.c": 0.30000000000000004 },
  },
);

const valid = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify([{ ...claim({ local_id: "C1" }), ...overrides }]);
const invalidClaims = [
  {
    name: "a duplicate property name, which parsers resolve differently",
    claims_json: valid().replace('"confidence":0.5', '"confidence":0.1,"confidence":0.5'),
  },
  { name: "a lone surrogate in a string", claims_json: valid({ statement: "Broken \\ud800 text." }).replace("\\\\ud800", "\\ud800") },
  { name: "a number outside binary64", claims_json: valid().replace('"confidence":0.5', '"confidence":1e400') },
  { name: "a field the schema doesn't define", claims_json: valid({ priority: "high" }) },
  { name: "an empirical claim without evidence", claims_json: valid({ type: "empirical" }) },
  { name: "a confidence above 1", claims_json: valid({ confidence: 1.5 }) },
  {
    name: "a dependency cycle",
    claims_json: JSON.stringify([claim({ local_id: "C1", depends_on: ["C2"] }), claim({ local_id: "C2", depends_on: ["C1"] })]),
  },
  { name: "an unknown local dependency", claims_json: JSON.stringify([claim({ local_id: "C1", depends_on: ["C9"] })]) },
  {
    name: "a duplicate local ID",
    claims_json: JSON.stringify([claim({ local_id: "C1" }), claim({ local_id: "C1", statement: "Another." })]),
  },
  { name: "a malformed global ID", claims_json: JSON.stringify([claim({ local_id: "C1", depends_on: ["claim:7f3a"] })]) },
  // Found by the independent verification of v2: shapes a validator must check, not assume.
  { name: "evidence given as an object", claims_json: valid({ evidence: {} }) },
  { name: "evidence given as a string", claims_json: valid({ evidence: "" }) },
  { name: "depends_on given as an object", claims_json: valid({ depends_on: {} }) },
  { name: "depends_on given as a string", claims_json: valid({ depends_on: "" }) },
  {
    name: "evidence fields of the wrong type",
    claims_json: valid({ type: "empirical", evidence: [{ result: 7, produced_by: false }] }),
  },
  {
    name: "empty evidence strings",
    claims_json: valid({ type: "empirical", evidence: [{ result: "", produced_by: "" }] }),
  },
  { name: "a local ID ending in a newline", claims_json: valid({ local_id: "C1\n" }) },
  {
    name: "an evidence item that is two kinds at once",
    claims_json: valid({ type: "empirical", evidence: [{ result: "R1.x", produced_by: "code/run.py", measured: "data/x.csv" }] }),
  },
  {
    name: "a computation outside code/",
    claims_json: valid({ type: "empirical", evidence: [{ result: "R1.x", produced_by: "run.py" }] }),
  },
  {
    name: "a measurement outside data/",
    claims_json: valid({ type: "empirical", evidence: [{ result: "R1.x", measured: "results/R1.json" }] }),
  },
  {
    name: "a proof with a checker the protocol doesn't name",
    claims_json: valid({ evidence: [{ proof: "proofs/A.thy", theorem: "A.t", checker: "isabelle" }] }),
  },
  {
    name: "a result name with no key",
    claims_json: valid({ type: "empirical", evidence: [{ result: "R1", produced_by: "code/run.py" }] }),
  },
  {
    name: "an integer outside binary64",
    claims_json: valid({
      type: "empirical",
      evidence: [{ result: "R1.x", produced_by: "code/run.py", tolerance: 1 }],
    }).replace('"tolerance":1', `"tolerance":1${"0".repeat(400)}`),
  },
];
for (const { name, claims_json } of invalidClaims) {
  mustReject(name, () => ClaimsFileSchema.safeParse(parseJson(claims_json)).success);
}

// Valid claims whose bundle doesn't declare a result they name: no ID can be computed.
const unresolved = [
  {
    name: "a result the bundle doesn't declare",
    claims_json: valid({ type: "empirical", evidence: [{ result: "R1.x", produced_by: "code/run.py" }] }),
    verification_inputs: INPUTS_A,
    results: { "R1.y": 1 },
  },
];
for (const { name, claims_json, verification_inputs, results } of unresolved) {
  mustReject(name, () => {
    assignClaimIds(ClaimsFileSchema.parse(parseJson(claims_json)), declaredInputs(verification_inputs, results));
    return true;
  });
}

write("claim-id-vectors.json", {
  description:
    "For each case, the exact text of a claims.json file, the bundle's verification inputs, the declared value of each result its claims name, and the claim ID of every claim in it. A claim with evidence binds the verification inputs and, when its evidence names results, a results object mapping each name to its value. Every file under invalid must be rejected, and every case under unresolved must fail because a named result isn't declared.",
  invalid: invalidClaims,
  unresolved,
  cases: claimCases.map(({ name, claims, verification_inputs, results }) => {
    const claimsJson = typeof claims === "string" ? claims : JSON.stringify(claims);
    const parsed = ClaimsFileSchema.parse(JSON.parse(claimsJson));
    const ids = assignClaimIds(parsed, declaredInputs(verification_inputs, results));
    return {
      name,
      claims_json: claimsJson,
      verification_inputs,
      results,
      expected: Object.fromEntries(parsed.map((c) => [c.local_id, ids.get(c.local_id)])),
    };
  }),
});

// --- Bundles -----------------------------------------------------------------------------

const bytes = (text: string) => utf8ToBytes(text);
const bundleCases: { name: string; files: Map<string, Uint8Array> }[] = [
  {
    name: "a minimal bundle with no verification inputs",
    files: new Map([
      ["manifest.json", bytes('{"fields":["mathematics"]}')],
      ["paper.md", bytes("# Summary\n")],
      ["claims.json", bytes("[]")],
    ]),
  },
  {
    name: "nested directories, an empty file, binary content, and a non-ASCII NFC path",
    files: new Map([
      ["paper.md", bytes("# Summary\n\nResults follow.\n")],
      ["code/eval.py", bytes("print(-0.031)\n")],
      ["code/lib/__init__.py", new Uint8Array()],
      ["data/raw/séance.csv", bytes("a,b\n1,2\n")],
      ["data/blob.bin", Uint8Array.from({ length: 256 }, (_, i) => i)],
      ["results/R1.json", bytes('{"loss_delta":-0.031}')],
      ["env/requirements.txt", bytes("numpy==2.3.0\n")],
      ["proofs/Main.lean", bytes("theorem t : 1 + 1 = 2 := rfl\n")],
    ]),
  },
  {
    name: "the signature file is left out of the bundle hash but has a file digest",
    files: new Map([
      ["paper.md", bytes("# Summary\n\nResults follow.\n")],
      ["code/eval.py", bytes("print(-0.031)\n")],
      ["signature", bytes(`${SIGNATURE_ALGORITHM}:00`)],
    ]),
  },
];

bundleCases.push({
  name: "paths whose UTF-16 order differs from their code-point order",
  files: new Map([
    ["paper.md", bytes("# Summary\n")],
    ["data/\uE000.txt", bytes("private use\n")],
    ["data/😀.txt", bytes("outside the BMP\n")],
  ]),
});
const invalidPaths = [
  { name: "a parent segment", paths: ["code/../paper.md"] },
  { name: "an absolute path", paths: ["/paper.md"] },
  { name: "an empty segment", paths: ["code//run.py"] },
  { name: "a backslash", paths: ["code\\run.py"] },
  { name: "a path that isn't Unicode NFC", paths: ["data/e\u0301.csv"] },
  { name: "a file outside the layout", paths: ["notes.txt"] },
  { name: "paths that differ only in case", paths: ["code/Run.py", "code/run.py"] },
  { name: "a path that is both a file and a directory", paths: ["code/run", "code/run/main.py"] },
  { name: "a control character", paths: ["code/run\u0007.py"] },
  { name: "the DEL character", paths: ["code/run\u007f.py"] },
];
for (const { name, paths } of invalidPaths) {
  mustReject(name, () => (digestBundle(new Map(paths.map((path) => [path, bytes("x")]))), true));
}

write("bundle-vectors.json", {
  description:
    "For each case, the files (base64) and their digests: per file, the bundle hash (every file but signature), and the verification inputs (every file under code/, env/, data/, proofs/; declared results under results/ are bound claim by claim instead). Every path set under invalid must be rejected.",
  invalid: invalidPaths,
  cases: bundleCases.map(({ name, files }) => {
    const digests = digestBundle(files);
    return {
      name,
      files: Object.fromEntries([...files].map(([path, b]) => [path, Buffer.from(b).toString("base64")])),
      expected: {
        files: digests.files,
        bundle: digests.bundle,
        verification_inputs: digests.verificationInputs,
      },
    };
  }),
});

// --- The log -----------------------------------------------------------------------------

const MAX_SIZE = 32;
// The first eight leaves are the Certificate Transparency reference leaves.
const CT_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"];
const leafInputs = Array.from({ length: MAX_SIZE }, (_, i) =>
  i < CT_LEAVES.length ? CT_LEAVES[i] : bytesToHex(utf8ToBytes(`sciencejournal conformance leaf ${i}`)),
);
const source = memorySource(leafInputs.map((hex) => leafHash(Buffer.from(hex, "hex"))));
const hex = (list: Uint8Array[]) => list.map(bytesToHex);

const operatorKey = testKey(1);
const keyEntry = {
  type: "key" as const,
  key: operatorKey.public_key as PublicKey,
  name: "Conformance test operator",
  model_families: ["test-family"],
};
const exampleLeaves: SignedLeaf[] = [
  {
    timestamp: "2026-10-02T12:00:00.000Z",
    operator: "op:1",
    entry: { ...keyEntry, sig: sign(signingPayload(keyEntry), operatorKey.secretKey) },
  },
  {
    timestamp: "2026-10-02T12:00:01.000Z",
    operator: "op:1",
    entry: {
      ...bundleSigningObject(INPUTS_A),
      sig: sign(signingPayload(bundleSigningObject(INPUTS_A)), operatorKey.secretKey),
    },
    claims: [EXTERNAL as `claim:${string}`],
    fields: ["mathematics"],
  },
];

async function main() {
const trees = [];
const inclusion = [];
const consistency = [];
for (let size = 1; size <= MAX_SIZE; size++) {
  trees.push({ size, root: bytesToHex(await rootHash(source, size)) });
  for (let index = 0; index < size; index++) {
    inclusion.push({ index, size, proof: hex(await inclusionProof(source, index, size)) });
  }
}
for (let second = 1; second <= MAX_SIZE; second++) {
  for (let first = 1; first <= second; first++) {
    consistency.push({ first, second, proof: hex(await consistencyProof(source, first, second)) });
  }
}

const leafAt = (i: number) => bytesToHex(leafHash(Buffer.from(leafInputs[i], "hex")));
const proofOf = async (index: number, size: number) => hex(await inclusionProof(source, index, size));
const rootOf = async (size: number) => bytesToHex(await rootHash(source, size));
const flip = (h: string) => (h[0] === "0" ? "1" : "0") + h.slice(1);
const invalidInclusion = [
  { name: "an index equal to the tree size", index: 5, size: 5, leaf_hash: leafAt(4), proof: await proofOf(4, 5), root: await rootOf(5) },
  { name: "a negative index", index: -1, size: 1, leaf_hash: leafAt(0), proof: [], root: await rootOf(1) },
  { name: "a truncated path", index: 5, size: 13, leaf_hash: leafAt(5), proof: (await proofOf(5, 13)).slice(1), root: await rootOf(13) },
  { name: "an extended path", index: 5, size: 13, leaf_hash: leafAt(5), proof: [...(await proofOf(5, 13)), leafAt(0)], root: await rootOf(13) },
  { name: "a tampered sibling", index: 5, size: 13, leaf_hash: leafAt(5), proof: (await proofOf(5, 13)).map((h, i) => (i === 1 ? flip(h) : h)), root: await rootOf(13) },
  { name: "the wrong leaf", index: 5, size: 13, leaf_hash: leafAt(6), proof: await proofOf(5, 13), root: await rootOf(13) },
  { name: "another tree's root", index: 5, size: 13, leaf_hash: leafAt(5), proof: await proofOf(5, 13), root: await rootOf(12) },
  { name: "a fractional index", index: 0.5, size: 1, leaf_hash: leafAt(0), proof: [], root: await rootOf(1) },
  { name: "hashes that aren't 32 bytes", index: 0, size: 1, leaf_hash: "", proof: [], root: "" },
];
const invalidConsistency = [
  { name: "an empty proof for a growing tree", first: 3, second: 4, first_root: await rootOf(3), second_root: await rootOf(4), proof: [] },
  { name: "empty trees whose roots aren't the empty root", first: 0, second: 0, first_root: leafAt(0), second_root: leafAt(0), proof: [] },
  { name: "equal sizes with different roots", first: 7, second: 7, first_root: await rootOf(7), second_root: await rootOf(8), proof: [] },
  { name: "a shrinking tree", first: 8, second: 7, first_root: await rootOf(8), second_root: await rootOf(7), proof: hex(await consistencyProof(source, 7, 8)) },
  { name: "swapped roots", first: 6, second: 20, first_root: await rootOf(20), second_root: await rootOf(6), proof: hex(await consistencyProof(source, 6, 20)) },
  { name: "a tampered proof", first: 6, second: 20, first_root: await rootOf(6), second_root: await rootOf(20), proof: hex(await consistencyProof(source, 6, 20)).map((h, i) => (i === 0 ? flip(h) : h)) },
  { name: "a fractional size", first: 1, second: 1.5, first_root: await rootOf(1), second_root: await rootOf(1), proof: [] },
  { name: "hashes that aren't 32 bytes", first: 1, second: 1, first_root: "", second_root: "", proof: [] },
];
const bytesOf = (list: string[]) => list.map((h) => Buffer.from(h, "hex"));
for (const c of invalidInclusion) {
  mustReject(c.name, () => verifyInclusion(c.index, c.size, Buffer.from(c.leaf_hash, "hex"), bytesOf(c.proof), Buffer.from(c.root, "hex")));
}
for (const c of invalidConsistency) {
  mustReject(c.name, () =>
    verifyConsistency(c.first, c.second, Buffer.from(c.first_root, "hex"), Buffer.from(c.second_root, "hex"), bytesOf(c.proof)),
  );
}

write("log-vectors.json", {
  description:
    "RFC 9162 Merkle trees over the listed leaf inputs (hex): the empty-tree root, the root of every tree size, an inclusion proof for every leaf in every tree, a consistency proof between every pair of sizes, and two example log leaves: each entry as signed, the leaf the log holds, in which each signature field (sig, and a key rotation's key_sig) is replaced by the SHA-256 of the signature's canonical JSON, and the leaf's hash (its canonical JSON, prefixed with 0x00). Every proof under invalid_inclusion and invalid_consistency must fail verification.",
  empty_root: bytesToHex(EMPTY_ROOT),
  invalid_inclusion: invalidInclusion,
  invalid_consistency: invalidConsistency,
  leaves: leafInputs,
  trees,
  inclusion,
  consistency,
  leaf_examples: exampleLeaves.map((signedLeaf) => {
    const leaf = detachLeaf(signedLeaf);
    return { signed_entry: signedLeaf.entry, leaf, leaf_hash: bytesToHex(leafHash(leafBytes(leaf))) };
  }),
});

// --- Signatures --------------------------------------------------------------------------

const signatureCases = [
  {
    name: "a key entry",
    key: testKey(1),
    object: {
      type: "key",
      key: testKey(1).public_key,
      name: "Conformance test operator",
      model_families: ["test-family", "another-family"],
    },
  },
  { name: "a bundle signing object", key: testKey(2), object: bundleSigningObject(INPUTS_B) },
  {
    name: "a tree head",
    key: testKey(3),
    object: {
      type: "tree_head",
      log: "log:0000000000000000000000000000000000000000000000000000000000000000",
      size: 32,
      root: trees[31].root,
      timestamp: "2026-10-02T12:00:00.000Z",
    },
  },
  {
    name: "non-ASCII text in a signed field",
    key: testKey(4),
    object: { type: "key", key: testKey(4).public_key, name: "Équipe 東京 ✓", model_families: ["x"] },
  },
];

const signed = signatureCases.map(({ key, object }) => ({ key, object, sig: sign(signingPayload(object), key.secretKey) }));
const prefix = SIGNATURE_ALGORITHM.length + 1;
const flipSig = (sig: string) => `${sig.slice(0, prefix)}${flip(sig.slice(prefix))}`;
// Each half has to verify: flip a byte of the ML-DSA half alone, or the Ed25519 half alone.
const flipMlDsa = (sig: string) => {
  const at = prefix + 2 * 64;
  return `${sig.slice(0, at)}${flip(sig.slice(at))}`;
};
const invalidSignatures = [
  { name: "a tampered Ed25519 half", public_key: signed[0].key.public_key, object: signed[0].object, sig: flipSig(signed[0].sig) },
  { name: "a tampered ML-DSA-44 half", public_key: signed[0].key.public_key, object: signed[0].object, sig: flipMlDsa(signed[0].sig) },
  {
    name: "one key's Ed25519 half with another's ML-DSA-44 half",
    public_key: `${signed[0].key.public_key.slice(0, prefix + 64)}${signed[1].key.public_key.slice(prefix + 64)}`,
    object: signed[0].object,
    sig: signed[0].sig,
  },
  {
    name: "an Ed25519 signature alone",
    public_key: signed[0].key.public_key,
    object: signed[0].object,
    sig: `ed25519:${signed[0].sig.slice(prefix, prefix + 128)}`,
  },
  { name: "another key", public_key: signed[1].key.public_key, object: signed[0].object, sig: signed[0].sig },
  { name: "a changed field", public_key: signed[0].key.public_key, object: { ...signed[0].object, name: "Someone else" }, sig: signed[0].sig },
  { name: "a signature for another object type", public_key: signed[1].key.public_key, object: { ...signed[1].object, type: "key" }, sig: signed[1].sig },
];
for (const c of invalidSignatures) mustReject(c.name, () => verify(c.sig, signingPayload(c.object), c.public_key));

write("signature-vectors.json", {
  description:
    `Hybrid ${SIGNATURE_ALGORITHM} signatures over canonical JSON without the sig field. A public key is "${SIGNATURE_ALGORITHM}:" and, in hex, the 32-byte Ed25519 key (RFC 8032) followed by the 1,312-byte ML-DSA-44 key (FIPS 204); a signature is the 64-byte Ed25519 signature followed by the 2,420-byte ML-DSA-44 signature, both over the same payload, with an empty ML-DSA context. It verifies only if both halves do. A secret key is the 32-byte Ed25519 seed followed by the 32-byte ML-DSA-44 seed. The secret keys are test keys published only for these vectors. Ed25519 signatures are deterministic, and these ML-DSA signatures use the deterministic variant so the file reproduces byte for byte; real signers use the hedged default, which verifies the same way. key_digest is the SHA-256 of the public key as written, which manifests, tasks, and DNS records name keys by; sig_digest is the SHA-256 of the signature's canonical JSON (the quoted string), which a log leaf holds in place of the signature. Every case under invalid must fail verification.`,
  invalid: invalidSignatures,
  cases: signatureCases.map(({ name, key, object }) => ({
    name,
    secret_key: key.secret_key,
    public_key: key.public_key,
    key_digest: keyDigest(key.public_key),
    object,
    payload: canonicalJson(object),
    sig: sign(signingPayload(object), key.secretKey),
    sig_digest: signatureDigest(sign(signingPayload(object), key.secretKey)),
  })),
});

console.log("Wrote vectors to", data);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
