import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { digestBundle } from "./bundle";
import { bundleSigningObject, signObject, verifyObject } from "./entries";
import { leafBytes, type LogLeaf } from "./leaves";
import { inclusionProof, leafHash, memorySource, rootHash } from "./merkle";
import { signBundle, verifyReceipt, type Receipt } from "./receipts";
import { generateKeyPair } from "./signing";

const operator = generateKeyPair();
const log = generateKeyPair();

describe("signBundle", () => {
  it("adds a signature over the bundle hash, replacing any old one", () => {
    const files = new Map([
      ["paper.md", utf8ToBytes("# Summary")],
      ["signature", utf8ToBytes("stale")],
    ]);
    const signed = signBundle(files, operator.secretKey);
    const sig = new TextDecoder().decode(signed.get("signature"));
    const { bundle } = digestBundle(files);
    expect(verifyObject({ ...bundleSigningObject(bundle), sig }, operator.publicKey)).toBe(true);
    expect(digestBundle(signed).bundle).toBe(bundle);
  });
});

describe("verifyReceipt", () => {
  async function receiptFor(index: number, size: number): Promise<Receipt> {
    const leaves: LogLeaf[] = Array.from({ length: size }, (_, i) => ({
      timestamp: new Date(Date.UTC(2026, 9, 2, 12, 0, i)).toISOString(),
      operator: "op:1",
      entry: signObject(
        { type: "bundle" as const, bundle: `sha256:${String(i).padStart(64, "0")}` as const },
        operator.secretKey,
      ),
      claims: [],
      fields: ["machine-learning"],
    }));
    const source = memorySource(leaves.map((leaf) => leafHash(leafBytes(leaf))));
    const treeHead = signObject(
      {
        type: "tree_head" as const,
        log: "log:test",
        size,
        root: bytesToHex(await rootHash(source, size)),
        timestamp: leaves[size - 1].timestamp,
      },
      log.secretKey,
    );
    return {
      log: "log:test",
      index,
      leaf: leaves[index],
      leaf_hash: bytesToHex(leafHash(leafBytes(leaves[index]))),
      tree_head: treeHead,
      inclusion_proof: (await inclusionProof(source, index, size)).map(bytesToHex),
    };
  }

  it("accepts a genuine receipt", async () => {
    expect(verifyReceipt(await receiptFor(3, 7), log.publicKey)).toBe(true);
  });

  it("rejects an altered leaf, a forged tree head, or another log's key", async () => {
    const receipt = await receiptFor(3, 7);
    const backdated = { ...receipt, leaf: { ...receipt.leaf, timestamp: "2020-01-01T00:00:00.000Z" } };
    const forgedHead = { ...receipt, tree_head: { ...receipt.tree_head, size: 8 } };
    expect(verifyReceipt(backdated, log.publicKey)).toBe(false);
    expect(verifyReceipt(forgedHead, log.publicKey)).toBe(false);
    expect(verifyReceipt(receipt, operator.publicKey)).toBe(false);
    expect(verifyReceipt({ ...receipt, inclusion_proof: ["zz"] }, log.publicKey)).toBe(false);
  });
});
