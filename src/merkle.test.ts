import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  completedSubtrees,
  consistencyProof,
  EMPTY_ROOT,
  extendRange,
  inclusionProof,
  leafHash,
  memorySource,
  rangeRoot,
  rootHash,
  verifyConsistency,
  verifyInclusion,
} from "./merkle";

// Leaves and roots from the Certificate Transparency reference test data
// (transparency-dev/merkle, testonly).
const VECTOR_LEAVES = [
  "",
  "00",
  "10",
  "2021",
  "3031",
  "40414243",
  "5051525354555657",
  "606162636465666768696a6b6c6d6e6f",
].map(hexToBytes);
const VECTOR_ROOTS = [
  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

const leaves = (count: number) =>
  Array.from({ length: count }, (_, i) => leafHash(new TextEncoder().encode(`leaf ${i}`)));

describe("rootHash", () => {
  it("matches the Certificate Transparency test vectors", async () => {
    const source = memorySource(VECTOR_LEAVES.map(leafHash));
    for (let size = 1; size <= VECTOR_ROOTS.length; size++) {
      expect(bytesToHex(await rootHash(source, size))).toBe(VECTOR_ROOTS[size - 1]);
    }
  });

  it("is the hash of the empty string for an empty tree", async () => {
    expect(bytesToHex(await rootHash(memorySource([]), 0))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(EMPTY_ROOT).toEqual(await rootHash(memorySource([]), 0));
  });
});

describe("proofs", () => {
  const all = leaves(70);
  const source = memorySource(all);

  it("verify inclusion for every leaf in every tree size up to 70", async () => {
    for (let size = 1; size <= all.length; size++) {
      const root = await rootHash(source, size);
      for (let index = 0; index < size; index++) {
        const proof = await inclusionProof(source, index, size);
        expect(verifyInclusion(index, size, all[index], proof, root)).toBe(true);
      }
    }
  });

  it("verify consistency between every pair of tree sizes up to 70", async () => {
    const roots: Uint8Array[] = [EMPTY_ROOT];
    for (let size = 1; size <= all.length; size++) roots.push(await rootHash(source, size));
    for (let second = 0; second <= all.length; second++) {
      for (let first = 0; first <= second; first++) {
        const proof = await consistencyProof(source, first, second);
        expect(verifyConsistency(first, second, roots[first], roots[second], proof)).toBe(true);
      }
    }
  });

  it("reject the wrong leaf, index, size, root, or a tampered path", async () => {
    const size = 13;
    const root = await rootHash(source, size);
    const proof = await inclusionProof(source, 5, size);
    const tampered = proof.map((hash, i) => (i === 1 ? leafHash(hash) : hash));

    expect(verifyInclusion(5, size, all[6], proof, root)).toBe(false);
    expect(verifyInclusion(6, size, all[5], proof, root)).toBe(false);
    // A size is always checked together with the signed root for that size.
    const nextRoot = await rootHash(source, size + 1);
    expect(verifyInclusion(5, size + 1, all[5], proof, nextRoot)).toBe(false);
    expect(verifyInclusion(5, size, all[5], proof, await rootHash(source, 12))).toBe(false);
    expect(verifyInclusion(5, size, all[5], tampered, root)).toBe(false);
    expect(verifyInclusion(5, size, all[5], proof.slice(1), root)).toBe(false);
  });

  it("reject a consistency proof against a rewritten history", async () => {
    const rewritten = memorySource([...all.slice(0, 3), leafHash(Uint8Array.of(9)), ...all.slice(4)]);
    const proof = await consistencyProof(rewritten, 6, 20);
    const honestRoot = await rootHash(source, 6);
    const rewrittenRoot = await rootHash(rewritten, 20);
    expect(verifyConsistency(6, 20, honestRoot, rewrittenRoot, proof)).toBe(false);
  });

  it("reject boundary cases RFC 9162 leaves to the implementer", () => {
    const root = leafHash(Uint8Array.of(0));
    expect(verifyInclusion(1, 1, root, [], root)).toBe(false);
    expect(verifyInclusion(-1, 1, root, [], root)).toBe(false);
    expect(verifyConsistency(0, 0, root, root, [])).toBe(false);
    expect(verifyConsistency(0, 0, EMPTY_ROOT, EMPTY_ROOT, [])).toBe(true);
    expect(verifyConsistency(3, 4, root, root, [])).toBe(false);
  });

  it("reject non-integer positions and hashes that aren't 32 bytes", () => {
    const root = leafHash(new Uint8Array());
    expect(verifyInclusion(0, 1, root, [], root)).toBe(true);
    expect(verifyInclusion(0.5, 1, root, [], root)).toBe(false);
    expect(verifyInclusion(0, 1.5, root, [], root)).toBe(false);
    expect(verifyInclusion(0, 1, new Uint8Array(), [], new Uint8Array())).toBe(false);
    expect(verifyConsistency(1, 1, new Uint8Array(), new Uint8Array(), [])).toBe(false);
    expect(verifyConsistency(1, 1.5, root, root, [])).toBe(false);
  });

  it("refuse out-of-range requests", async () => {
    await expect(inclusionProof(source, 5, 5)).rejects.toThrow(RangeError);
    await expect(consistencyProof(source, 6, 5)).rejects.toThrow(RangeError);
  });
});

describe("completedSubtrees", () => {
  it("lists the perfect subtrees each append completes", () => {
    expect(completedSubtrees(0)).toEqual([]);
    expect(completedSubtrees(1)).toEqual([[1, 0]]);
    expect(completedSubtrees(2)).toEqual([]);
    expect(completedSubtrees(3)).toEqual([
      [1, 1],
      [2, 0],
    ]);
    expect(completedSubtrees(7)).toEqual([
      [1, 3],
      [2, 1],
      [3, 0],
    ]);
  });
});

describe("compact ranges", () => {
  it("extend one leaf at a time to every tree's root, matching the Certificate Transparency vectors", async () => {
    const range: Uint8Array[] = [];
    expect(rangeRoot(range)).toEqual(EMPTY_ROOT);
    VECTOR_LEAVES.forEach((leaf, size) => {
      extendRange(range, size, leafHash(leaf));
      expect(bytesToHex(rangeRoot(range))).toBe(VECTOR_ROOTS[size]);
    });
  });

  it("hold one subtree for each bit of the size, and agree with rootHash up to 70 leaves", async () => {
    const all = leaves(70);
    const source = memorySource(all);
    const range: Uint8Array[] = [];
    for (let size = 0; size < all.length; size++) {
      extendRange(range, size, all[size]);
      expect(range.length).toBe((size + 1).toString(2).replaceAll("0", "").length);
      expect(rangeRoot(range)).toEqual(await rootHash(source, size + 1));
    }
  });

  it("refuse a range that doesn't cover the size it is extended at", () => {
    expect(() => extendRange([], 1, leafHash(Uint8Array.of(1)))).toThrow(RangeError);
  });
});
