import { sha256 } from "@noble/hashes/sha2.js";

// Merkle tree hashing and proofs from RFC 9162 (Certificate Transparency 2.0), section 2.1.
// Leaves and interior nodes are domain-separated so a leaf can never pose as a node.

const LEAF_PREFIX = Uint8Array.of(0);
const NODE_PREFIX = Uint8Array.of(1);

export function leafHash(leaf: Uint8Array): Uint8Array {
  return sha256(concat(LEAF_PREFIX, leaf));
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concat(NODE_PREFIX, left, right));
}

/** The root of an empty tree: the hash of the empty string. */
export const EMPTY_ROOT = sha256(new Uint8Array());

/**
 * Where proof generation reads subtree hashes from. Every range the RFC algorithms need
 * decomposes into perfect subtrees, so a log only has to store those as they complete.
 */
export interface SubtreeSource {
  /** The hash of leaves [index * 2^level, (index + 1) * 2^level). */
  node(level: number, index: number): Promise<Uint8Array>;
}

/** Subtree hashes computed from a list of leaf hashes, for tests and small trees. */
export function memorySource(leafHashes: readonly Uint8Array[]): SubtreeSource {
  const node = (level: number, index: number): Uint8Array => {
    if (level === 0) {
      const leaf = leafHashes[index];
      if (!leaf) throw new RangeError(`No leaf ${index}`);
      return leaf;
    }
    return nodeHash(node(level - 1, 2 * index), node(level - 1, 2 * index + 1));
  };
  return { node: async (level, index) => node(level, index) };
}

/** The Merkle Tree Hash of the first `size` leaves. */
export async function rootHash(source: SubtreeSource, size: number): Promise<Uint8Array> {
  return size === 0 ? EMPTY_ROOT : rangeHash(source, 0, size);
}

/** The audit path proving leaf `index` is in the tree of the first `size` leaves. */
export async function inclusionProof(
  source: SubtreeSource,
  index: number,
  size: number,
): Promise<Uint8Array[]> {
  if (!(index >= 0 && index < size)) throw new RangeError(`Leaf ${index} is not in a tree of ${size}`);
  const path = async (index: number, start: number, end: number): Promise<Uint8Array[]> => {
    if (end - start === 1) return [];
    const k = split(end - start);
    return index < k
      ? [...(await path(index, start, start + k)), await rangeHash(source, start + k, end)]
      : [...(await path(index - k, start + k, end)), await rangeHash(source, start, start + k)];
  };
  return path(index, 0, size);
}

/** The proof that the tree of the first `first` leaves is a prefix of the tree of `second`. */
export async function consistencyProof(
  source: SubtreeSource,
  first: number,
  second: number,
): Promise<Uint8Array[]> {
  if (!(first >= 0 && first <= second)) throw new RangeError(`Bad tree sizes ${first}, ${second}`);
  if (first === 0 || first === second) return [];
  const subproof = async (
    m: number,
    start: number,
    end: number,
    complete: boolean,
  ): Promise<Uint8Array[]> => {
    if (m === end - start) return complete ? [] : [await rangeHash(source, start, end)];
    const k = split(end - start);
    return m <= k
      ? [...(await subproof(m, start, start + k, complete)), await rangeHash(source, start + k, end)]
      : [...(await subproof(m - k, start + k, end, false)), await rangeHash(source, start, start + k)];
  };
  return subproof(first, 0, second, true);
}

/** RFC 9162 section 2.1.3.2. Rejects non-integer positions and hashes that aren't 32 bytes. */
export function verifyInclusion(
  index: number,
  size: number,
  leaf: Uint8Array,
  proof: readonly Uint8Array[],
  root: Uint8Array,
): boolean {
  if (!isPosition(index) || !isPosition(size) || index >= size) return false;
  if (![leaf, root, ...proof].every(isHash)) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && equal(r, root);
}

/** RFC 9162 section 2.1.4.2, extended to accept the trivial cases of an empty or equal tree. */
export function verifyConsistency(
  first: number,
  second: number,
  firstRoot: Uint8Array,
  secondRoot: Uint8Array,
  proof: readonly Uint8Array[],
): boolean {
  if (!isPosition(first) || !isPosition(second) || first > second) return false;
  if (![firstRoot, secondRoot, ...proof].every(isHash)) return false;
  if (second === 0) return proof.length === 0 && equal(firstRoot, EMPTY_ROOT) && equal(secondRoot, EMPTY_ROOT);
  if (first === second) return proof.length === 0 && equal(firstRoot, secondRoot);
  if (first === 0) return proof.length === 0 && equal(firstRoot, EMPTY_ROOT);
  if (proof.length === 0) return false;

  const path = isPowerOfTwo(first) ? [firstRoot, ...proof] : [...proof];
  let fn = first - 1;
  let sn = second - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && equal(fr, firstRoot) && equal(sr, secondRoot);
}

/**
 * Adds a leaf to a compact range: the roots of the perfect subtrees that cover the first
 * `size` leaves, largest first, one for each bit set in `size`. A range is all a reader
 * needs to extend the tree one leaf at a time and compute its root, so a monitor can check
 * every leaf against a signed tree head without keeping the leaves.
 */
export function extendRange(range: Uint8Array[], size: number, leaf: Uint8Array): void {
  if (range.length !== bitCount(size)) throw new RangeError(`A range over ${size} leaves has ${bitCount(size)} hashes`);
  let node = leaf;
  // Each trailing one bit of the old size is a subtree as large as everything after it, so it merges.
  for (let rest = size; rest % 2 === 1; rest = Math.floor(rest / 2)) node = nodeHash(range.pop()!, node);
  range.push(node);
}

/** The Merkle Tree Hash of the leaves a compact range covers. */
export function rangeRoot(range: readonly Uint8Array[]): Uint8Array {
  if (range.length === 0) return EMPTY_ROOT;
  return range.slice(0, -1).reduceRight((right, left) => nodeHash(left, right), range[range.length - 1]);
}

/** The perfect subtrees a log stores once leaf `index` is appended: [level, index] pairs. */
export function completedSubtrees(index: number): [level: number, index: number][] {
  const completed: [number, number][] = [];
  for (let level = 1, width = 2; (index + 1) % width === 0; level++, width *= 2) {
    completed.push([level, (index + 1) / width - 1]);
  }
  return completed;
}

// Every range reached from the RFC recursions is either a perfect, aligned subtree or splits
// into one followed by a smaller range, so this only ever asks the source for stored nodes.
async function rangeHash(source: SubtreeSource, start: number, end: number): Promise<Uint8Array> {
  const size = end - start;
  if (isPowerOfTwo(size) && start % size === 0) return source.node(Math.log2(size), start / size);
  const k = split(size);
  return nodeHash(await rangeHash(source, start, start + k), await rangeHash(source, start + k, end));
}

function isPosition(n: number): boolean {
  return Number.isSafeInteger(n) && n >= 0;
}

function isHash(bytes: Uint8Array): boolean {
  return bytes.length === 32;
}

/** The largest power of two smaller than n, for n > 1. */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function isPowerOfTwo(n: number): boolean {
  return n > 0 && (n & (n - 1)) === 0;
}

/** How many bits are set in a non-negative safe integer, which may exceed 32 bits. */
function bitCount(n: number): number {
  let count = 0;
  for (let rest = n; rest > 0; rest = Math.floor(rest / 2)) count += rest % 2;
  return count;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
