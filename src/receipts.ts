import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { digestBundle } from "./bundle";
import {
  bundleSigningObject,
  leafBytes,
  signObject,
  verifyObject,
  type LogLeaf,
  type TreeHead,
} from "./entries";
import { leafHash, verifyConsistency, verifyInclusion } from "./merkle";

/** Returns the bundle with its `signature` file: the operator's signature over its hash. */
export function signBundle(
  files: ReadonlyMap<string, Uint8Array>,
  secretKey: Uint8Array,
): Map<string, Uint8Array> {
  const unsigned = new Map(files);
  unsigned.delete("signature");
  const { sig } = signObject(bundleSigningObject(digestBundle(unsigned).bundle), secretKey);
  return new Map([...unsigned, ["signature", utf8ToBytes(sig)]]);
}

export interface Receipt {
  log: string;
  index: number;
  leaf: LogLeaf;
  leaf_hash: string;
  tree_head: TreeHead;
  inclusion_proof: string[];
}

/**
 * Checks a receipt against the log's public key: the log signed the tree head, the leaf
 * hashes to `leaf_hash`, and the proof places that leaf in the signed tree.
 */
export function verifyReceipt(receipt: Receipt, logPublicKey: string): boolean {
  try {
    return checkReceipt(receipt, logPublicKey);
  } catch {
    return false; // malformed hex or an unserializable leaf
  }
}

function checkReceipt(receipt: Receipt, logPublicKey: string): boolean {
  const { tree_head: head } = receipt;
  const hash = leafHash(leafBytes(receipt.leaf));
  return (
    head.log === receipt.log &&
    verifyObject(head, logPublicKey) &&
    bytesToHex(hash) === receipt.leaf_hash &&
    verifyInclusion(
      receipt.index,
      head.size,
      hash,
      receipt.inclusion_proof.map(hexToBytes),
      hexToBytes(head.root),
    )
  );
}

/** Checks that `second` extends `first` without rewriting it: what a monitor verifies. */
export function verifyTreeGrowth(
  first: TreeHead,
  second: TreeHead,
  proof: readonly string[],
  logPublicKey: string,
): boolean {
  return (
    first.log === second.log &&
    verifyObject(first, logPublicKey) &&
    verifyObject(second, logPublicKey) &&
    verifyConsistency(
      first.size,
      second.size,
      hexToBytes(first.root),
      hexToBytes(second.root),
      proof.map(hexToBytes),
    )
  );
}
