import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { z } from "zod";
import { SignatureSchema } from "./entries";
import { CHECKPOINT_ORIGIN_PREFIX } from "./vocabulary";

// Checkpoints in the format transparency logs share, so witnesses that cosign other logs'
// checkpoints can cosign this one's: a signed note (c2sp.org/signed-note) whose text is the
// log's origin, its size, and its root (c2sp.org/tlog-checkpoint), signed by the log with
// Ed25519 and cosigned by witnesses with timestamped Ed25519 (c2sp.org/tlog-cosignature).
// Only the signature types those specifications' final releases assign are used here: 0x01
// for the log, 0x04 for witnesses. A checkpoint says nothing a signed tree head doesn't; it is
// the tree head in a form witnesses read, and witnessing never counts toward any status.

/** The note signature types used here, by the byte signed-note assigns each. */
export const NOTE_SIGNATURE_TYPES = {
  /** A log's Ed25519 signature over the note text. */
  ed25519: 0x01,
  /** A witness's timestamped Ed25519 cosignature of a checkpoint. */
  cosignature: 0x04,
} as const;
export type NoteSignatureType = (typeof NOTE_SIGNATURE_TYPES)[keyof typeof NOTE_SIGNATURE_TYPES];

/** Signed notes are text: anything here that doesn't fit the format throws this. */
export class NoteError extends Error {
  override name = "NoteError";
}

/** The most signature lines a note may carry here; signed-note asks verifiers to accept at least 16. */
const MAX_SIGNATURES = 64;
const ED25519_SIGNATURE_BYTES = 64;
const ED25519_KEY_BYTES = 32;
const TIMESTAMP_BYTES = 8;
/** Signature lines begin with an em dash, U+2014. */
const EM_DASH = "\u2014";
/** The latest time a cosignature may state: 2^63 - 1 seconds. */
const MAX_TIMESTAMP = BigInt("9223372036854775807");

// --- Base64 --------------------------------------------------------------------------

/** Standard, padded base64 (RFC 4648, section 4). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Decodes standard, padded base64, rejecting any other encoding of the same bytes, as signed-note requires. */
export function base64ToBytes(text: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(text);
  } catch {
    throw new NoteError(`${JSON.stringify(text)} isn't base64`);
  }
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  if (bytesToBase64(bytes) !== text) throw new NoteError(`${JSON.stringify(text)} isn't canonical base64`);
  return bytes;
}

// --- Keys ----------------------------------------------------------------------------

/** A key that verifies note signatures: its name, its 32-bit ID, its signature type, and its public key. */
export interface NoteVerifier {
  name: string;
  id: number;
  type: NoteSignatureType;
  publicKey: Uint8Array;
}

function checkKeyName(name: string): void {
  // Non-empty, with no Unicode space or plus sign: the rule signed-note sets for key names.
  if (name.length === 0 || /[\s+]/u.test(name)) throw new NoteError(`${JSON.stringify(name)} isn't a key name: it must be non-empty, with no spaces or +`);
}

/** A key's ID: the first four bytes, big-endian, of SHA-256 over its name, a newline, its type, and its public key. */
export function noteKeyId(name: string, type: NoteSignatureType, publicKey: Uint8Array): number {
  const hash = sha256(concatBytes(utf8ToBytes(name), Uint8Array.of(0x0a, type), publicKey));
  return new DataView(hash.buffer, hash.byteOffset).getUint32(0);
}

/** A verifier for an Ed25519 key of `type`, named `name`. */
export function noteVerifier(name: string, type: NoteSignatureType, publicKey: Uint8Array): NoteVerifier {
  checkKeyName(name);
  if (publicKey.length !== ED25519_KEY_BYTES) throw new NoteError("An Ed25519 public key is 32 bytes");
  return { name, id: noteKeyId(name, type, publicKey), type, publicKey };
}

/** A verifier key as text (a vkey): its name, its ID in hex, and its type and public key in base64, joined by +. */
export function verifierKey(verifier: NoteVerifier): string {
  const id = verifier.id.toString(16).padStart(8, "0");
  return `${verifier.name}+${id}+${bytesToBase64(concatBytes(Uint8Array.of(verifier.type), verifier.publicKey))}`;
}

/** Reads a vkey of a type used here; throws for anything else, or for an ID that isn't the key's. */
export function parseVerifierKey(vkey: string): NoteVerifier {
  // The name holds no +, so it ends at the first; the ID is the next eight hex digits; base64 may hold + itself.
  const nameEnd = vkey.indexOf("+");
  const idEnd = nameEnd + 9;
  if (nameEnd < 0 || vkey[idEnd] !== "+") throw new NoteError(`${JSON.stringify(vkey)} isn't a verifier key: name+id+key`);
  const name = vkey.slice(0, nameEnd);
  const idText = vkey.slice(nameEnd + 1, idEnd);
  if (!/^[0-9a-f]{8}$/.test(idText)) throw new NoteError(`The ID in ${JSON.stringify(vkey)} isn't eight lowercase hex digits`);
  const material = base64ToBytes(vkey.slice(idEnd + 1));
  const type = material[0] as NoteSignatureType;
  if (!Object.values(NOTE_SIGNATURE_TYPES).includes(type)) {
    throw new NoteError(`${JSON.stringify(vkey)} is a key of type ${material[0]}; this reads Ed25519 keys of type 1 or 4`);
  }
  const verifier = noteVerifier(name, type, material.subarray(1));
  if (verifier.id !== Number.parseInt(idText, 16)) throw new NoteError(`The ID in ${JSON.stringify(vkey)} isn't the one its name and key make`);
  return verifier;
}

// --- Notes ---------------------------------------------------------------------------

export interface NoteSignature {
  name: string;
  id: number;
  /** The signature after the key ID. */
  signature: Uint8Array;
  /** The line as written, newline included. */
  line: string;
}

export interface Note {
  /** The signed text, ending in a newline. */
  text: string;
  signatures: NoteSignature[];
}

/** A signature line: an em dash, the key's name, and its ID and signature in base64. */
export function signatureLine(name: string, id: number, signature: Uint8Array): string {
  checkKeyName(name);
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, id);
  return `${EM_DASH} ${name} ${bytesToBase64(concatBytes(prefix, signature))}\n`;
}

function parseSignatureLine(line: string): NoteSignature {
  const parts = line.slice(0, -1).split(" ");
  if (parts.length !== 3 || parts[0] !== EM_DASH) throw new NoteError(`${JSON.stringify(line)} isn't a signature line`);
  const [, name, encoded] = parts;
  checkKeyName(name);
  const bytes = base64ToBytes(encoded);
  if (bytes.length < 5) throw new NoteError(`The signature in ${JSON.stringify(line)} is too short`);
  return { name, id: new DataView(bytes.buffer).getUint32(0), signature: bytes.subarray(4), line };
}

/**
 * Splits a signed note into its text and its signature lines. The text ends at the note's last
 * blank line; every line after it must be a signature line.
 */
export function parseNote(note: string): Note {
  for (const char of note) {
    if (char < " " && char !== "\n") throw new NoteError("A note holds no control characters other than newlines");
  }
  if (!note.endsWith("\n")) throw new NoteError("A note ends with a newline");
  const blank = note.lastIndexOf("\n\n");
  if (blank < 0) throw new NoteError("A note's signatures follow a blank line");
  const text = note.slice(0, blank + 1);
  const lines = note.slice(blank + 2).split("\n").slice(0, -1);
  if (lines.length === 0) throw new NoteError("A note has at least one signature");
  if (lines.length > MAX_SIGNATURES) throw new NoteError(`A note here has at most ${MAX_SIGNATURES} signatures`);
  return { text, signatures: lines.map((line) => parseSignatureLine(`${line}\n`)) };
}

/** The message a witness's cosignature signs: its header, its time, and the checkpoint's text. */
export function cosignatureMessage(text: string, timestamp: bigint): Uint8Array {
  return utf8ToBytes(`cosignature/v1\ntime ${timestamp}\n${text}`);
}

/** Signs a note's text with an Ed25519 seed, as a log signs its checkpoint: the signature line. */
export function signNote(text: string, name: string, seed: Uint8Array): string {
  const verifier = noteVerifier(name, NOTE_SIGNATURE_TYPES.ed25519, ed25519.getPublicKey(seed));
  return signatureLine(name, verifier.id, ed25519.sign(utf8ToBytes(text), seed));
}

/** Cosigns a checkpoint's text at `timestamp` (seconds since the epoch), as a witness does: the signature line. */
export function cosignNote(text: string, name: string, seed: Uint8Array, timestamp: bigint): string {
  const verifier = noteVerifier(name, NOTE_SIGNATURE_TYPES.cosignature, ed25519.getPublicKey(seed));
  const time = new Uint8Array(TIMESTAMP_BYTES);
  new DataView(time.buffer).setBigUint64(0, timestamp);
  return signatureLine(name, verifier.id, concatBytes(time, ed25519.sign(cosignatureMessage(text, timestamp), seed)));
}

/** What a note's signatures say for one key: none from it, one that verifies (with a cosignature's time), or one that doesn't. */
export type NoteSignatureCheck =
  | { verified: false; reason: "absent" | "invalid" | "repeated" }
  | { verified: true; timestamp?: bigint };

/**
 * Checks the signature `verifier` made on `note`, matched by name and ID as signed-note says;
 * signatures from other keys are ignored. Two lines from one key are an error in the note.
 */
export function checkNoteSignature(note: Note, verifier: NoteVerifier): NoteSignatureCheck {
  const lines = note.signatures.filter((s) => s.name === verifier.name && s.id === verifier.id);
  if (lines.length === 0) return { verified: false, reason: "absent" };
  if (lines.length > 1) return { verified: false, reason: "repeated" };
  const { signature } = lines[0];
  const valid = (bytes: Uint8Array, message: Uint8Array) => {
    try {
      return bytes.length === ED25519_SIGNATURE_BYTES && ed25519.verify(bytes, message, verifier.publicKey);
    } catch {
      return false;
    }
  };
  if (verifier.type === NOTE_SIGNATURE_TYPES.ed25519) {
    return valid(signature, utf8ToBytes(note.text)) ? { verified: true } : { verified: false, reason: "invalid" };
  }
  if (signature.length !== TIMESTAMP_BYTES + ED25519_SIGNATURE_BYTES) return { verified: false, reason: "invalid" };
  const timestamp = new DataView(signature.buffer, signature.byteOffset).getBigUint64(0);
  if (timestamp > MAX_TIMESTAMP) return { verified: false, reason: "invalid" };
  return valid(signature.subarray(TIMESTAMP_BYTES), cosignatureMessage(note.text, timestamp))
    ? { verified: true, timestamp }
    : { verified: false, reason: "invalid" };
}

// --- Checkpoints ---------------------------------------------------------------------

/** A log's origin, its checkpoints' first line and its checkpoint key's name, derived from its ID so anyone can compute it. */
export function checkpointOrigin(logId: string): string {
  if (!/^log:[0-9a-f]{64}$/.test(logId)) throw new NoteError(`${JSON.stringify(logId)} isn't a log ID`);
  return `${CHECKPOINT_ORIGIN_PREFIX}${logId.slice("log:".length)}`;
}

/** A checkpoint's text: the origin, the tree size in decimal, and the root in base64, each on its own line. */
export function checkpointText(origin: string, size: number, rootHex: string): string {
  return `${origin}\n${size}\n${bytesToBase64(hexToBytes(rootHex))}\n`;
}

export interface CheckpointNote extends Note {
  origin: string;
  size: number;
  /** The root, in hex as tree heads write it. */
  root: string;
}

/** Reads a checkpoint: a signed note whose text is an origin, a size, a root, and no extension lines. */
export function parseCheckpointNote(checkpoint: string): CheckpointNote {
  const note = parseNote(checkpoint);
  const lines = note.text.slice(0, -1).split("\n");
  if (lines.length < 3 || lines.some((line) => line.length === 0)) throw new NoteError("A checkpoint's text is an origin, a size, and a root, each on a line");
  // Extension lines aren't signed by witnesses' newer cosignatures nor checked by monitors; this log writes none.
  if (lines.length > 3) throw new NoteError("This log's checkpoints have no extension lines");
  const [origin, sizeText, rootText] = lines;
  if (utf8ToBytes(origin).length > 255) throw new NoteError("A checkpoint's origin is at most 255 bytes");
  if (!/^(0|[1-9][0-9]*)$/.test(sizeText) || !Number.isSafeInteger(Number(sizeText))) throw new NoteError(`${JSON.stringify(sizeText)} isn't a tree size`);
  const root = base64ToBytes(rootText);
  if (root.length !== 32) throw new NoteError("A checkpoint's root is 32 bytes");
  return { ...note, origin, size: Number(sizeText), root: bytesToHex(root) };
}

/**
 * What a log publishes beside its tree heads so its checkpoints can be trusted through its
 * own key: its origin and its checkpoint keys as vkeys, signed by the log's key. The checkpoint
 * key is its own, so the log's key signs only the log's own objects.
 */
export const CheckpointKeysSchema = z.strictObject({
  type: z.literal("checkpoint_keys"),
  log: z.string(),
  origin: z.string(),
  keys: z.array(z.string()).min(1).max(8),
  sig: SignatureSchema,
});
export type CheckpointKeys = z.infer<typeof CheckpointKeysSchema>;
