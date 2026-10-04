import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import {
  base64ToBytes,
  checkNoteSignature,
  checkpointOrigin,
  checkpointText,
  cosignNote,
  NOTE_SIGNATURE_TYPES,
  NoteError,
  noteVerifier,
  parseCheckpointNote,
  parseNote,
  parseVerifierKey,
  signNote,
  verifierKey,
} from "./notes";

const seed = (n: number) => new Uint8Array(32).fill(n);

describe("signed notes", () => {
  // The example in c2sp.org/signed-note, "Verifier keys".
  const vkey = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
  const note =
    "This is an example message.\n\n\u2014 example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";

  it("verifies the specification's example with its verifier key", () => {
    const verifier = parseVerifierKey(vkey);
    expect(verifier).toMatchObject({ name: "example.com/foo", id: 0x530d903a, type: NOTE_SIGNATURE_TYPES.ed25519 });
    expect(verifierKey(verifier)).toBe(vkey);
    const parsed = parseNote(note);
    expect(parsed.text).toBe("This is an example message.\n");
    expect(checkNoteSignature(parsed, verifier)).toEqual({ verified: true });
    // One changed byte of text, and it no longer verifies.
    expect(checkNoteSignature({ ...parsed, text: "This is an example message!\n" }, verifier)).toEqual({ verified: false, reason: "invalid" });
  });

  it("ignores signatures from other keys, even one sharing a name, and refuses one key signing twice", () => {
    const verifier = parseVerifierKey(vkey);
    const other = noteVerifier("example.com/foo", NOTE_SIGNATURE_TYPES.ed25519, ed25519.getPublicKey(seed(9)));
    expect(checkNoteSignature(parseNote(note), other)).toEqual({ verified: false, reason: "absent" });
    const [line] = parseNote(note).signatures;
    expect(checkNoteSignature(parseNote(`${note}${line.line}`), verifier)).toEqual({ verified: false, reason: "repeated" });
  });

  it("splits a note at its last blank line, and refuses what isn't a note", () => {
    const text = "first\n\nsecond\n";
    const signed = `${text}\n${signNote(text, "example.com/k", seed(1))}`;
    expect(parseNote(signed).text).toBe(text);
    for (const bad of [text, `${text}\n`, signed.slice(0, -1), signed.replace("first", "fi\trst"), `${text}\nnot a signature\n`]) {
      expect(() => parseNote(bad)).toThrow(NoteError);
    }
  });

  it("rejects base64 that isn't canonical, and verifier keys whose ID isn't theirs", () => {
    expect(base64ToBytes("AQI=")).toEqual(Uint8Array.of(1, 2));
    expect(() => base64ToBytes("AQJ=")).toThrow(/canonical/);
    expect(() => base64ToBytes("AQI")).toThrow(NoteError);
    expect(() => parseVerifierKey(vkey.replace("530d903a", "530d903b"))).toThrow(/isn't the one/);
    expect(() => parseVerifierKey("example.com/foo+530d903a")).toThrow(NoteError);
    expect(() => noteVerifier("has space", NOTE_SIGNATURE_TYPES.ed25519, ed25519.getPublicKey(seed(1)))).toThrow(/key name/);
  });
});

describe("checkpoints", () => {
  const log = `log:${"ab".repeat(32)}`;
  const origin = checkpointOrigin(log);
  const root = "cd".repeat(32);
  const text = checkpointText(origin, 20852163, root);

  it("writes an origin derived from the log ID, the size, and the root in base64", () => {
    expect(origin).toBe(`sciencejournal.ai/log/${"ab".repeat(32)}`);
    expect(text).toBe(`${origin}\n20852163\nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0=\n`);
    const checkpoint = parseCheckpointNote(`${text}\n${signNote(text, origin, seed(1))}`);
    expect(checkpoint).toMatchObject({ origin, size: 20852163, root });
    const logKey = noteVerifier(origin, NOTE_SIGNATURE_TYPES.ed25519, ed25519.getPublicKey(seed(1)));
    expect(checkNoteSignature(checkpoint, logKey)).toEqual({ verified: true });
  });

  it("checks a witness's timestamped cosignature over the checkpoint's text", () => {
    const signed = `${text}\n${signNote(text, origin, seed(1))}${cosignNote(text, "witness.example/w1", seed(2), BigInt(1679315147))}`;
    const checkpoint = parseCheckpointNote(signed);
    const witness = noteVerifier("witness.example/w1", NOTE_SIGNATURE_TYPES.cosignature, ed25519.getPublicKey(seed(2)));
    expect(checkNoteSignature(checkpoint, witness)).toEqual({ verified: true, timestamp: BigInt(1679315147) });
    // The same key as a plain note signature is another key: a different ID, so absent.
    const plain = noteVerifier("witness.example/w1", NOTE_SIGNATURE_TYPES.ed25519, ed25519.getPublicKey(seed(2)));
    expect(checkNoteSignature(checkpoint, plain)).toEqual({ verified: false, reason: "absent" });
    // A cosignature of another checkpoint doesn't verify on this one.
    const other = checkpointText(origin, 20852164, root);
    const moved = `${text}\n${cosignNote(other, "witness.example/w1", seed(2), BigInt(1679315147))}`;
    expect(checkNoteSignature(parseCheckpointNote(moved), witness)).toEqual({ verified: false, reason: "invalid" });
  });

  it("refuses checkpoints that don't fit the format", () => {
    const sign = (body: string) => `${body}\n${signNote(body, origin, seed(1))}`;
    expect(() => parseCheckpointNote(sign(`${origin}\n020852163\n${text.split("\n")[2]}\n`))).toThrow(/tree size/);
    expect(() => parseCheckpointNote(sign(`${origin}\n1\nAAAA\n`))).toThrow(/32 bytes/);
    expect(() => parseCheckpointNote(sign(`${origin}\n1\n`))).toThrow(/origin, a size, and a root/);
    expect(() => parseCheckpointNote(sign(`${text}extension\n`))).toThrow(/extension/);
    expect(() => checkpointOrigin("log:xyz")).toThrow(/log ID/);
  });
});

describe("a checkpoint a live witness cosigned", () => {
  // From a public witness's monitoring endpoint (c2sp.org/tlog-witness), on 2026-10-03: a log on
  // the witness network's staging list, signed by the log and cosigned by the witness with
  // Ed25519 and with ML-DSA-44, a type whose specification isn't final, which this ignores.
  const checkpoint = "markovianprotocol.com/log\n9266\nQnwPzJywq5AyOk9k1zLqfryh6Ktw1CnaaKplELApoxw=\n\n\u2014 markovianprotocol.com/log AwLGyIvuxLXZM101mKdNCPTsl9GgtiG/wzbd8cGru0pGnWVMXI06twIsEIZho7n8id+w2EO0BZCalxuEm6BauQGNmgo=\n\u2014 witness.navigli.sunlight.geomys.org o+AP4gAAAABqwX+So8evhUsltetL+QnwUxEYMNrD25pJYOTFHwDCopbgQMl2AEh583AxfFNMDZzE73rdjK62tUN8oUBfd9p6usq+BA==\n\u2014 witness.navigli.sunlight.geomys.org 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\n";
  const log = "markovianprotocol.com/log+0302c6c8+ATkpOWo95UuEiW2EhNZAol4f0CS8hMluJfPcTSzrr03v";
  const witness = "witness.navigli.sunlight.geomys.org+a3e00fe2+BNy/co4C1Hn1p+INwJrfUlgz7W55dSZReusH/GhUhJ/G";

  it("verifies the log's signature and the witness's Ed25519 cosignature", () => {
    const note = parseCheckpointNote(checkpoint);
    expect(note).toMatchObject({ origin: "markovianprotocol.com/log", size: 9266 });
    expect(checkNoteSignature(note, parseVerifierKey(log))).toEqual({ verified: true });
    expect(checkNoteSignature(note, parseVerifierKey(witness))).toMatchObject({ verified: true });
  });
});
