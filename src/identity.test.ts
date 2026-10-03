import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import { signatureDigest, signObject, verifyObject } from "./entries";
import {
  IdentityEntrySchema,
  KeyRecoveryEntrySchema,
  recoveryApprovalPayload,
  RepositorySchema,
  verifyRecoveryApproval,
  verifyVouch,
  VouchedRecoveryRequestSchema,
  vouchPayload,
} from "./identity";
import { LogLeafSchema, detachLeaf, type SignedLeaf } from "./leaves";
import { generateKeyPair } from "./signing";
import { virtualPasskey } from "./virtual-passkey";

// IDs of the shape operators' and volunteers' first keys make: op: or obs: and 64 hex digits.
const exampleId = (kind: "op" | "obs", n: number) => `${kind}:${n.toString(16).padStart(64, "0")}`;
const obs3 = exampleId("obs", 3);
const op12 = exampleId("op", 12);
const op13 = exampleId("op", 13);

describe("identity entries", () => {
  it("name GitHub repositories as owner/name, as GitHub allows them", () => {
    for (const name of ["example-lab/agents", "a/b", "Lab42/my.repo_v2"]) expect(RepositorySchema.safeParse(name).success).toBe(true);
    for (const name of ["example-lab", "-lab/agents", "lab/agents/extra", "lab/ag ents", "https://github.com/lab/agents", `${"a".repeat(40)}/x`]) {
      expect(RepositorySchema.safeParse(name).success).toBe(false);
    }
  });

  it("make a vouch the volunteer signs first and the operator countersigns, voucher_sig included", () => {
    const operator = generateKeyPair();
    const volunteer = virtualPasskey();
    const unsigned = { type: "identity" as const, kind: "vouched" as const, operator: op12, observer: obs3 };
    const vouch = { ...unsigned, voucher_sig: volunteer.sign(unsigned).sig };
    expect(new TextDecoder().decode(vouchPayload(vouch))).toBe(canonicalJson(unsigned));
    expect(verifyVouch(vouch, volunteer.publicKey)).toMatchObject({ origin: "https://sciencejournal.ai" });
    expect(verifyVouch({ ...vouch, operator: op13 }, volunteer.publicKey)).toBeNull();
    expect(verifyVouch(vouch, virtualPasskey().publicKey)).toBeNull();

    const entry = signObject(vouch, operator.secretKey);
    expect(IdentityEntrySchema.safeParse(entry).success).toBe(true);
    expect(verifyObject(entry, operator.publicKey)).toBe(true);
    // The operator's signature covers the volunteer's: swapping it breaks the countersignature.
    const other = { ...unsigned, operator: op13 };
    const swapped = { ...entry, voucher_sig: volunteer.sign(other).sig };
    expect(verifyObject(swapped, operator.publicKey)).toBe(false);
    // Neither signature alone makes an identity entry.
    expect(IdentityEntrySchema.safeParse(vouch).success).toBe(false);
    expect(IdentityEntrySchema.safeParse(signObject(unsigned, operator.secretKey)).success).toBe(false);

    // The leaf holds both signatures by digest.
    const signedLeaf = { timestamp: "2026-10-03T12:00:00.000Z", operator: op12, entry, organization: obs3 } as SignedLeaf;
    const leaf = detachLeaf(signedLeaf);
    expect(leaf.entry).toMatchObject({ sig: signatureDigest(entry.sig), voucher_sig: signatureDigest(vouch.voucher_sig) });
    expect(LogLeafSchema.safeParse(leaf).success).toBe(true);
    expect(LogLeafSchema.safeParse(signedLeaf).success).toBe(false);
  });
});

describe("key recoveries", () => {
  const next = generateKeyPair();
  const since = 40;

  it("are proven by a domain, a GitHub repository, a vouch, or the log, and say where the old key stops counting", () => {
    const base = { type: "key_recovery" as const, operator: op12, key: next.publicKey, since };
    const byGithub = signObject({ ...base, kind: "github" as const, repository: "example-lab/agents" }, next.secretKey);
    expect(KeyRecoveryEntrySchema.safeParse(byGithub).success).toBe(true);
    expect(verifyObject(byGithub, next.publicKey)).toBe(true);
    expect(KeyRecoveryEntrySchema.safeParse({ ...byGithub, repository: "example-lab" }).success).toBe(false);
    expect(KeyRecoveryEntrySchema.safeParse({ ...byGithub, kind: "domain" }).success).toBe(false);
  });

  it("through a vouch: the new key asks, the volunteer approves, and the new key countersigns their approval", () => {
    const volunteer = virtualPasskey();
    const unsigned = { type: "key_recovery" as const, kind: "vouched" as const, operator: op12, key: next.publicKey, observer: obs3, since };

    // The request proves the operator holds the new key; it isn't an entry by itself.
    const request = signObject(unsigned, next.secretKey);
    expect(VouchedRecoveryRequestSchema.safeParse(request).success).toBe(true);
    expect(KeyRecoveryEntrySchema.safeParse(request).success).toBe(false);
    expect(verifyObject(request, next.publicKey)).toBe(true);

    // The volunteer approves the recovery without either signature, as their browser signs it.
    const approved = { ...unsigned, voucher_sig: volunteer.sign(unsigned).sig };
    expect(new TextDecoder().decode(recoveryApprovalPayload(approved))).toBe(canonicalJson(unsigned));
    expect(verifyRecoveryApproval(approved, volunteer.publicKey)).toMatchObject({ origin: "https://sciencejournal.ai" });
    expect(verifyRecoveryApproval({ ...approved, key: generateKeyPair().publicKey }, volunteer.publicKey)).toBeNull();
    expect(verifyRecoveryApproval({ ...approved, since: since + 1 }, volunteer.publicKey)).toBeNull();
    expect(verifyRecoveryApproval(approved, virtualPasskey().publicKey)).toBeNull();

    // The new key countersigns everything but sig, so the log alone shows both agreed.
    const entry = signObject(approved, next.secretKey);
    expect(KeyRecoveryEntrySchema.safeParse(entry).success).toBe(true);
    expect(verifyObject(entry, next.publicKey)).toBe(true);
    const otherApproval = volunteer.sign({ ...unsigned, operator: op13 }).sig;
    const swapped = { ...entry, voucher_sig: otherApproval };
    expect(verifyObject(swapped, next.publicKey)).toBe(false);

    // The leaf holds both signatures by digest.
    const signedLeaf = { timestamp: "2026-10-03T12:00:00.000Z", operator: op12, entry } as SignedLeaf;
    const leaf = detachLeaf(signedLeaf);
    expect(leaf.entry).toMatchObject({ sig: signatureDigest(entry.sig), voucher_sig: signatureDigest(approved.voucher_sig) });
    expect(LogLeafSchema.safeParse(leaf).success).toBe(true);
  });
});
