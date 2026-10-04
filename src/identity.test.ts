import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import { signatureDigest, signObject, verifyObject } from "./entries";
import {
  attestRecoveryApproval,
  attestVouch,
  IdentityEntrySchema,
  KeyRecoveryEntrySchema,
  recoveryApprovalPayload,
  RepositorySchema,
  verifyRecoveryApproval,
  verifyVouch,
  VouchedRecoveryRequestSchema,
  vouchPayload,
  VouchSchema,
} from "./identity";
import { LogLeafSchema, detachLeaf, type SignedLeaf } from "./leaves";
import { generateKeyPair } from "./signing";

// IDs of the shape operators' and volunteers' first keys make: op: or obs: and 64 hex digits.
const exampleId = (kind: "op" | "obs", n: number) => `${kind}:${n.toString(16).padStart(64, "0")}`;
// A GitHub account that vouched, by its numeric ID.
const account = "github:583231";
const op12 = exampleId("op", 12);
const op13 = exampleId("op", 13);

describe("identity entries", () => {
  it("name GitHub repositories as owner/name, as GitHub allows them", () => {
    for (const name of ["example-lab/agents", "a/b", "Lab42/my.repo_v2"]) expect(RepositorySchema.safeParse(name).success).toBe(true);
    for (const name of ["example-lab", "-lab/agents", "lab/agents/extra", "lab/ag ents", "https://github.com/lab/agents", `${"a".repeat(40)}/x`]) {
      expect(RepositorySchema.safeParse(name).success).toBe(false);
    }
  });

  it("make a vouch the log attests and the operator countersigns, voucher_sig included", () => {
    const operator = generateKeyPair();
    const log = generateKeyPair();
    const unsigned = { type: "identity", kind: "vouched", operator: op12, voucher: account };
    const vouch = attestVouch({ operator: op12, voucher: account }, log.secretKey);
    expect(VouchSchema.safeParse(vouch).success).toBe(true);
    expect(new TextDecoder().decode(vouchPayload(vouch))).toBe(canonicalJson(unsigned));
    expect(verifyVouch(vouch, log.publicKey)).toBe(true);
    expect(verifyVouch({ ...vouch, operator: op13 }, log.publicKey)).toBe(false);
    expect(verifyVouch({ ...vouch, voucher: "github:583232" }, log.publicKey)).toBe(false);
    expect(verifyVouch(vouch, generateKeyPair().publicKey)).toBe(false);
    // A voucher is a GitHub account by its numeric ID, never a login, which can change hands.
    for (const voucher of ["github:octocat", "github:0", "github:0583231", "583231", exampleId("obs", 3)]) {
      expect(VouchSchema.safeParse({ ...vouch, voucher }).success).toBe(false);
    }

    const entry = signObject(vouch, operator.secretKey);
    expect(IdentityEntrySchema.safeParse(entry).success).toBe(true);
    expect(verifyObject(entry, operator.publicKey)).toBe(true);
    // The operator's signature covers the log's: swapping it breaks the countersignature.
    const swapped = { ...entry, voucher_sig: attestVouch({ operator: op13, voucher: account }, log.secretKey).voucher_sig };
    expect(verifyObject(swapped, operator.publicKey)).toBe(false);
    // Neither signature alone makes an identity entry.
    expect(IdentityEntrySchema.safeParse(vouch).success).toBe(false);
    expect(IdentityEntrySchema.safeParse(signObject(unsigned, operator.secretKey)).success).toBe(false);

    // The leaf holds both signatures by digest.
    const signedLeaf = { timestamp: "2026-10-03T12:00:00.000Z", operator: op12, entry, organization: account } as SignedLeaf;
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

  it("through a vouch: the new key asks, the account that vouched approves, and the new key countersigns the log's attestation", () => {
    const log = generateKeyPair();
    const unsigned = { type: "key_recovery" as const, kind: "vouched" as const, operator: op12, key: next.publicKey, voucher: account, since };

    // The request proves the operator holds the new key; it isn't an entry by itself.
    const request = signObject(unsigned, next.secretKey);
    expect(VouchedRecoveryRequestSchema.safeParse(request).success).toBe(true);
    expect(KeyRecoveryEntrySchema.safeParse(request).success).toBe(false);
    expect(verifyObject(request, next.publicKey)).toBe(true);

    // The account's holder signs in to approve, and the log attests it over the entry without either signature.
    const approved = { ...unsigned, voucher_sig: attestRecoveryApproval(unsigned, log.secretKey) };
    expect(new TextDecoder().decode(recoveryApprovalPayload(approved))).toBe(canonicalJson(unsigned));
    expect(verifyRecoveryApproval(approved, log.publicKey)).toBe(true);
    expect(verifyRecoveryApproval({ ...approved, key: generateKeyPair().publicKey }, log.publicKey)).toBe(false);
    expect(verifyRecoveryApproval({ ...approved, since: since + 1 }, log.publicKey)).toBe(false);
    expect(verifyRecoveryApproval(approved, generateKeyPair().publicKey)).toBe(false);

    // The new key countersigns everything but sig, so the log alone shows both agreed.
    const entry = signObject(approved, next.secretKey);
    expect(KeyRecoveryEntrySchema.safeParse(entry).success).toBe(true);
    expect(verifyObject(entry, next.publicKey)).toBe(true);
    const swapped = { ...entry, voucher_sig: attestRecoveryApproval({ ...unsigned, operator: op13 }, log.secretKey) };
    expect(verifyObject(swapped, next.publicKey)).toBe(false);

    // The leaf holds both signatures by digest.
    const signedLeaf = { timestamp: "2026-10-03T12:00:00.000Z", operator: op12, entry } as SignedLeaf;
    const leaf = detachLeaf(signedLeaf);
    expect(leaf.entry).toMatchObject({ sig: signatureDigest(entry.sig), voucher_sig: signatureDigest(approved.voucher_sig) });
    expect(LogLeafSchema.safeParse(leaf).success).toBe(true);
  });
});
