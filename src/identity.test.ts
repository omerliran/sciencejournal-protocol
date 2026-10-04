import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import { signatureDigest, signObject, verifyObject } from "./entries";
import {
  attestPairedVouch,
  attestRecoveryApproval,
  attestVouch,
  consentPayload,
  IdentityEntrySchema,
  isPairedVouch,
  PairedVouchSchema,
  PairingCodeSchema,
  pairingDigest,
  verifyConsent,
  VouchConsentSchema,
  InviteCodeSchema,
  invitePayload,
  InviteSchema,
  KeyRecoveryEntrySchema,
  recoveryApprovalPayload,
  RepositorySchema,
  verifyInvite,
  verifyRecoveryApproval,
  verifyVouch,
  VouchedRecoveryRequestSchema,
  vouchPayload,
  VouchSchema,
} from "./identity";
import { LogLeafSchema, detachLeaf, type SignedLeaf } from "./leaves";
import { generateKeyPair, sign } from "./signing";

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

describe("invites", () => {
  const code = `invite:${"ab2c7".repeat(6)}xy`;

  it("are codes of 160 random bits in base32, under a prefix that says what they are", () => {
    expect(InviteCodeSchema.safeParse(code).success).toBe(true);
    for (const wrong of [code.slice(0, -1), `${code}a`, code.toUpperCase(), code.replace("invite:", ""), `invite:${"a".repeat(31)}1`, `invite:${"a".repeat(31)}=`]) {
      expect(InviteCodeSchema.safeParse(wrong).success, wrong).toBe(false);
    }
  });

  it("are signed by the sponsor, then countersigned by the operator that uses one, sponsor_sig included", () => {
    const sponsor = generateKeyPair();
    const operator = generateKeyPair();
    const invite = signObject({ type: "invite" as const, sponsor: op12, code }, sponsor.secretKey);
    expect(InviteSchema.safeParse(invite).success).toBe(true);
    expect(new TextDecoder().decode(invitePayload(invite))).toBe(canonicalJson({ type: "invite", sponsor: op12, code }));

    const unsigned = { type: "identity" as const, kind: "sponsored" as const, operator: op13, sponsor: op12, code, sponsor_sig: invite.sig };
    const entry = signObject(unsigned, operator.secretKey);
    expect(IdentityEntrySchema.safeParse(entry).success).toBe(true);
    expect(verifyInvite(entry, sponsor.publicKey)).toBe(true);
    expect(verifyInvite({ ...entry, code: `invite:${"z".repeat(32)}` }, sponsor.publicKey)).toBe(false);
    expect(verifyInvite({ ...entry, sponsor: op13 }, sponsor.publicKey)).toBe(false);
    expect(verifyInvite(entry, operator.publicKey)).toBe(false);
    // The operator's signature covers the sponsor's: swapping it breaks the countersignature.
    const swapped = { ...entry, sponsor_sig: sign(invitePayload({ sponsor: op12, code: `invite:${"z".repeat(32)}` }), sponsor.secretKey) };
    expect(verifyObject(swapped, operator.publicKey)).toBe(false);
    // An invite alone isn't an identity entry.
    expect(IdentityEntrySchema.safeParse(invite).success).toBe(false);

    // The leaf holds both signatures by digest.
    const signedLeaf = { timestamp: "2026-10-04T12:00:00.000Z", operator: op13, entry, organization: "example.org" } as SignedLeaf;
    const leaf = detachLeaf(signedLeaf);
    expect(leaf.entry).toMatchObject({ sig: signatureDigest(entry.sig), sponsor_sig: signatureDigest(invite.sig) });
    expect(LogLeafSchema.safeParse(leaf).success).toBe(true);
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

/** An object without one of its fields. */
const without = (object: object, field: string) => Object.fromEntries(Object.entries(object).filter(([key]) => key !== field));

describe("paired vouches", () => {
  const code = `pair:${"ab2c7".repeat(6)}xy`;
  const pairing = pairingDigest(code);

  it("pair with a code of 160 random bits in base32, which only its digest names", () => {
    expect(PairingCodeSchema.safeParse(code).success).toBe(true);
    for (const wrong of [code.slice(0, -1), `${code}a`, code.toUpperCase(), code.replace("pair:", "invite:"), `pair:${"a".repeat(31)}1`]) {
      expect(PairingCodeSchema.safeParse(wrong).success, wrong).toBe(false);
    }
    expect(pairing).toBe(`sha256:${createHash("sha256").update(code).digest("hex")}`);
  });

  it("complete a consent the operator signed in advance with a vouch the log attests, and nothing else", () => {
    const operator = generateKeyPair();
    const log = generateKeyPair();
    const consent = signObject({ type: "vouch_consent" as const, operator: op12, pairing }, operator.secretKey);
    expect(VouchConsentSchema.safeParse(consent).success).toBe(true);
    expect(new TextDecoder().decode(consentPayload(consent))).toBe(canonicalJson({ type: "vouch_consent", operator: op12, pairing }));
    // The consent names the code only by its digest, so the node holding it can't vouch with it.
    expect(VouchConsentSchema.safeParse({ ...consent, pairing: code }).success).toBe(false);

    const entry = attestPairedVouch(consent, account, log.secretKey);
    expect(entry).toEqual({ type: "identity", kind: "vouched", operator: op12, voucher: account, pairing, consent_sig: consent.sig, voucher_sig: entry.voucher_sig });
    expect(IdentityEntrySchema.safeParse(entry).success).toBe(true);
    expect(PairedVouchSchema.safeParse(entry).success).toBe(true);
    expect(isPairedVouch(entry)).toBe(true);
    // The log attests the entry without its signatures, the pairing included.
    expect(new TextDecoder().decode(vouchPayload(entry))).toBe(
      canonicalJson({ type: "identity", kind: "vouched", operator: op12, voucher: account, pairing }),
    );
    expect(verifyVouch(entry, log.publicKey)).toBe(true);
    expect(verifyVouch({ ...entry, voucher: "github:583232" }, log.publicKey)).toBe(false);
    expect(verifyVouch({ ...entry, pairing: pairingDigest(`pair:${"z".repeat(32)}`) }, log.publicKey)).toBe(false);
    // A countersigned vouch's attestation, without the pairing, doesn't stand in for it.
    expect(verifyVouch({ ...entry, voucher_sig: attestVouch({ operator: op12, voucher: account }, log.secretKey).voucher_sig }, log.publicKey)).toBe(false);
    expect(verifyConsent(entry, operator.publicKey)).toBe(true);
    expect(verifyConsent(entry, log.publicKey)).toBe(false);
    expect(verifyConsent({ ...entry, operator: op13 }, operator.publicKey)).toBe(false);

    // A vouch is countersigned or paired, never both or neither.
    const countersigned = signObject(attestVouch({ operator: op12, voucher: account }, log.secretKey), operator.secretKey);
    expect(isPairedVouch(countersigned)).toBe(false);
    expect(IdentityEntrySchema.safeParse({ ...entry, sig: countersigned.sig }).success).toBe(false);
    expect(IdentityEntrySchema.safeParse({ ...countersigned, pairing }).success).toBe(false);
    expect(IdentityEntrySchema.safeParse(without(entry, "consent_sig")).success).toBe(false);
    expect(IdentityEntrySchema.safeParse(without(entry, "pairing")).success).toBe(false);

    // The leaf holds both signatures by digest, and no sig.
    const signedLeaf = { timestamp: "2026-10-04T12:00:00.000Z", operator: op12, entry, organization: account } as SignedLeaf;
    const leaf = detachLeaf(signedLeaf);
    expect(leaf.entry).toEqual({ ...entry, consent_sig: signatureDigest(consent.sig), voucher_sig: signatureDigest(entry.voucher_sig) });
    expect(LogLeafSchema.safeParse(leaf).success).toBe(true);
    expect(LogLeafSchema.safeParse(signedLeaf).success).toBe(false);
    // A countersigned vouch's leaf still needs its sig.
    const countersignedLeaf = detachLeaf({ ...signedLeaf, entry: countersigned } as SignedLeaf);
    expect(LogLeafSchema.safeParse(countersignedLeaf).success).toBe(true);
    expect(LogLeafSchema.safeParse({ ...countersignedLeaf, entry: without(countersignedLeaf.entry, "sig") }).success).toBe(false);
  });
});
