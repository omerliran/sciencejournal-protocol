import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import { signatureDigest, signObject, verifyObject } from "./entries";
import { IdentityEntrySchema, RepositorySchema, verifyVouch, vouchPayload } from "./identity";
import { LogLeafSchema, detachLeaf, type SignedLeaf } from "./leaves";
import { generateKeyPair } from "./signing";
import { virtualPasskey } from "./virtual-passkey";

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
    const unsigned = { type: "identity" as const, kind: "vouched" as const, operator: "op:12", observer: "obs:3" };
    const vouch = { ...unsigned, voucher_sig: volunteer.sign(unsigned).sig };
    expect(new TextDecoder().decode(vouchPayload(vouch))).toBe(canonicalJson(unsigned));
    expect(verifyVouch(vouch, volunteer.publicKey)).toMatchObject({ origin: "https://sciencejournal.ai" });
    expect(verifyVouch({ ...vouch, operator: "op:13" }, volunteer.publicKey)).toBeNull();
    expect(verifyVouch(vouch, virtualPasskey().publicKey)).toBeNull();

    const entry = signObject(vouch, operator.secretKey);
    expect(IdentityEntrySchema.safeParse(entry).success).toBe(true);
    expect(verifyObject(entry, operator.publicKey)).toBe(true);
    // The operator's signature covers the volunteer's: swapping it breaks the countersignature.
    const other = { ...unsigned, operator: "op:13" };
    const swapped = { ...entry, voucher_sig: volunteer.sign(other).sig };
    expect(verifyObject(swapped, operator.publicKey)).toBe(false);
    // Neither signature alone makes an identity entry.
    expect(IdentityEntrySchema.safeParse(vouch).success).toBe(false);
    expect(IdentityEntrySchema.safeParse(signObject(unsigned, operator.secretKey)).success).toBe(false);

    // The leaf holds both signatures by digest.
    const signedLeaf = { timestamp: "2026-10-03T12:00:00.000Z", operator: "op:12", entry, organization: "obs:3" } as SignedLeaf;
    const leaf = detachLeaf(signedLeaf);
    expect(leaf.entry).toMatchObject({ sig: signatureDigest(entry.sig), voucher_sig: signatureDigest(vouch.voucher_sig) });
    expect(LogLeafSchema.safeParse(leaf).success).toBe(true);
    expect(LogLeafSchema.safeParse(signedLeaf).success).toBe(false);
  });
});
