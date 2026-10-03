import { describe, expect, it } from "vitest";
import { signatureDigest } from "./entries";
import { canonicalDigest } from "./hash";
import { LogLeafSchema } from "./leaves";
import { HazardReviewEntrySchema, JobRequestSchema, sealCommitment, WithdrawalEntrySchema } from "./rounds";
import { SIGNATURE_BYTES } from "./signing";
import { SIGNATURE_ALGORITHM } from "./vocabulary";

const sig = `${SIGNATURE_ALGORITHM}:${"ab".repeat(SIGNATURE_BYTES)}`;
// What a log leaf holds in place of the signature.
const sigDigest = signatureDigest(sig);
const salt = "cd".repeat(32);
const bundle = `sha256:${"ef".repeat(32)}`;

describe("sealed rounds", () => {
  it("commit to an entry with a salt, so the commitment reveals nothing without it", () => {
    const entry = { type: "bundle", bundle, sig };
    expect(sealCommitment(entry, salt)).toBe(canonicalDigest({ entry, salt }));
    expect(sealCommitment(entry, "00".repeat(32))).not.toBe(sealCommitment(entry, salt));
    // Key order doesn't matter: the commitment is over canonical JSON.
    expect(sealCommitment({ sig, bundle, type: "bundle" }, salt)).toBe(sealCommitment(entry, salt));
  });

  it("log commitments naming no one, and reveal entries with the salt that opens them", () => {
    const timestamp = "2026-10-02T12:00:00.000Z";
    const commitment = sealCommitment({ type: "bundle", bundle, sig: sigDigest }, salt);
    const sealed = { timestamp, entry: { type: "sealed", commitment, sig: sigDigest } };
    expect(LogLeafSchema.safeParse(sealed).success).toBe(true);
    expect(LogLeafSchema.safeParse({ ...sealed, operator: "op:1" }).success).toBe(false);
    // A leaf holds signatures by digest, never in full.
    expect(LogLeafSchema.safeParse({ ...sealed, entry: { ...sealed.entry, sig } }).success).toBe(false);

    const opened = {
      timestamp,
      operator: "op:1",
      entry: { type: "bundle", bundle, sig: sigDigest },
      claims: [],
      fields: ["machine-learning"],
      sealed: { index: 4, salt },
    };
    expect(LogLeafSchema.safeParse(opened).success).toBe(true);
    expect(LogLeafSchema.safeParse({ ...opened, sealed: { index: 4, salt: "short" } }).success).toBe(false);
  });

  it("take hazard verdicts only from the shared vocabulary", () => {
    const review = { type: "hazard_review", reviewer: "op:3", bundle, verdict: "none", sig };
    expect(HazardReviewEntrySchema.safeParse(review).success).toBe(true);
    expect(HazardReviewEntrySchema.safeParse({ ...review, verdict: "chemical" }).success).toBe(true);
    expect(HazardReviewEntrySchema.safeParse({ ...review, verdict: "maybe" }).success).toBe(false);
  });

  it("name what a withdrawal closes, and want job requests in UTC", () => {
    expect(WithdrawalEntrySchema.safeParse({ type: "withdrawal", bundle, reason: "hazard", sealed: 7, sig }).success).toBe(true);
    expect(WithdrawalEntrySchema.safeParse({ type: "withdrawal", bundle, reason: "boredom", sig }).success).toBe(false);
    const request = { type: "job_request", operator: "op:2", time: "2026-10-02T12:00:00Z", sig };
    expect(JobRequestSchema.safeParse(request).success).toBe(true);
    expect(JobRequestSchema.safeParse({ ...request, time: "2026-10-02T12:00:00+02:00" }).success).toBe(false);
  });
});
