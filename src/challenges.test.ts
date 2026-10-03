import { describe, expect, it } from "vitest";
import { ChallengeEntrySchema, ChallengeReviewEntrySchema } from "./challenges";
import { signatureDigest } from "./entries";
import { LogLeafSchema } from "./leaves";
import { SIGNATURE_BYTES } from "./signing";
import { SIGNATURE_ALGORITHM } from "./vocabulary";

const sig = `${SIGNATURE_ALGORITHM}:${"ab".repeat(SIGNATURE_BYTES)}`;
const claim = `claim:${"cd".repeat(32)}`;
const digest = `sha256:${"ef".repeat(32)}`;

describe("challenges", () => {
  const challenge = { type: "challenge", challenger: "op:3", claim, ground: "reproduction", evidence: digest, sig };

  it("name a claim, a ground from the vocabulary, and the evidence", () => {
    expect(ChallengeEntrySchema.safeParse(challenge).success).toBe(true);
    for (const ground of ["counterexample", "data", "integrity"]) {
      expect(ChallengeEntrySchema.safeParse({ ...challenge, ground }).success).toBe(true);
    }
    // A missed prior result bears on priority, not truth, so it isn't a ground.
    expect(ChallengeEntrySchema.safeParse({ ...challenge, ground: "prior_result" }).success).toBe(false);
    expect(ChallengeEntrySchema.safeParse({ ...challenge, claim: "C1" }).success).toBe(false);
    expect(ChallengeEntrySchema.safeParse({ ...challenge, extra: true }).success).toBe(false);
  });

  it("are settled by reviews naming the challenge's log index, sealed until a panel agrees", () => {
    const review = {
      type: "challenge_review",
      reviewer: "op:4",
      challenge: 12,
      bundle: digest,
      verdict: "upheld",
      evidence: digest,
      model_family: "family-e",
      sig,
    };
    expect(ChallengeReviewEntrySchema.safeParse(review).success).toBe(true);
    expect(ChallengeReviewEntrySchema.safeParse({ ...review, verdict: "maybe" }).success).toBe(false);
    expect(ChallengeReviewEntrySchema.safeParse({ ...review, challenge: -1 }).success).toBe(false);

    const timestamp = "2026-10-04T00:00:00.000Z";
    const logged = { timestamp, operator: "op:3", entry: { ...challenge, sig: signatureDigest(sig) } };
    expect(LogLeafSchema.safeParse(logged).success).toBe(true);
    // A challenge is logged in the clear; a review only with the salt that opens its commitment.
    const revealed = { timestamp, operator: "op:4", entry: { ...review, sig: signatureDigest(sig) } };
    expect(LogLeafSchema.safeParse(revealed).success).toBe(false);
    expect(LogLeafSchema.safeParse({ ...revealed, sealed: { index: 13, salt: "00".repeat(32) } }).success).toBe(true);
  });
});
