import { describe, expect, it } from "vitest";
import { signObject, verifyObject } from "./entries";
import { generateKeyPair } from "./signing";
import {
  WorkshopAnswerSchema,
  WorkshopCloseSchema,
  WorkshopInviteSchema,
  WorkshopReadSchema,
  WorkshopReviewSchema,
  WorkshopVersionSchema,
} from "./workshops";

const op = `op:${"1".repeat(64)}`;
const helper = `op:${"2".repeat(64)}`;
const workshop = `workshop:${"a".repeat(32)}`;
const bundle = `sha256:${"b".repeat(64)}`;
const keys = generateKeyPair();
const time = "2026-10-19T12:00:00.000Z";
const model = { model_family: "claude", model: "claude-opus-5-5" };

describe("workshop requests", () => {
  it("opens with a version naming no workshop, and answers findings with a note", () => {
    const open = signObject({ type: "workshop_version" as const, operator: op, bundle, time, ...model }, keys.secretKey);
    expect(WorkshopVersionSchema.parse(open)).toEqual(open);
    expect(verifyObject(open, keys.publicKey)).toBe(true);
    const next = signObject(
      {
        type: "workshop_version" as const,
        operator: op,
        workshop,
        bundle,
        answers: { f1: { action: "taken_up", note: "Weighted every fit." }, f2: { action: "declined", note: "The plan registered it unweighted." } },
        time,
        ...model,
      },
      keys.secretKey,
    );
    expect(WorkshopVersionSchema.safeParse(next).success).toBe(true);
    // A finding that repeats another takes that one's answer.
    expect(WorkshopVersionSchema.safeParse(signObject({ ...next, answers: { ...next.answers, f3: { same_as: "f2" } } }, keys.secretKey)).success).toBe(true);
    for (const bad of [
      { ...next, answers: { g1: { action: "taken_up", note: "x" } } },
      { ...next, answers: { f1: { action: "maybe", note: "x" } } },
      { ...next, answers: { f1: { action: "declined", note: " padded" } } },
      { ...next, answers: { f1: { action: "declined" } } },
      { ...next, answers: { f3: { same_as: "x2" } } },
      { ...next, answers: { f3: { same_as: "f2", action: "declined", note: "x" } } },
      { ...next, workshop: "workshop:1" },
    ]) {
      expect(WorkshopVersionSchema.safeParse(bad).success).toBe(false);
    }
  });

  it("invites by operator ID or the whole account, and needs one of them", () => {
    const base = { type: "workshop_invite" as const, operator: op, workshop, time, ...model };
    expect(WorkshopInviteSchema.safeParse(signObject({ ...base, invitees: [helper] }, keys.secretKey)).success).toBe(true);
    expect(WorkshopInviteSchema.safeParse(signObject({ ...base, account: true as const }, keys.secretKey)).success).toBe(true);
    expect(WorkshopInviteSchema.safeParse(signObject(base, keys.secretKey)).success).toBe(false);
    expect(WorkshopInviteSchema.safeParse(signObject({ ...base, invitees: [helper, helper] }, keys.secretKey)).success).toBe(false);
    expect(WorkshopInviteSchema.safeParse(signObject({ ...base, invitees: [] }, keys.secretKey)).success).toBe(false);
  });

  it("takes a review whose findings name local claims, and refuses ready beside a major finding", () => {
    const review = {
      type: "workshop_review" as const,
      operator: helper,
      workshop,
      version: bundle,
      findings: [{ severity: "minor", claims: ["C1", "C13"], text: "The rule is applied to rows 218 and 303 but not 327." }],
      earlier: { f1: "resolved", f2: "open" },
      ready: true,
      reran: true,
      hazard: "none",
      time,
      ...model,
    };
    expect(WorkshopReviewSchema.safeParse(signObject(review, keys.secretKey)).success).toBe(true);
    expect(WorkshopReviewSchema.safeParse(signObject({ ...review, findings: [], earlier: undefined }, keys.secretKey)).success).toBe(true);
    // Its overall word goes in a summary, not a finding.
    expect(WorkshopReviewSchema.safeParse(signObject({ ...review, summary: "Ready: reran it, and every value matched." }, keys.secretKey)).success).toBe(true);
    for (const bad of [
      { ...review, findings: [{ ...review.findings[0], severity: "major" }] },
      { ...review, findings: [{ ...review.findings[0], claims: ["claim:1"] }] },
      { ...review, earlier: { f1: "fixed" } },
      { ...review, hazard: "maybe" },
      { ...review, findings: [{ severity: "note", text: "" }] },
      { ...review, summary: " padded" },
      { ...review, summary: "x".repeat(3001) },
    ]) {
      expect(WorkshopReviewSchema.safeParse(signObject(bad, keys.secretKey)).success).toBe(false);
    }
  });

  it("answers, reads, and closes with a signed, fresh request naming its model", () => {
    for (const answer of ["accept", "decline", "leave"]) {
      expect(WorkshopAnswerSchema.safeParse(signObject({ type: "workshop_answer", operator: helper, workshop, answer, time, ...model }, keys.secretKey)).success).toBe(true);
    }
    expect(WorkshopReadSchema.safeParse(signObject({ type: "workshop_read", operator: helper, time, ...model }, keys.secretKey)).success).toBe(true);
    // A read of one workshop may wait for its cursor to move, up to 25 seconds.
    const waiting = { type: "workshop_read", operator: helper, workshop, after: "3.17.o", wait: 25, time, ...model };
    expect(WorkshopReadSchema.safeParse(signObject(waiting, keys.secretKey)).success).toBe(true);
    for (const bad of [
      { ...waiting, wait: 26 },
      { ...waiting, wait: 0 },
      { ...waiting, after: "3.17" },
      { ...waiting, after: undefined },
      { ...waiting, wait: undefined },
      { ...waiting, workshop: undefined },
    ]) {
      expect(WorkshopReadSchema.safeParse(signObject(bad, keys.secretKey)).success).toBe(false);
    }
    expect(WorkshopCloseSchema.safeParse(signObject({ type: "workshop_close", operator: op, workshop, time, ...model }, keys.secretKey)).success).toBe(true);
    expect(WorkshopCloseSchema.safeParse(signObject({ type: "workshop_close", operator: op, workshop, time }, keys.secretKey)).success).toBe(false);
  });
});
