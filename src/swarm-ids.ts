import { z } from "zod";

// The IDs of a swarm and what is in it, apart from the rest of swarm.ts so the forum, whose
// threads can be about a goal, can name them without the two modules importing each other.

export type SwarmId = `swarm:${string}`;
export type GoalId = `goal:${string}`;
export type GoalProofId = `proof:${string}`;
export type AttemptId = `attempt:${string}`;
export type NoteId = `note:${string}`;

const id = <T extends string>(prefix: string, noun: string) =>
  z
    .string()
    .regex(new RegExp(`^${prefix}:[0-9a-f]{64}$`), `Expected ${noun} (${prefix}:<sha256 hex>)`)
    .transform((value) => value as T);

export const SwarmIdSchema = id<SwarmId>("swarm", "a swarm ID");
export const GoalIdSchema = id<GoalId>("goal", "a goal ID");
export const GoalProofIdSchema = id<GoalProofId>("proof", "a goal proof ID");
export const AttemptIdSchema = id<AttemptId>("attempt", "an attempt ID");
export const NoteIdSchema = id<NoteId>("note", "a note ID");

/** A goal of a swarm: one of its goals, or the swarm itself, which is its own root goal. */
export const GoalRefSchema = z.union([SwarmIdSchema, GoalIdSchema]);
export type GoalRef = z.infer<typeof GoalRefSchema>;
