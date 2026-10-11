import { join } from "node:path";
import { FILTER_AREAS, type FilterArea } from "../vocabulary";
import { NodeClient, nodeUrl, signAs, signIn, type Credentials } from "./client";
import { HarnessError, type Deps } from "./context";
import { readJsonFile } from "./files";

/** The area a filter's refusal named, as --blocked gives it. */
export function filterArea(value: string | undefined): FilterArea {
  const area = FILTER_AREAS.find((known) => known === value);
  if (!area) {
    throw new HarnessError(
      `Say which area the refusal named: --blocked ${FILTER_AREAS.join("|")}, other when its message names none of the rest.`,
      2,
    );
  }
  return area;
}

/**
 * Hands back a job because the model's provider refused to show it what the job holds: the job in
 * `dir`, or with no directory the one the operator holds, so a new session can hand back a job
 * without opening it again. Nothing in the job is read but its ID.
 */
export async function releaseJob(dir: string | undefined, options: Credentials & { node?: string; blocked?: string }, deps: Deps): Promise<number> {
  const blocked = filterArea(options.blocked);
  let job: string | undefined;
  if (dir) {
    job = (await readJsonFile<{ job?: string }>(join(dir, "job.json")).catch(() => null))?.job;
    if (!job) throw new HarnessError(`${dir} holds no job.json: give a job's directory, or none to hand back the job you hold.`, 2);
  }
  const client = new NodeClient(nodeUrl(options.node, deps), deps);
  const operator = await signIn(options, client, deps);
  const release = signAs(operator, {
    type: "job_release" as const,
    operator: operator.id,
    time: deps.now().toISOString(),
    ...(job && { job }),
    blocked,
  });
  const answer = await client.post<{ job: string; kind: string; blocked: FilterArea }>("/api/v1/jobs/release", release);
  deps.print(
    `Handed back ${answer.job} (${answer.kind}), blocked in ${answer.blocked}. No job about the same work comes to your organization again, and it counts as a job handed back without work. Ask for your next job with ${deps.invocation} job.`,
  );
  return 0;
}
