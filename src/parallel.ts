// Work done a few at a time, for the harness, the monitor, and the mirror; never exported from
// the index, since it says nothing about the protocol.

/** Runs `work` on each item with at most `limit` at once, keeping the results in order. */
export async function inParallel<T, R>(items: readonly T[], limit: number, work: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await work(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
