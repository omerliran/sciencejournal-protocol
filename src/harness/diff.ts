// Line diffs for a helper reviewing a workshop's next version: what changed in the paper, the
// claims, and the deviations since the version it reviewed, in the unified form reviewers know.

/** One line of a diff: kept (" "), removed ("-"), or added ("+"). */
export type DiffLine = { kind: " " | "-" | "+"; text: string };

/**
 * The shortest edit turning `before` into `after`, line by line (Myers, "An O(ND) difference
 * algorithm", 1986), or null when it would change more than `maxChanged` lines.
 */
export function diffLines(before: readonly string[], after: readonly string[], maxChanged = Infinity): DiffLine[] | null {
  const n = before.length;
  const m = after.length;
  const max = Math.min(n + m, maxChanged);
  const offset = max + 1;
  const v = new Int32Array(2 * max + 3);
  // What v held at the start of each step, from k = -(d + 1) to d + 1, which is all walking back reads.
  const trace: Int32Array[] = [];
  let found = false;
  for (let d = 0; d <= max && !found; d++) {
    trace.push(v.slice(offset - d - 1, offset + d + 2));
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1]) ? v[offset + k + 1] : v[offset + k - 1] + 1;
      let y = x - k;
      while (x < n && y < m && before[x] === after[y]) {
        x++;
        y++;
      }
      v[offset + k] = x;
      if (x >= n && y >= m) {
        found = true;
        break;
      }
    }
  }
  if (!found) return null;
  const lines: DiffLine[] = [];
  let x = n;
  let y = m;
  for (let d = trace.length - 1; d >= 0; d--) {
    const at = (k: number) => trace[d][k + d + 1];
    const k = x - y;
    const previous = k === -d || (k !== d && at(k - 1) < at(k + 1)) ? k + 1 : k - 1;
    const px = at(previous);
    const py = px - previous;
    while (x > px && y > py) {
      x--;
      y--;
      lines.push({ kind: " ", text: before[x] });
    }
    if (d > 0) {
      if (x === px) lines.push({ kind: "+", text: after[--y] });
      else lines.push({ kind: "-", text: before[--x] });
    }
  }
  return lines.reverse();
}

/** Text as lines, with no empty last line for a closing newline. */
const linesOf = (text: string) => (text === "" ? [] : text.replace(/\n$/, "").split("\n"));

/**
 * What changed between two texts as unified-diff hunks, with `context` lines around each change;
 * past `maxChanged` changed lines, only how many of how many changed, at least, since the edit
 * itself isn't worked out.
 */
export function unifiedDiff(
  before: string,
  after: string,
  { context = 3, maxChanged = 300 }: { context?: number; maxChanged?: number } = {},
): { hunks: string; changed: number } | { rewritten: true; changed: number; lines: number } {
  const a = linesOf(before);
  const b = linesOf(after);
  const lines = diffLines(a, b, maxChanged);
  if (lines === null) return { rewritten: true, changed: unmatched(a, b), lines: Math.max(a.length, b.length) };
  const changed = lines.filter((line) => line.kind !== " ").length;
  const hunks: string[] = [];
  let i = 0;
  // Where each line falls in the old and new texts, counted from 1.
  const oldAt: number[] = [];
  const newAt: number[] = [];
  let o = 1;
  let p = 1;
  for (const line of lines) {
    oldAt.push(o);
    newAt.push(p);
    if (line.kind !== "+") o++;
    if (line.kind !== "-") p++;
  }
  while (i < lines.length) {
    if (lines[i].kind === " ") {
      i++;
      continue;
    }
    const start = Math.max(0, i - context);
    let end = i;
    // A hunk runs on while the next change is within two contexts of the last.
    for (let j = i; j < lines.length; j++) {
      if (lines[j].kind !== " ") end = j;
      else if (j - end > 2 * context) break;
    }
    const stop = Math.min(lines.length, end + context + 1);
    const slice = lines.slice(start, stop);
    const oldCount = slice.filter((line) => line.kind !== "+").length;
    const newCount = slice.filter((line) => line.kind !== "-").length;
    hunks.push(`@@ -${oldAt[start]},${oldCount} +${newAt[start]},${newCount} @@`, ...slice.map((line) => `${line.kind}${line.text}`));
    i = stop;
  }
  return { hunks: hunks.join("\n"), changed };
}

/** How many lines of either text the other lacks, counting repeats: the fewest a diff could change. */
function unmatched(a: readonly string[], b: readonly string[]): number {
  const counts = new Map<string, number>();
  for (const line of a) counts.set(line, (counts.get(line) ?? 0) + 1);
  let shared = 0;
  for (const line of b) {
    const left = counts.get(line) ?? 0;
    if (left > 0) {
      shared++;
      counts.set(line, left - 1);
    }
  }
  return a.length + b.length - 2 * shared;
}
