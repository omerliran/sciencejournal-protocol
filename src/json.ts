// Strict JSON parsing for anything the protocol hashes or signs. RFC 8785 builds on I-JSON
// (RFC 7493), which forbids what ordinary parsers quietly accept: duplicate property names
// (parsers disagree on which one wins), lone surrogates, Unicode noncharacters, and numbers
// outside binary64. Accepting them would let two implementations read the same file as
// different claims.

export class JsonError extends Error {
  override name = "JsonError";
  constructor(
    message: string,
    /** JSON Pointer to the offending value, "" for the document itself. */
    readonly path = "",
  ) {
    super(message);
  }
}

/**
 * JSON.parse, but rejecting anything outside I-JSON. Whatever the text, it returns a value or
 * throws a JsonError: the checks keep one entry per value on the heap, not one call per level
 * on the stack, so any depth JSON.parse accepts is checked.
 */
export function parseJson(text: string): unknown {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new JsonError(`Not valid JSON: ${(error as Error).message}`);
  }
  try {
    checkDuplicateNames(text);
    checkValues(value);
  } catch (error) {
    // With no recursion left, a RangeError can only mean the document is too large to check.
    if (error instanceof RangeError) throw new JsonError(`Too large to check: ${error.message}`);
    throw error;
  }
  return value;
}

/**
 * Where a value sits in the document: its parent's place and its own name or index. The JSON
 * Pointer is built only for a value that fails, so deep documents never hold long paths.
 */
interface Place {
  parent: Place | null;
  segment: string | number;
}

const pointer = (place: Place | null): string => {
  const segments: string[] = [];
  for (let at = place; at; at = at.parent) segments.push(String(at.segment).replaceAll("~", "~0").replaceAll("/", "~1"));
  return segments.reverse().map((segment) => `/${segment}`).join("");
};

/** What is left to check, in document order: a value, or a property name within an object. */
type Pending = { value: unknown; place: Place | null } | { name: string; place: Place | null };

function checkValues(root: unknown): void {
  const pending: Pending[] = [{ value: root, place: null }];
  while (pending.length > 0) {
    const next = pending.pop()!;
    if ("name" in next) {
      checkString(next.name, "Property name", next.place);
      continue;
    }
    const { value, place } = next;
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new JsonError("Number is outside the range of a binary64 double", pointer(place));
    }
    if (typeof value === "string") checkString(value, "String", place);
    // Pushed last to first, so they come off in document order, each name before its value.
    if (Array.isArray(value)) {
      for (let i = value.length - 1; i >= 0; i--) pending.push({ value: value[i], place: { parent: place, segment: i } });
    } else if (value !== null && typeof value === "object") {
      const entries = Object.entries(value);
      for (let i = entries.length - 1; i >= 0; i--) {
        const [key, item] = entries[i];
        pending.push({ value: item, place: { parent: place, segment: key } }, { name: key, place });
      }
    }
  }
}

/** RFC 7493 section 2.1: no surrogates or noncharacters in names or string values. */
function checkString(text: string, what: string, place: Place | null): void {
  if (!text.isWellFormed()) throw new JsonError(`${what} contains a lone surrogate`, pointer(place));
  for (const char of text) {
    const code = char.codePointAt(0)!;
    if (isNoncharacter(code)) {
      const hex = code.toString(16).toUpperCase().padStart(4, "0");
      throw new JsonError(`${what} contains the Unicode noncharacter U+${hex}`, pointer(place));
    }
  }
}

/** The 66 noncharacters: U+FDD0 through U+FDEF, and the last two code points of every plane. */
function isNoncharacter(code: number): boolean {
  return (code >= 0xfdd0 && code <= 0xfdef) || (code & 0xfffe) === 0xfffe;
}

type Frame =
  | { kind: "object"; place: Place | null; names: Set<string>; expectName: boolean; name?: string }
  | { kind: "array"; place: Place | null; index: number };

/**
 * Scans already-valid JSON text for an object that repeats a property name. JSON.parse
 * keeps the last duplicate, so this has to look at the text itself.
 */
function checkDuplicateNames(text: string): void {
  const stack: Frame[] = [];
  const childPlace = (): Place | null => {
    const top = stack.at(-1);
    if (!top) return null;
    return { parent: top.place, segment: top.kind === "object" ? (top.name ?? "") : top.index };
  };

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const top = stack.at(-1);
    if (char === '"') {
      let end = i + 1;
      while (text[end] !== '"') end += text[end] === "\\" ? 2 : 1;
      if (top?.kind === "object" && top.expectName) {
        const name = JSON.parse(text.slice(i, end + 1)) as string;
        if (top.names.has(name)) {
          throw new JsonError(`Duplicate property name "${name}"`, pointer(top.place));
        }
        top.names.add(name);
        top.name = name;
        top.expectName = false;
      }
      i = end;
    } else if (char === "{") {
      stack.push({ kind: "object", place: childPlace(), names: new Set(), expectName: true });
    } else if (char === "[") {
      stack.push({ kind: "array", place: childPlace(), index: 0 });
    } else if (char === "}" || char === "]") {
      stack.pop();
    } else if (char === ",") {
      if (top?.kind === "object") top.expectName = true;
      else if (top?.kind === "array") top.index++;
    }
  }
}
