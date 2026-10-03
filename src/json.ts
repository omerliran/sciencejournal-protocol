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

/** JSON.parse, but rejecting anything outside I-JSON. */
export function parseJson(text: string): unknown {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new JsonError(`Not valid JSON: ${(error as Error).message}`);
  }
  checkDuplicateNames(text);
  checkValues(value, "");
  return value;
}

const pointer = (path: string, segment: string | number) =>
  `${path}/${String(segment).replaceAll("~", "~0").replaceAll("/", "~1")}`;

function checkValues(value: unknown, path: string): void {
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new JsonError("Number is outside the range of a binary64 double", path);
  }
  if (typeof value === "string") checkString(value, "String", path);
  if (Array.isArray(value)) {
    value.forEach((item, i) => checkValues(item, pointer(path, i)));
  } else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      checkString(key, "Property name", path);
      checkValues(item, pointer(path, key));
    }
  }
}

/** RFC 7493 section 2.1: no surrogates or noncharacters in names or string values. */
function checkString(text: string, what: string, path: string): void {
  if (!text.isWellFormed()) throw new JsonError(`${what} contains a lone surrogate`, path);
  for (const char of text) {
    const code = char.codePointAt(0)!;
    if (isNoncharacter(code)) {
      const hex = code.toString(16).toUpperCase().padStart(4, "0");
      throw new JsonError(`${what} contains the Unicode noncharacter U+${hex}`, path);
    }
  }
}

/** The 66 noncharacters: U+FDD0 through U+FDEF, and the last two code points of every plane. */
function isNoncharacter(code: number): boolean {
  return (code >= 0xfdd0 && code <= 0xfdef) || (code & 0xfffe) === 0xfffe;
}

type Frame =
  | { kind: "object"; path: string; names: Set<string>; expectName: boolean; name?: string }
  | { kind: "array"; path: string; index: number };

/**
 * Scans already-valid JSON text for an object that repeats a property name. JSON.parse
 * keeps the last duplicate, so this has to look at the text itself.
 */
function checkDuplicateNames(text: string): void {
  const stack: Frame[] = [];
  const childPath = () => {
    const top = stack.at(-1);
    if (!top) return "";
    return top.kind === "object" ? pointer(top.path, top.name ?? "") : pointer(top.path, top.index);
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
          throw new JsonError(`Duplicate property name "${name}"`, top.path);
        }
        top.names.add(name);
        top.name = name;
        top.expectName = false;
      }
      i = end;
    } else if (char === "{") {
      stack.push({ kind: "object", path: childPath(), names: new Set(), expectName: true });
    } else if (char === "[") {
      stack.push({ kind: "array", path: childPath(), index: 0 });
    } else if (char === "}" || char === "]") {
      stack.pop();
    } else if (char === ",") {
      if (top?.kind === "object") top.expectName = true;
      else if (top?.kind === "array") top.index++;
    }
  }
}
