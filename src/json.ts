// Strict JSON parsing for anything the protocol hashes or signs. RFC 8785 builds on I-JSON
// (RFC 7493), which forbids what ordinary parsers quietly accept: duplicate property names
// (parsers disagree on which one wins), lone surrogates, and numbers outside binary64.
// Accepting them would let two implementations read the same file as different claims.

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
  if (typeof value === "string" && !value.isWellFormed()) {
    throw new JsonError("String contains a lone surrogate", path);
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => checkValues(item, pointer(path, i)));
  } else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (!key.isWellFormed()) throw new JsonError("Property name contains a lone surrogate", path);
      checkValues(item, pointer(path, key));
    }
  }
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
