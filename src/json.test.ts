import { describe, expect, it } from "vitest";
import { JsonError, parseJson } from "./json";

const rejects = (text: string, path: string, message: RegExp) => {
  let error: unknown;
  try {
    parseJson(text);
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(JsonError);
  expect((error as JsonError).path).toBe(path);
  expect((error as JsonError).message).toMatch(message);
};

describe("parseJson", () => {
  it("parses ordinary JSON exactly as JSON.parse does", () => {
    const samples = [
      '{"a":1,"b":[true,false,null],"c":{"d":"é"}}',
      '[{"x":1},{"x":2},{"y":{"x":3,"z":{"x":4}}}]',
      '{"a\\"b":1,"a\\\\":2,"}":"{","[":"]"}',
      '  {"nested": [[{"a": 1}, {"a": 2}], {"a": [{"a": 0}]}]}  ',
      '"just a string"',
      "-0.5e-7",
    ];
    for (const text of samples) expect(parseJson(text)).toEqual(JSON.parse(text));
  });

  it("allows the same name in different objects", () => {
    expect(() => parseJson('[{"a":1},{"a":2}]')).not.toThrow();
    expect(() => parseJson('{"a":{"a":{"a":1}}}')).not.toThrow();
  });

  it("rejects duplicate property names, wherever they are", () => {
    rejects('{"confidence":0.1,"confidence":0.9}', "", /Duplicate property name "confidence"/);
    rejects('[{"ok":1},{"local_id":"C1","x":{"a":1,"a":2}}]', "/1/x", /"a"/);
    rejects('{"a":[1,{"b":2,"b":3}]}', "/a/1", /"b"/);
  });

  it("rejects duplicates spelled with different escapes", () => {
    rejects('{"a":1,"\\u0061":2}', "", /Duplicate property name "a"/);
  });

  it("rejects lone surrogates and numbers outside binary64", () => {
    rejects('{"s":"\\ud800"}', "/s", /lone surrogate/);
    rejects('{"\\udc00":1}', "", /lone surrogate/);
    rejects('[1, 1e400]', "/1", /binary64/);
    expect(parseJson('"\\ud83d\\ude00"')).toBe("😀");
  });

  it("agrees with JSON.parse on random documents, and catches injected duplicates", () => {
    let seed = 7;
    const random = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
    const pick = <T>(items: T[]) => items[Math.floor(random() * items.length)];
    const names = ["a", "b", 'q"x', "{", "]", "\\", "é", ",", ":", "\u0000"];
    const value = (depth: number): unknown => {
      const kind = depth > 3 ? pick(["string", "number", "literal"]) : pick(["object", "array", "string", "number", "literal"]);
      if (kind === "string") return pick(names) + pick(names);
      if (kind === "number") return pick([0, -1.5, 1e-7, 1e21, 123]);
      if (kind === "literal") return pick([true, false, null]);
      if (kind === "array") return Array.from({ length: Math.floor(random() * 4) }, () => value(depth + 1));
      const object: Record<string, unknown> = {};
      for (let i = 0; i < Math.floor(random() * 4); i++) object[pick(names)] = value(depth + 1);
      return object;
    };

    for (let n = 0; n < 1000; n++) {
      const document = { root: value(0), [pick(names)]: value(1) };
      const text = JSON.stringify(document, null, n % 2 ? 2 : undefined);
      expect(parseJson(text)).toEqual(JSON.parse(text));
      // Repeat the first property at the end of the top-level object.
      const duplicated = `${text.trimEnd().slice(0, -1)},"root":1}`;
      expect(() => parseJson(duplicated)).toThrow(/Duplicate property name "root"/);
    }
  });

  it("reports syntax errors", () => {
    expect(() => parseJson("{")).toThrow(JsonError);
  });
});
