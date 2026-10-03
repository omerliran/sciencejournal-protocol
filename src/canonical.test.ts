import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import { hashCanonical } from "./hash";

describe("canonicalJson", () => {
  it("matches the RFC 8785 section 3.2.2 example", () => {
    const input = {
      numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001],
      string: "\u20ac$\u000F\nA'B\"\\\\\"/",
      literals: [null, true, false],
    };
    expect(canonicalJson(input)).toBe(
      String.raw`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
    );
  });

  it("is independent of key insertion order", () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe(
      canonicalJson({ a: { c: 3, d: 2 }, b: 1 }),
    );
  });

  it("rejects values with no JSON representation", () => {
    expect(() => canonicalJson(undefined)).toThrow(TypeError);
    expect(() => canonicalJson(Number.NaN)).toThrow();
  });
});

describe("hashCanonical", () => {
  it("is SHA-256 over the canonical UTF-8 bytes", () => {
    const expected = createHash("sha256").update('{"a":"é","b":1}', "utf8").digest("hex");
    expect(hashCanonical({ b: 1, a: "é" })).toBe(expected);
  });
});
