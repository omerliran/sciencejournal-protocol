import { describe, expect, it } from "vitest";
import { spelledNumbers } from "./number-words";

const read = (text: string) => spelledNumbers(text).map(({ text, small }) => [text, small]);

describe("numbers spelled out in words", () => {
  it("reads a compound number as one, however English builds it", () => {
    expect(read("n equals eight hundred thirty-seven thousand seven hundred ninety-nine")).toEqual([
      ["eight hundred thirty-seven thousand seven hundred ninety-nine", false],
    ]);
    expect(read("delay one hundred and eleven, and ten million integers")).toEqual([
      ["one hundred and eleven", false],
      ["ten million", false],
    ]);
    expect(read("Fifty-four records, a dozen runs, and twelve hundred steps")).toEqual([
      ["Fifty-four", false],
      ["dozen", false],
      ["twelve hundred", false],
    ]);
    expect(read("the twenty-first run and the one hundred and first")).toEqual([
      ["twenty-first", false],
      ["one hundred and first", false],
    ]);
  });

  it("reads decimals, fractions, and percentages", () => {
    expect(read("three point one four, two thirds, one third, nine tenths, and three quarters")).toEqual([
      ["three point one four", false],
      ["two thirds", false],
      ["one third", false],
      ["nine tenths", false],
      ["three quarters", false],
    ]);
    // "a" counts one part as "one" does, before "of"; otherwise "a third" is an ordinal.
    expect(read("about a third of the runs, a quarter of them, and a half of those; a third attempt")).toEqual([
      ["a third", false],
      ["a quarter", false],
      ["a half", false],
      ["third", true],
    ]);
    expect(read("five percent, five per cent, and three point five percent")).toEqual([
      ["five percent", false],
      ["five per cent", false],
      ["three point five percent", false],
    ]);
  });

  it("marks the single words for zero to nine and first to ninth as small", () => {
    expect(read("two methods agree on the third claim")).toEqual([
      ["two", true],
      ["third", true],
    ]);
    // "One second" is a time, not a half; an ordinal ends a number.
    expect(read("one second, the first two")).toEqual([
      ["one", true],
      ["second", true],
      ["first", true],
      ["two", true],
    ]);
  });

  it("joins words only across white space or one hyphen, and only in a number's order", () => {
    expect(read("nine, ten")).toEqual([
      ["nine", true],
      ["ten", false],
    ]);
    expect(read("two three")).toEqual([
      ["two", true],
      ["three", true],
    ]);
    expect(read("two and three, at one point the")).toEqual([
      ["two", true],
      ["three", true],
      ["one", true],
    ]);
    expect(read("one-hundred\ntrials")).toEqual([["one-hundred", false]]);
  });

  it("leaves out words that only contain number words, plurals that say roughly how many, and fractions without a count", () => {
    expect(read("Someone often tones a network; hundreds of runs, thousands of tens, and half the claims.")).toEqual([]);
  });

  it("gives each number's place in the text", () => {
    const text = "Up by twenty-seven points.";
    const [found] = spelledNumbers(text);
    expect(text.slice(found.start, found.end)).toBe("twenty-seven");
  });
});
