// Numbers spelled out in English words, read the way a reader reads them, so a result written
// as "eight hundred thirty-seven thousand" is found like one typed in digits. English number
// words are a closed class: the units, teens, and tens, the scales, their ordinals, and the
// fractions made from them, so this is the whole vocabulary, not a guess at it. Papers here
// are written in English.
//
// A word is a run of letters and marks. Words join into one number across white space or a
// single hyphen, never across other punctuation, and only in the orders English builds numbers
// in: "twenty-seven", "one hundred and eleven", "two thirds", "three point one four", "five
// percent", and "a third of", where "a" counts one part as "one" does, though "a third run" is
// an ordinal. Plurals such as "hundreds" or "thousands" say roughly how many rather than giving
// a value, so they aren't numbers here.

const UNITS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"];
const TEENS = ["ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"];
const TENS = ["twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"];
/** Words that multiply what comes before them, as in "two hundred" or "two dozen". */
const SCALES = ["hundred", "thousand", "million", "billion", "trillion", "quadrillion", "quintillion", "dozen"];
const SMALL_ORDINALS = ["zeroth", "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth"];
const LARGE_ORDINALS = [
  ...["tenth", "eleventh", "twelfth", "thirteenth", "fourteenth", "fifteenth", "sixteenth", "seventeenth", "eighteenth", "nineteenth"],
  ...["twentieth", "thirtieth", "fortieth", "fiftieth", "sixtieth", "seventieth", "eightieth", "ninetieth"],
  ...["hundredth", "thousandth", "millionth", "billionth", "trillionth"],
];
/** Ordinals that name a fraction's parts after "one", as in "one third"; "one second" is a time. */
const PARTS = new Set(SMALL_ORDINALS.slice(3));
/** The other words for one part of a whole, as in "a quarter of". */
const ONE_PART = new Set(["half", "quarter"]);

type Kind = "unit" | "teen" | "ten" | "scale" | "small_ordinal" | "large_ordinal" | "denominator";

const KINDS = new Map<string, Kind>([
  ...UNITS.map((word) => [word, "unit"] as const),
  ...TEENS.map((word) => [word, "teen"] as const),
  ...TENS.map((word) => [word, "ten"] as const),
  ...SCALES.map((word) => [word, "scale"] as const),
  ...SMALL_ORDINALS.map((word) => [word, "small_ordinal"] as const),
  ...LARGE_ORDINALS.map((word) => [word, "large_ordinal"] as const),
  // What a fraction is counted in, after a number: "one half", "three quarters", "two thirds", "nine tenths".
  ...["half", "halves", "quarter", "quarters", ...[...PARTS, ...LARGE_ORDINALS].map((word) => `${word}s`)].map(
    (word) => [word, "denominator"] as const,
  ),
]);

const CARDINAL = new Set<Kind | undefined>(["unit", "teen", "ten", "scale"]);
/** Kinds after which a number is complete: "the twenty-first", "two thirds". */
const FINAL = new Set<Kind | undefined>(["small_ordinal", "large_ordinal", "denominator"]);

export interface SpelledNumber {
  /** Where it starts and ends in the text, as string offsets. */
  start: number;
  end: number;
  /** As written: "one hundred and eleven", "two thirds", "five percent". */
  text: string;
  /**
   * Whether it is one word for zero to nine, or for first to ninth: the counts prose spells out
   * by convention, such as "two methods" or "the third claim".
   */
  small: boolean;
}

const WORD = /[\p{L}\p{M}]+/gu;
/** What may sit between two words of one number: white space, or one hyphen and nothing else. */
const JOIN = /^(?:\s+|[-‐‑])$/u;

/** Every number spelled out in English words in `text`, in order. */
export function spelledNumbers(text: string): SpelledNumber[] {
  const words = [...text.matchAll(WORD)].map((m) => ({ word: m[0].toLowerCase(), start: m.index, end: m.index + m[0].length }));
  /** Whether word i and the one after it can belong to one number. */
  const joined = (i: number) => i + 1 < words.length && JOIN.test(text.slice(words[i].end, words[i + 1].start));
  const kind = (i: number) => (i < words.length ? KINDS.get(words[i].word) : undefined);
  const is = (i: number, word: string) => i < words.length && words[i].word === word;
  const found: SpelledNumber[] = [];

  for (let i = 0; i < words.length; i++) {
    // "a third of", "a quarter of", "a half of": a fraction, as "one third" is.
    if (is(i, "a") && joined(i) && (PARTS.has(words[i + 1].word) || ONE_PART.has(words[i + 1].word)) && joined(i + 1) && is(i + 2, "of")) {
      found.push({ start: words[i].start, end: words[i + 1].end, text: text.slice(words[i].start, words[i + 1].end), small: false });
      i += 1;
      continue;
    }
    // A number starts with a number word; a denominator, "and", "point", or "percent" can't start one.
    if (kind(i) === undefined || kind(i) === "denominator") continue;
    let last = i;
    while (!FINAL.has(kind(last)) && joined(last)) {
      if (follows(words[last].word, kind(last)!, kind(last + 1), words[last + 1].word)) {
        last += 1;
      } else if (is(last + 1, "and") && kind(last) === "scale" && joined(last + 1) && ANDED.has(kind(last + 2))) {
        // "one hundred and eleven", "one hundred and first"
        last += 2;
      } else if (is(last + 1, "point") && CARDINAL.has(kind(last)) && joined(last + 1) && kind(last + 2) === "unit") {
        // "three point one four": the digits after the point are said one at a time.
        last += 2;
        while (joined(last) && kind(last + 1) === "unit") last += 1;
        break;
      } else break;
    }
    // "five percent", "five per cent": a share, whatever the number.
    let percent = 0;
    if (CARDINAL.has(kind(last)) && joined(last)) {
      if (is(last + 1, "percent")) percent = 1;
      else if (is(last + 1, "per") && joined(last + 1) && is(last + 2, "cent")) percent = 2;
    }
    const end = last + percent;
    found.push({
      start: words[i].start,
      end: words[end].end,
      text: text.slice(words[i].start, words[end].end),
      small: end === i && (kind(i) === "unit" || kind(i) === "small_ordinal"),
    });
    i = end;
  }
  return found;
}

/** What may follow "and" in a number. */
const ANDED = new Set<Kind | undefined>(["unit", "teen", "ten", "small_ordinal", "large_ordinal"]);

/** Whether a word of kind `next` can follow one of kind `previous` within a number, as English builds them. */
function follows(previousWord: string, previous: Kind, next: Kind | undefined, nextWord: string): boolean {
  switch (previous) {
    case "ten":
      // "twenty-seven", "twenty thousand", "twenty-first", "twenty thousandth"
      return next === "unit" || next === "scale" || next === "small_ordinal" || next === "large_ordinal";
    case "unit":
    case "teen":
      // "two hundred", "twelve hundred", "one hundredth", "nine tenths", "two thirds", and "one third"
      return (
        next === "scale" ||
        next === "large_ordinal" ||
        next === "denominator" ||
        (next === "small_ordinal" && previousWord === "one" && PARTS.has(nextWord))
      );
    case "scale":
      // "hundred eleven", "hundred thousand", "hundred first", "two hundred thousandths"
      return next !== undefined;
    default:
      return false;
  }
}
