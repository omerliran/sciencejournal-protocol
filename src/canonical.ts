import canonicalize from "canonicalize";

/**
 * RFC 8785 (JSON Canonicalization Scheme) serialization. Every hash and signature in the
 * protocol is computed over this form, so independent implementations agree byte for byte.
 */
export function canonicalJson(value: unknown): string {
  const json = canonicalize(value);
  if (json === undefined) {
    throw new TypeError("Value has no JSON representation");
  }
  return json;
}
