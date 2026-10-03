// Unpadded base64url (RFC 4648, section 5), the encoding WebAuthn uses for binary values.
// atob and btoa exist in browsers and in Node, so this stays dependency-free.

export function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** Throws on input that isn't base64url; validate with z.base64url() first. */
export function base64urlToBytes(value: string): Uint8Array {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "="));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
