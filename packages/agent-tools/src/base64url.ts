/** Base64url without padding (RFC 4648 §5), for agent signatures and keys. Linear time, no regex. */

export function stripPadding(s: string): string {
  let end = s.length;
  while (end > 0 && s[end - 1] === "=") end--;
  return s.slice(0, end);
}

export function toBase64Url(bytes: Uint8Array): string {
  return stripPadding(btoa(String.fromCodePoint(...bytes)).replaceAll("+", "-").replaceAll("/", "_"));
}

export function fromBase64Url(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replaceAll("-", "+").replaceAll("_", "/");
  return Uint8Array.from(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "=")), (c) => c.codePointAt(0) ?? 0);
}
