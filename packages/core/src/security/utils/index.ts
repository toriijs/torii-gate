export function escapeRegex(str: string): string {
  return str.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

/**
 * Extract a cookie value from a Cookie header string
 * @param cookieHeader - The Cookie header value
 * @param name - The cookie name to extract
 * @returns The cookie value or null if not found
 */
export function extractCookieValue(cookieHeader: string, name: string): string | null {
  if (!cookieHeader) return null;
  const pattern = new RegExp(String.raw`(?:^|;\s*)${escapeRegex(name)}=([^;]+)`);
  return pattern.exec(cookieHeader)?.[1] ?? null;
}

/**
 * BASE64URL encoding without padding.
 * RFC 7636 §4.1 / RFC 4648 §5
 *
 */
export function base64urlEncode(bytes: Uint8Array): string {
  const binary = Array.from(bytes, (b) => String.fromCodePoint(b)).join("");
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export function base64urlDecode(value: string): Uint8Array {
  const base64 = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(value.length + ((4 - (value.length % 4)) % 4), "=");
  const binary = atob(base64);
  return new Uint8Array(Array.from(binary, (c) => c.codePointAt(0) ?? 0));
}

/**
 * Timing-safe string comparison using HMAC-SHA256.
 *
 * Direct character-by-character comparison leaks the position of the first
 * differing character through timing. HMAC-based comparison avoids this.
 */
export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const [macA, macB] = await Promise.all([
    crypto.subtle.sign("HMAC", key, encoder.encode(a)),
    crypto.subtle.sign("HMAC", key, encoder.encode(b)),
  ]);

  const viewA = new Uint8Array(macA);
  const viewB = new Uint8Array(macB);

  if (viewA.length !== viewB.length) return false;

  let diff = 0;
  for (let i = 0; i < viewA.length; i++) {
    diff |= (viewA[i] ?? 0) ^ (viewB[i] ?? 0);
  }

  return diff === 0;
}
