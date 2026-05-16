/**
 * Nonce
 *
 * OpenID Connect Core 1.0 — §3.1.2.1, §3.1.3.7
 * RFC 9700  — §4.7: replay attack prevention
 *
 * The nonce sent in the authorization request is hashed before storage.
 * On callback, the nonce in the ID token is hashed and compared to the
 * stored hash. This means the raw nonce never persists server-side —
 * only its SHA-256 hash is stored.
 */

import { base64urlEncode } from "./utils";
import { NONCE_BYTES } from "./constants";

/**
 * Generates a cryptographically random nonce.
 * 16 random bytes → ~22 chars base64url → 128 bits entropy.
 *
 * This primitive is used internally by PendingAuthStore implementations.
 */
export function generateNonce(): Promise<string> {
  const bytes = new Uint8Array(NONCE_BYTES);
  crypto.getRandomValues(bytes);
  return Promise.resolve(base64urlEncode(bytes));
}

/**
 * SHA-256 hashes a nonce value for safe server-side storage.
 *
 * The raw nonce travels in the authorization request URL (potentially logged).
 * Storing only the hash means a log leak doesn't expose a reusable nonce.
 *
 * Used internally by PendingAuthStore implementations to validate nonces
 * from ID tokens without storing the raw value.
 */
export async function hashNonce(nonce: string): Promise<string> {
  const encoded = new TextEncoder().encode(nonce);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return base64urlEncode(new Uint8Array(digest));
}
