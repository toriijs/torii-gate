/**
 * PKCE — Proof Key for Code Exchange
 *
 * RFC 7636  — https://datatracker.ietf.org/doc/html/rfc7636
 * RFC 9700  — §4: S256 is the only permitted method
 *
 * Web Crypto API only — runs identically on:
 *   Cloudflare Workers, Deno Deploy, Bun, Node.js ≥ 20
 */

import { base64urlEncode, timingSafeEqual } from "./utils";
import { PKCE_CODE_VERIFIER_BYTES } from "./constants";

/** The only PKCE method permitted by RFC 9700 §4 */
export const PKCE_METHOD = "S256" as const;

/**
 * Generates a cryptographically random code_verifier.
 *
 * RFC 7636 §4.1:
 *   - Characters: [A-Z a-z 0-9 - . _ ~] (unreserved per RFC 3986)
 *   - Length: 43–128 characters
 *   - Entropy: minimum 256 bits (32 random bytes)
 */
export function generateCodeVerifier(): Promise<string> {
  const bytes = new Uint8Array(PKCE_CODE_VERIFIER_BYTES);
  crypto.getRandomValues(bytes);
  return Promise.resolve(base64urlEncode(bytes));
}

/**
 * Derives the code_challenge from a code_verifier using S256.
 *
 * RFC 7636 §4.2:
 *   code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))
 */
export async function generateCodeChallenge(
  codeVerifier: string,
): Promise<string> {
  const encoded = new TextEncoder().encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return base64urlEncode(new Uint8Array(digest));
}

/**
 * Verifies that a code_verifier matches a stored code_challenge.
 *
 * Used server-side to validate the token exchange request.
 * Uses HMAC-based comparison to avoid timing oracles.
 */
export async function verifyCodeChallenge(
  codeVerifier: string,
  storedChallenge: string,
): Promise<boolean> {
  if (!codeVerifier || !storedChallenge) return false;

  try {
    const derived = await generateCodeChallenge(codeVerifier);
    return await timingSafeEqual(derived, storedChallenge);
  } catch {
    return false;
  }
}
