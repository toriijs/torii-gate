/**
 * PKCE State Cookie — Stateless Login State
 *
 * Stores the PKCE code_verifier, nonce, and state inside an encrypted
 * HttpOnly cookie sent during the login redirect. On callback, the values
 * are read back from the cookie — no server-side state required.
 *
 * This solves the scale-to-zero / horizontal-scaling problem:
 *   - Module-scope Maps are lost when an isolate dies or a new instance starts
 *   - A Redis store adds infrastructure dependency
 *   - An encrypted cookie is stateless, works on any edge runtime,
 *     and requires zero extra infrastructure
 *
 * Security properties:
 *   - AES-GCM-256 encryption — cookie value is opaque, tamper-evident
 *   - Short Max-Age (default 10 minutes) — matches PKCE flow TTL
 *   - HttpOnly, Secure, SameSite=Lax (Lax required — callback is a redirect)
 *   - Cookie is deleted on callback — single use enforced
 *
 * This is the same pattern used by auth0-spa-js, NextAuth.js, and
 * the IETF draft for browser-based apps.
 *
 * Cookie name: __Host-torii-pkce
 *
 * References:
 *   RFC 9700 §4.7  — state and nonce requirements
 *   RFC 7636       — PKCE
 */

import { base64urlDecode, base64urlEncode, extractCookieValue } from './utils';
import { AES_GCM_IV_BYTES, PKCE_PENDING_TTL_SECONDS } from './constants';

/** Data stored in the PKCE state cookie */
export interface PkceStateCookieData {
  /** PKCE code_verifier — submitted on token exchange */
  codeVerifier: string;
  /** Raw nonce — validated against ID token nonce claim */
  nonce: string;
  /** State value — validated against callback state param */
  state: string;
  /** Expiry timestamp (ms) */
  expiresAt: number;
}

export interface PkceStateCookieOptions {
  /**
   * Secret for AES-GCM encryption.
   * Must be the same secret used for session encryption so we don't need
   * a separate key — the session secret is already required.
   */
  secret: string;
  /** Max-Age in seconds — defaults to 600 (10 minutes) */
  maxAge?: number;
}

const COOKIE_NAME = '__Host-torii-pkce' as const;

/**
 * Builds the Set-Cookie header for the PKCE state cookie.
 * Called during login — sent alongside the redirect to the provider.
 *
 * SameSite=Lax is required (not Strict) because the callback is a
 * top-level navigation redirect from the provider — SameSite=Strict
 * would cause the browser to not send the cookie on that redirect.
 */
export async function buildPkceStateCookie(data: PkceStateCookieData, options: PkceStateCookieOptions): Promise<string> {
  const key = await deriveKey(options.secret);
  const encrypted = await encrypt(data, key);
  const maxAge = options.maxAge ?? PKCE_PENDING_TTL_SECONDS;

  return [
    `${COOKIE_NAME}=${encrypted}`,
    `Max-Age=${maxAge}`,
    `Path=/`,
    `Secure`,
    `HttpOnly`,
    `SameSite=Lax`, // Lax — must travel on the provider redirect callback
  ].join('; ');
}

/**
 * Reads and decrypts the PKCE state cookie from a Cookie header.
 * Returns null if missing, expired, or tampered.
 *
 * Call this during the callback before validating state/nonce.
 */
export async function readPkceStateCookie(cookieHeader: string, secret: string): Promise<PkceStateCookieData | null> {
  const value = extractCookieValue(cookieHeader, COOKIE_NAME);
  if (!value) return null;

  try {
    const key = await deriveKey(secret);
    const data = await decrypt(value, key);

    if (Date.now() > data.expiresAt) return null;

    return data;
  } catch {
    // Tampered or malformed — treat as missing
    return null;
  }
}

/**
 * Builds a Set-Cookie header that immediately clears the PKCE state cookie.
 * Called after callback processing — whether success or failure.
 */
export function clearPkceStateCookie(): string {
  return [`${COOKIE_NAME}=`, `Max-Age=0`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`].join('; ');
}

async function deriveKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode('torii-pkce-state-v1'),
      info: encoder.encode('pkce-state-encryption'),
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encrypt(data: PkceStateCookieData, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);

  const combined = new Uint8Array(AES_GCM_IV_BYTES + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), AES_GCM_IV_BYTES);

  return base64urlEncode(combined);
}

async function decrypt(value: string, key: CryptoKey): Promise<PkceStateCookieData> {
  const combined = base64urlDecode(value);
  if (combined.length <= AES_GCM_IV_BYTES) throw new Error('Too short');

  const iv = combined.slice(0, AES_GCM_IV_BYTES);
  const ciphertext = combined.slice(AES_GCM_IV_BYTES);

  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plaintext)) as PkceStateCookieData;
}
