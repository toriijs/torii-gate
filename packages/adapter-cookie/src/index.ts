/**
 * Cookie Session Adapter
 *
 * Stores the entire session payload encrypted inside the cookie value itself.
 * Stateless — no server-side storage required.
 *
 * Security properties:
 *   - AES-GCM-256 encryption (authenticated — integrity + confidentiality)
 *   - Random 96-bit IV per encrypt operation — no IV reuse
 *   - Key derived via HKDF-SHA256 from the configured secret
 *   - Cookie value is opaque to the browser — cannot be read or tampered
 *   - Tokens inside the cookie satisfy RFC 9700's "not accessible to JavaScript"
 *     requirement — HttpOnly + AES-GCM means raw tokens are never readable
 *
 * RFC 9700 compliance note:
 *   The spec's primary concern is that tokens are not accessible to JavaScript.
 *   HttpOnly + AES-GCM satisfies this. The "server-side storage" recommendation
 *   refers to the ideal — encrypted cookies are an explicitly documented
 *   alternative for stateless deployments (oauth2-proxy default behaviour).
 *
 * 4KB limit and partitioning:
 *   Browsers enforce a 4096-byte per-cookie limit (RFC 6265). A Keycloak
 *   session with many claims can easily produce access + ID + refresh tokens
 *   totalling 3–8KB before encryption. AES-GCM adds ~50 bytes, base64url
 *   expansion adds ~33% — a 4KB token payload becomes ~5.5KB.
 *
 *   This adapter automatically partitions large payloads across multiple
 *   __Host- cookies: __Host-session.0, __Host-session.1, __Host-session.2
 *   Each chunk is independently encrypted with AES-GCM.
 *
 *   On GET (read), the adapter reassembles chunks in order before decrypting.
 *   On DELETE, all chunk cookies are cleared.
 *
 *   The number of Set-Cookie headers returned by set() varies with payload
 *   size — callers must apply all headers from the returned array.
 *
 * Trade-off vs Redis:
 *   + Zero infrastructure dependency
 *   + Scales to zero cost
 *   - Cannot revoke before cookie expires (max 15 min with default config)
 *   - Requires sending/reading multiple cookies for large token payloads
 *   → For high-throughput production deployments, prefer RedisAdapter
 *
 * Web Crypto API only — runs identically on all edge runtimes.
 */

import type { SessionAdapter, SessionData, CookieOptions } from '@torii-gate/core/adapters/interface';

export interface CookieAdapterOptions {
  /**
   * Secret used to derive the AES-GCM encryption key via HKDF.
   * Minimum 32 characters. Changing this invalidates all existing sessions.
   */
  secret: string;
  /** Session TTL in seconds — defaults to 900 (15 minutes) */
  maxAge?: number | undefined;
  /**
   * Maximum bytes per cookie chunk — defaults to 3072 (3KB).
   * Keeps each chunk safely under the 4096-byte browser limit after
   * AES-GCM overhead (~50 bytes) and base64url expansion (~33%).
   *
   * 3072 raw bytes → ~4096 bytes base64url → within the 4KB limit.
   * Reduce this value if your reverse proxy enforces a stricter limit.
   */
  chunkSize?: number | undefined;
  /**
   * Base cookie name — must start with __Host-.
   * Chunk cookies are named <cookieName>.0, <cookieName>.1, etc.
   * Single-chunk sessions use the base name without a suffix.
   */
  cookieName?: `__Host-${string}` | undefined;
}

const DEFAULT_MAX_AGE = 900;
const DEFAULT_CHUNK = 3072; // 3KB raw → ~4KB after base64url
const DEFAULT_COOKIE = '__Host-session' as const;
const IV_BYTES = 12; // 96-bit IV — AES-GCM standard
const KEY_SALT = 'torii-cookie-adapter-v1';
const KEY_INFO = 'session-encryption';

export class CookieAdapter implements SessionAdapter {
  readonly #secret: string;
  readonly #maxAge: number;
  readonly #chunkSize: number;
  readonly #cookieName: string;
  #key: CryptoKey | null = null;

  constructor(options: CookieAdapterOptions) {
    if (options.secret.length < 32) {
      throw new Error(`CookieAdapter secret must be at least 32 characters (got ${options.secret.length})`);
    }
    this.#secret = options.secret;
    this.#maxAge = options.maxAge ?? DEFAULT_MAX_AGE;
    this.#chunkSize = options.chunkSize ?? DEFAULT_CHUNK;
    this.#cookieName = options.cookieName ?? DEFAULT_COOKIE;
  }

  /**
   * Extracts session from HTTP request by parsing Cookie header.
   *
   * Finds all chunk cookies (__Host-session.0, .1, .2), reassembles them,
   * then decrypts the session data.
   *
   * Returns null if no session found, decryption fails, or session is expired.
   */
  async get(request: Request): Promise<SessionData | null> {
    const cookieHeader = request.headers.get('cookie') ?? '';
    if (!cookieHeader) return null;

    try {
      const key = await this.#getKey();
      const assembled = assembleChunks(cookieHeader, this.#cookieName);
      if (!assembled) return null;

      const data = await decrypt(assembled, key);
      if (Date.now() > data.expiresAt) return null;

      return data;
    } catch {
      return null;
    }
  }

  /**
   * Encrypts session data and returns Set-Cookie headers ready to send.
   *
   * Returns an array — may be 1 header for small sessions, or multiple
   * for large token payloads (chunking). Caller must send ALL headers.
   *
   * @param sessionData - The session data to encrypt
   * @param options - Cookie configuration (name, maxAge, topology, domain)
   * @returns Array of Set-Cookie header strings
   */
  async set(sessionData: SessionData, options: CookieOptions): Promise<string[]> {
    const key = await this.#getKey();
    const encoded = await encrypt(sessionData, key);
    const chunks = splitIntoChunks(encoded, this.#chunkSize);

    const { cookieName, maxAge, topology, cookieDomain } = options;
    const sameSite = topology === 'same-domain' ? 'Strict' : 'Lax';
    const domainAttr = topology === 'subdomain' && cookieDomain ? `; Domain=${cookieDomain}` : '';

    if (chunks.length === 1) {
      // Small payload — single cookie, no suffix
      const chunk = chunks[0];
      if (!chunk) throw new Error('Chunk array is empty');
      return [buildCookieHeaderWithOptions(cookieName, chunk, maxAge, sameSite, domainAttr)];
    }

    // Large payload — numbered chunk cookies
    return chunks.map((chunk, i) => buildCookieHeaderWithOptions(`${cookieName}.${i}`, chunk, maxAge, sameSite, domainAttr));
  }

  /**
   * Deletes session and returns Set-Cookie headers that clear all cookies.
   *
   * Handles both single-cookie and chunked-cookie sessions.
   *
   * @param request - The incoming HTTP request (contains cookies to clear)
   * @param options - Cookie configuration (needed for correct clear headers)
   * @returns Array of Set-Cookie headers with Max-Age=0
   */
  delete(request: Request, options: CookieOptions): Promise<string[]> {
    const cookieHeader = request.headers.get('cookie') ?? '';
    const headers: string[] = [];
    const cookieName = options.cookieName;
    const topology = options.topology;
    const sameSite = topology === 'same-domain' ? 'Strict' : 'Lax';
    const domainAttr = topology === 'subdomain' && options.cookieDomain ? `; Domain=${options.cookieDomain}` : '';

    if (cookieHeader) {
      // Clear exactly the chunks present in the request
      const chunkCount = countChunks(cookieHeader, cookieName);

      if (chunkCount === 0) {
        // Single un-chunked cookie
        headers.push(clearCookieHeaderWithOptions(cookieName, sameSite, domainAttr));
      } else {
        for (let i = 0; i < chunkCount; i++) {
          headers.push(clearCookieHeaderWithOptions(`${cookieName}.${i}`, sameSite, domainAttr));
        }
      }
    } else {
      // No request context — defensively clear base + chunks 0–9
      headers.push(clearCookieHeaderWithOptions(cookieName, sameSite, domainAttr));
      for (let i = 0; i < 10; i++) {
        headers.push(clearCookieHeaderWithOptions(`${cookieName}.${i}`, sameSite, domainAttr));
      }
    }

    return Promise.resolve(headers);
  }

  /**
   * Encrypts SessionData and returns all Set-Cookie headers needed.
   *
   * This is the CookieAdapter-specific API used by BFF entry points.
   * Returns an array because large payloads produce multiple chunk cookies.
   *
   *   const headers = await adapter.buildSetCookieHeaders(sessionData)
   *   headers.forEach(h => response.headers.append('set-cookie', h))
   */
  async buildSetCookieHeaders(data: SessionData): Promise<string[]> {
    const key = await this.#getKey();
    const encoded = await encrypt(data, key);
    const chunks = splitIntoChunks(encoded, this.#chunkSize);
    const maxAge = this.#maxAge;

    if (chunks.length === 1) {
      // Small payload — single cookie, no suffix
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      return [buildCookieHeader(this.#cookieName, chunks[0]!, maxAge)];
    }

    // Large payload — numbered chunk cookies
    return chunks.map((chunk, i) => buildCookieHeader(`${this.#cookieName}.${i}`, chunk, maxAge));
  }

  /**
   * Returns Set-Cookie headers that immediately clear all session cookies.
   * Handles both single-cookie and chunked-cookie sessions.
   *
   * Pass the incoming Cookie header so we know how many chunks to clear.
   * If not available, clears the base name and chunks 0–9 defensively.
   */
  buildClearCookieHeaders(incomingCookieHeader?: string): string[] {
    const headers: string[] = [];

    if (incomingCookieHeader) {
      // Clear exactly the chunks present in the request
      const chunkCount = countChunks(incomingCookieHeader, this.#cookieName);

      if (chunkCount === 0) {
        // Single un-chunked cookie
        headers.push(clearCookieHeader(this.#cookieName));
      } else {
        for (let i = 0; i < chunkCount; i++) {
          headers.push(clearCookieHeader(`${this.#cookieName}.${i}`));
        }
      }
    } else {
      // No request context — defensively clear base + chunks 0–9
      headers.push(clearCookieHeader(this.#cookieName));
      for (let i = 0; i < 10; i++) {
        headers.push(clearCookieHeader(`${this.#cookieName}.${i}`));
      }
    }

    return headers;
  }

  /**
   * Encrypts and returns a single base64url value (for SessionAdapter compat).
   * Prefer buildSetCookieHeaders() in BFF entry points.
   */
  async encrypt(data: SessionData): Promise<string> {
    const key = await this.#getKey();
    return encrypt(data, key);
  }

  async #getKey(): Promise<CryptoKey> {
    if (this.#key !== null) return this.#key;
    this.#key = await deriveKey(this.#secret);
    return this.#key;
  }
}

// ─── Chunk assembly ───────────────────────────────────────────────────────────

/**
 * Splits a base64url string into chunks of at most `size` bytes.
 * Each chunk is independently safe to store in a cookie.
 */
function splitIntoChunks(value: string, size: number): string[] {
  const chunks: string[] = [];
  for (let i = 0; i < value.length; i += size) {
    chunks.push(value.slice(i, i + size));
  }
  return chunks;
}

/**
 * Reads the Cookie header and reassembles chunk cookies in order.
 *
 * Handles two layouts:
 *   Single:  __Host-session=<value>
 *   Chunked: __Host-session.0=<v0>; __Host-session.1=<v1>; ...
 *
 * Returns null if no session cookies found.
 */
function assembleChunks(cookieHeader: string, baseName: string): string | null {
  const cookies = parseCookies(cookieHeader);

  // Check for single un-chunked cookie first
  const single = cookies.get(baseName);
  if (single !== undefined) return single;

  // Reassemble chunks in index order
  const assembled: string[] = [];
  let i = 0;

  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  while (true) {
    const chunk = cookies.get(`${baseName}.${i}`);
    if (chunk === undefined) break;
    assembled.push(chunk);
    i++;
  }

  return assembled.length > 0 ? assembled.join('') : null;
}

/**
 * Counts how many numbered chunk cookies are present.
 * Returns 0 if only the un-chunked base cookie exists.
 */
function countChunks(cookieHeader: string, baseName: string): number {
  const cookies = parseCookies(cookieHeader);
  let count = 0;
  while (cookies.has(`${baseName}.${count}`)) count++;
  return count;
}

/**
 * Parses a Cookie header into a Map.
 * Handles quoted values, whitespace, and semicolons correctly.
 */
function parseCookies(header: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const pair of header.split(';')) {
    const eq = pair.indexOf('=');
    if (eq < 0) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair
      .slice(eq + 1)
      .trim()
      .replace(/^"|"$/g, '');
    if (name) map.set(name, value);
  }
  return map;
}

// ─── Cookie header builders ───────────────────────────────────────────────────

function buildCookieHeader(name: string, value: string, maxAge: number): string {
  return [`${name}=${value}`, `Max-Age=${maxAge}`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Strict`].join('; ');
}

function buildCookieHeaderWithOptions(name: string, value: string, maxAge: number, sameSite: string, domainAttr: string): string {
  return [`${name}=${value}`, `Max-Age=${maxAge}`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=${sameSite}${domainAttr}`].join('; ');
}

function clearCookieHeader(name: string): string {
  return [`${name}=`, `Max-Age=0`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Strict`].join('; ');
}

function clearCookieHeaderWithOptions(name: string, sameSite: string, domainAttr: string): string {
  return [`${name}=`, `Max-Age=0`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=${sameSite}${domainAttr}`].join('; ');
}

// ─── Crypto primitives — Web Crypto API only ──────────────────────────────────

async function deriveKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveKey']);

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(KEY_SALT),
      info: encoder.encode(KEY_INFO),
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encrypt(data: SessionData, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);

  const combined = new Uint8Array(IV_BYTES + cipher.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipher), IV_BYTES);

  return base64urlEncode(combined);
}

async function decrypt(value: string, key: CryptoKey): Promise<SessionData> {
  const combined = base64urlDecode(value);

  if (combined.length <= IV_BYTES) {
    throw new Error('Cookie value too short to contain IV + ciphertext');
  }

  const iv = combined.slice(0, IV_BYTES);
  const ciphertext = combined.slice(IV_BYTES);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);

  return JSON.parse(new TextDecoder().decode(plaintext)) as SessionData;
}

function base64urlEncode(bytes: Uint8Array): string {
  const binary = Array.from(bytes, (b) => String.fromCodePoint(b)).join('');
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function base64urlDecode(value: string): Uint8Array {
  const base64 = value
    .replaceAll('-', '+')
    .replaceAll('_', '/')
    .padEnd(value.length + ((4 - (value.length % 4)) % 4), '=');
  const binary = atob(base64);
  return new Uint8Array(Array.from(binary, (c) => c.codePointAt(0) ?? 0));
}

// Re-export pending store for convenience
export { CookiePendingStore, type CookiePendingStoreOptions } from './pending.js';
