/**
 * Memory Session Adapter
 *
 * In-memory session storage — development and testing only.
 *
 * ⚠️  NOT for production use:
 *   - Sessions lost on process restart
 *   - Sessions NOT shared across instances
 *   - No persistence across requests on serverless (new isolate = new Map)
 *
 * Satisfies the SessionAdapter contract exactly — designed to be the
 * fastest possible implementation for test suites. All operations
 * are synchronous under the async interface.
 *
 * TTL is enforced lazily on get() rather than with setInterval() —
 * no background timers, no memory leaks, safe for edge runtime environments.
 */

import type { SessionAdapter, SessionData, CookieOptions } from '@torii-gate/core/adapters/interface';
import { extractSessionId, generateSessionId } from './helpers.js';

interface Entry {
  data: SessionData;
  expiresAt: number;
}

export interface MemoryAdapterOptions {
  /** Cookie name to use for session ID - defaults to __Host-session */
  cookieName?: string | undefined;
  /**
   * Opt-in to allow MemoryAdapter in production.
   * Default: false.
   *
   * ⚠️  Memory adapter is NOT recommended for production:
   *   - Sessions lost on process restart
   *   - Sessions NOT shared across instances
   *   - No persistence across requests on serverless
   *
   * Only set to true if you understand the risks and have a valid use case
   * (e.g., single-instance deployment with session stickiness).
   */
  allowInProduction?: boolean | undefined;
}

export class MemoryAdapter implements SessionAdapter {
  readonly #store = new Map<string, Entry>();
  readonly #cookieName: string;

  constructor(options: MemoryAdapterOptions = {}) {
    this.#cookieName = options.cookieName ?? '__Host-session';

    // Production guard — fail fast if memory adapter is used in production without opt-in
    // Only runs in Node.js environments (edge runtimes without process fall through)
    if (
      typeof globalThis !== 'undefined' &&
      'process' in globalThis &&
      typeof (globalThis as { process?: { env?: Record<string, string | undefined> } }).process === 'object' &&
      (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.['NODE_ENV'] === 'production' &&
      options.allowInProduction !== true
    ) {
      throw new Error(
        '[torii] MemoryAdapter is not safe for production use. ' +
          'Sessions are lost on restart and not shared across instances. ' +
          'Use adapter-redis or adapter-cookie for production. ' +
          'To bypass this check (not recommended), pass { allowInProduction: true }.',
      );
    }
  }

  /**
   * Extracts session from HTTP request by parsing Cookie header.
   * Returns null if no session found or session is expired.
   */
  get(request: Request): Promise<SessionData | null> {
    const sessionId = extractSessionId(request, this.#cookieName);
    if (!sessionId) return Promise.resolve(null);

    const entry = this.#store.get(sessionId);
    if (!entry) return Promise.resolve(null);

    // Lazy TTL enforcement — check on access
    if (Date.now() > entry.expiresAt) {
      this.#store.delete(sessionId);
      return Promise.resolve(null);
    }

    return Promise.resolve(entry.data);
  }

  /**
   * Stores session data and returns Set-Cookie header.
   * Generates a random session ID, stores data in memory.
   *
   * Note: sessionData.expiresAt is the token expiry (from OAuth provider).
   * options.maxAge is the cookie lifetime. These are independent:
   * - Cookie might live 8 hours (session duration)
   * - Access token might expire in 15 minutes
   */
  set(sessionData: SessionData, options: CookieOptions): Promise<string[]> {
    const sessionId = generateSessionId();
    // Store session with its own expiresAt (don't override with cookie maxAge)
    this.#store.set(sessionId, { data: sessionData, expiresAt: sessionData.expiresAt });

    const sameSite = options.topology === 'same-domain' ? 'Strict' : 'Lax';
    const domainAttr = options.topology === 'subdomain' && options.cookieDomain ? `; Domain=${options.cookieDomain}` : '';

    const header = [
      `${options.cookieName}=${sessionId}`,
      `Max-Age=${options.maxAge}`,
      `Path=/`,
      `Secure`,
      `HttpOnly`,
      `SameSite=${sameSite}${domainAttr}`,
    ].join('; ');

    return Promise.resolve([header]);
  }

  /**
   * Deletes session and returns Set-Cookie header to clear the cookie.
   */
  delete(request: Request, options: CookieOptions): Promise<string[]> {
    const sessionId = extractSessionId(request, this.#cookieName);
    if (sessionId) {
      this.#store.delete(sessionId);
    }

    const sameSite = options.topology === 'same-domain' ? 'Strict' : 'Lax';
    const domainAttr = options.topology === 'subdomain' && options.cookieDomain ? `; Domain=${options.cookieDomain}` : '';

    const header = [`${options.cookieName}=`, `Max-Age=0`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=${sameSite}${domainAttr}`].join('; ');

    return Promise.resolve([header]);
  }

  /**
   * Rotates session ID — deletes old session and creates a new one with updated data.
   *
   * Session fixation mitigation (RFC 9700 §7): generates a fresh session ID
   * after privilege escalation (e.g., token refresh).
   *
   * Race condition: not atomic. If two requests race, both may delete the old
   * session. The second will fail to find it and create a duplicate. Acceptable
   * for the memory adapter (dev/test only). Production adapters should use
   * atomic operations (Redis MULTI/EXEC, SQL transactions).
   */
  async rotate(request: Request, sessionData: SessionData, options: CookieOptions): Promise<string[]> {
    // Delete old session (best-effort — may already be gone in concurrent refresh)
    const oldSessionId = extractSessionId(request, this.#cookieName);
    if (oldSessionId) {
      this.#store.delete(oldSessionId);
    }

    // Create new session with fresh ID
    return this.set(sessionData, options);
  }

  /**
   * Returns the number of active (non-expired) sessions.
   * Useful in tests to assert sessions were stored or cleared.
   */
  get size(): number {
    const now = Date.now();
    let count = 0;
    for (const entry of this.#store.values()) {
      if (now <= entry.expiresAt) count++;
    }
    return count;
  }

  /**
   * Clears all sessions — useful between tests.
   */
  clear(): void {
    this.#store.clear();
  }
}
