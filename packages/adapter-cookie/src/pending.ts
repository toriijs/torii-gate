/**
 * Cookie Pending Auth Store
 *
 * Stores PKCE state in an encrypted AES-GCM HttpOnly cookie.
 * Zero server-side state — works on Cloudflare Workers, Deno Deploy,
 * scale-to-zero, and any multi-instance deployment.
 *
 * Cookie size: ~320 bytes — well under the 4KB browser limit.
 * Cookie name: __Host-torii-pkce
 * SameSite: Lax (required — must travel on the provider redirect)
 */

import type { PendingAuthStore, PendingAuth } from '@torii-gate/core/adapters/pending';
import { buildPkceStateCookie, readPkceStateCookie, clearPkceStateCookie } from '@torii-gate/core/security/pkce-state-cookie';
import { timingSafeEqual } from '@torii-gate/core/security/utils';

export interface CookiePendingStoreOptions {
  /**
   * Secret for AES-GCM encryption.
   * Should be the same secret used for session encryption.
   */
  secret: string;
  /** Max-Age in seconds — defaults to 600 (10 minutes) */
  maxAge?: number;
}

/**
 * Default PendingAuthStore implementation.
 *
 * Stores PKCE state in an encrypted AES-GCM HttpOnly cookie.
 * Zero server-side state — works on Cloudflare Workers, Deno Deploy,
 * scale-to-zero, and any multi-instance deployment.
 */
export class CookiePendingStore implements PendingAuthStore {
  readonly #secret: string;
  readonly #maxAge: number;

  constructor(options: CookiePendingStoreOptions) {
    this.#secret = options.secret;
    this.#maxAge = options.maxAge ?? 600;
  }

  async set(data: PendingAuth): Promise<Record<string, string>> {
    const cookieHeader = await buildPkceStateCookie(data, {
      secret: this.#secret,
      maxAge: this.#maxAge,
    });
    return { 'set-cookie': cookieHeader };
  }

  async get(state: string, request?: Request): Promise<PendingAuth | null> {
    const cookieHeader = request?.headers.get('cookie') ?? '';
    const data = await readPkceStateCookie(cookieHeader, this.#secret);

    if (!data) return null;

    // Enforce single-use: state in cookie must match state in callback params
    // Use timing-safe comparison to prevent timing attacks that could leak valid state values
    const stateMatches = await timingSafeEqual(data.state, state);
    if (!stateMatches) return null;

    return data;
  }

  clear(): Record<string, string> {
    return { 'set-cookie': clearPkceStateCookie() };
  }
}
