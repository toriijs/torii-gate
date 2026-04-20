/**
 * PendingAuthStore — Pluggable PKCE State Storage Interface
 *
 * Stores the short-lived auth state between the login redirect and callback:
 *   - codeVerifier  (PKCE — submitted on token exchange)
 *   - nonce         (OIDC — validated against ID token)
 *   - state         (CSRF — validated against callback param)
 *
 * THE PROBLEM:
 *   Module-scope Map() breaks on scale-to-zero (isolate restart loses state)
 *   and multi-instance deployments (login on instance A, callback on instance B).
 *
 * THE SOLUTION:
 *   A pluggable interface — like SessionAdapter — with a secure default.
 *   Default: CookiePendingStore (from @torii-gate/adapter-cookie/pending)
 *   Alternatives: RedisPendingStore, KVPendingStore, D1PendingStore
 *
 * Implementations:
 *   - @torii-gate/adapter-cookie/pending — CookiePendingStore (stateless, AES-GCM encrypted)
 *   - @torii-gate/adapter-memory/pending — MemoryPendingStore (dev/test only)
 *   - @torii-gate/adapter-redis — NodeRedisPendingStore, UpstashRedisPendingStore
 */

export interface PendingAuth {
  codeVerifier: string;
  nonce: string;
  state: string;
  expiresAt: number;
}

/**
 * Contract for storing pending auth state between login and callback.
 *
 * Implementations must handle the TTL — expired entries must not be returned.
 * The `set` method returns any headers that must be sent with the login redirect
 * (e.g. Set-Cookie for the cookie implementation).
 */
export interface PendingAuthStore {
  /**
   * Stores pending auth state.
   * Returns headers to attach to the login redirect response.
   * Empty object if no headers needed (e.g. Redis implementation).
   */
  set(data: PendingAuth): Promise<Record<string, string>>;

  /**
   * Retrieves and removes pending auth state by state value.
   * Returns null if not found or expired (single-use enforcement).
   * The second argument provides the incoming request for cookie-based stores.
   */
  get(state: string, request?: Request): Promise<PendingAuth | null>;

  /**
   * Returns headers to attach to the callback response to clean up state.
   * Cookie implementations use this to clear the PKCE cookie.
   * Redis implementations return empty object.
   */
  clear(): Record<string, string>;
}
