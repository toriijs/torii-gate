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
 *
 * DESIGN: Stateful vs Stateless Implementations
 *
 * This interface supports two removal patterns for single-use enforcement:
 *
 * 1. Stateful (Redis, Memory):
 *    - get() atomically retrieves and deletes
 *    - clear() returns empty headers {}
 *    - Single-use enforced at first get()
 *
 * 2. Stateless (Cookie):
 *    - get() retrieves and validates state (timing-safe comparison)
 *    - clear() returns Set-Cookie headers with Max-Age=0
 *    - Single-use enforced when browser receives callback response
 *
 * Both patterns satisfy single-use enforcement; the difference is timing.
 * The service layer calls clear() and appends headers for both types.
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
   * Retrieves pending auth state by state value (single-use enforcement).
   *
   * Stateful implementations (Redis, Memory): Atomically deletes on retrieval.
   * Stateless implementations (Cookie): Validates state; deletion via clear() headers.
   *
   * Returns null if not found or expired.
   *
   * @param state - OAuth state parameter from callback URL
   * @param request - Incoming request (required for cookie-based stores to read cookies)
   */
  get(state: string, request?: Request): Promise<PendingAuth | null>;

  /**
   * Returns headers to attach to the callback response to clean up state.
   *
   * Stateless implementations (Cookie): Returns {'set-cookie': '...'} with Max-Age=0.
   * Stateful implementations (Redis, Memory): Returns empty object {}.
   *
   * The service layer MUST call this after successful callback and append headers
   * to the response to complete single-use enforcement for cookie-based stores.
   */
  clear(): Record<string, string>;
}
