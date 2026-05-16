/**
 * Session Adapter Interface
 *
 * RFC 9700: tokens must never be sent to the browser.
 * Adapters handle the complete HTTP request → session → HTTP response cycle.
 *
 * Stateful adapters (Redis, Memory): Store sessions server-side, cookie contains session ID
 * Stateless adapters (Cookie): Encrypt session data directly into cookie value
 *
 * All adapters must implement this interface.
 * Consumers may provide their own adapter for custom storage backends
 * (Cloudflare D1, Durable Objects, libsql, etc.)
 */

/** All token data — stored server-side or encrypted in cookie */
export interface SessionData {
  /** OAuth 2.0 access token — injected by proxy, never forwarded to browser */
  accessToken: string;
  /** Unix timestamp (ms) when the access token expires */
  expiresAt: number;
  /** Refresh token — optional, provider-dependent */
  refreshToken?: string | undefined;
  /** OpenID Connect ID token */
  idToken?: string | undefined;
  /** Cached userinfo claims */
  userInfo?: Record<string, unknown> | undefined;
  /** Refresh token generation counter — increments on each refresh, used for reuse detection (RFC 9700 §4.14) */
  refreshGeneration: number;
}

/** Cookie configuration for session adapters */
export interface CookieOptions {
  /** Cookie name - must start with __Host- or __Secure- */
  cookieName: string;
  /** Max-Age in seconds */
  maxAge: number;
  /** Deployment topology - drives SameSite and Domain attributes */
  topology: 'same-domain' | 'subdomain';
  /** Required when topology is 'subdomain' */
  cookieDomain?: string | undefined;
}

/** The contract every session adapter must satisfy */
export interface SessionAdapter {
  /**
   * Extracts and retrieves session data from an HTTP request.
   *
   * Stateful adapters: Parse cookie to get session ID, look up in storage
   * Stateless adapters: Parse cookie header, decrypt session data
   *
   * @param request - The incoming HTTP request (contains Cookie header)
   * @returns Session data or null if not found/expired
   */
  get(request: Request): Promise<SessionData | null>;

  /**
   * Stores session data and returns Set-Cookie headers ready to send.
   *
   * Stateful adapters: Generate session ID, store in DB/memory, return one cookie
   * Stateless adapters: Encrypt session data, chunk if needed, return multiple cookies
   *
   * @param sessionData - The session data to store
   * @param options - Cookie configuration (name, maxAge, topology, domain)
   * @returns Array of Set-Cookie header strings (may be multiple for chunked cookies)
   */
  set(sessionData: SessionData, options: CookieOptions): Promise<string[]>;

  /**
   * Deletes session and returns Set-Cookie headers that clear the cookies.
   *
   * Stateful adapters: Extract session ID, delete from storage, return clear cookie
   * Stateless adapters: Extract all chunk cookies, return headers to clear all
   *
   * @param request - The incoming HTTP request (contains session cookies to clear)
   * @param options - Cookie configuration (needed to build clear headers with correct attributes)
   * @returns Array of Set-Cookie header strings with Max-Age=0
   */
  delete(request: Request, options: CookieOptions): Promise<string[]>;

  /**
   * Rotates the session — generates a new session identifier with updated data.
   *
   * Session fixation mitigation (RFC 9700 §7): the session ID should change
   * after privilege escalation events like token refresh.
   *
   * Stateful adapters: Generate new ID, write new session, delete old session.
   * Stateless adapters: Re-encrypt session data (new IV) via set().
   *
   * Optional — if not implemented, refresh.ts will fall back to calling set().
   *
   * @param request - The incoming HTTP request (contains old session cookie)
   * @param sessionData - The updated session data to store
   * @param options - Cookie configuration
   * @returns Array of Set-Cookie header strings for the new session
   */
  rotate?(request: Request, sessionData: SessionData, options: CookieOptions): Promise<string[]>;
}
