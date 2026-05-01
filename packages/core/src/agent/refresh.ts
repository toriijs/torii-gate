/**
 * OAuth Agent — Token Refresh
 *
 * RFC 6749  — §6: Refreshing an Access Token
 * RFC 9700  — tokens must remain server-side through refresh
 *
 * Handles refresh token rotation: the new refresh token from the response
 * replaces the old one in the session adapter atomically.
 *
 * The access token NEVER leaves the server — the session adapter is updated
 * in place and the browser only ever sees the unchanged session cookie.
 */

import { exchangeToken } from './utils/token-exchange.js';
import { revokeTokens } from './utils/revoke.js';
import type { SessionAdapter, SessionData, CookieOptions } from '../adapters/interface.js';

export interface RefreshConfig {
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  /** Provider revocation endpoint — for reuse detection token revocation */
  revocationEndpoint?: string | undefined;
  /** Session TTL to apply after a successful refresh — defaults to 900s */
  sessionTtlSeconds?: number | undefined;
  /**
   * Require provider to return a new refresh_token on each refresh (RFC 9700 §4.14).
   * Default: true. Set false only for non-compliant providers.
   */
  requireRotation?: boolean | undefined;
  /**
   * Cookie options — used for session rotation (RFC 9700 §7) and deletion on reuse detection.
   * When provided, refreshSession will call adapter.rotate() if available, or adapter.set() as fallback.
   */
  cookieOptions?: CookieOptions | undefined;
  fetch?: typeof fetch | undefined;
}

export interface RefreshResult {
  /** true = tokens refreshed successfully */
  refreshed: boolean;
  /**
   * Updated session data — caller must persist via adapter.rotate() or adapter.set().
   * Use rotate() to mitigate session fixation (RFC 9700 §7) by issuing a new session ID.
   */
  sessionData?: SessionData | undefined;
  /** reason for failure — server-side log only, never sent to browser */
  reason?: string | undefined;
}

/**
 * Attempts to refresh the access token for a session.
 *
 * Implements RFC 9700 §4.14 refresh token rotation and reuse detection:
 *   1. Requires new refresh_token in response (configurable)
 *   2. Increments refreshGeneration on each successful refresh
 *   3. Detects reuse if generation regresses → revokes chain
 *
 * Returns updated SessionData on success — caller must persist it.
 * For stateful adapters (Redis, Memory): caller can update the existing session.
 * For stateless adapters (Cookie): caller must generate new Set-Cookie headers.
 *
 * Returns { refreshed: false } on failure — caller should return 401.
 */
export async function refreshSession(request: Request, adapter: SessionAdapter, config: RefreshConfig): Promise<RefreshResult> {
  const session = await adapter.get(request);

  if (!session) {
    return { refreshed: false, reason: 'session not found' };
  }

  if (!session.refreshToken) {
    return { refreshed: false, reason: 'no refresh token in session' };
  }

  // Capture current generation before refresh attempt
  const incomingGeneration = session.refreshGeneration;

  try {
    const tokenResponse = await exchangeRefreshToken({
      refreshToken: session.refreshToken,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      tokenEndpoint: config.tokenEndpoint,
      fetch: config.fetch ?? fetch,
    });

    // ── RFC 9700 §4.14: enforce refresh token rotation ────────────────────────
    const requireRotation = config.requireRotation ?? true;
    if (requireRotation && !tokenResponse.refresh_token) {
      console.warn('[torii] Provider did not rotate refresh_token — rotation required by config');
      return { refreshed: false, reason: 'refresh token rotation missing' };
    }

    // ── Reuse detection: check if generation has advanced since we read it ────
    // For stateful adapters, re-read session to see if concurrent refresh happened
    const currentSession = await adapter.get(request);
    if (currentSession && currentSession.refreshGeneration > incomingGeneration) {
      // Another refresh happened concurrently → this is token reuse
      console.error('[torii] Refresh token reuse detected — revoking token chain');

      // Delete session immediately
      if (config.cookieOptions) {
        await adapter.delete(request, config.cookieOptions);
      }

      // Best-effort revoke both tokens
      if (config.revocationEndpoint) {
        void revokeTokens({
          accessToken: session.accessToken,
          refreshToken: session.refreshToken,
          revocationEndpoint: config.revocationEndpoint,
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          fetch: config.fetch ?? fetch,
        }).catch((err: unknown) => {
          console.error('[torii] Token revocation after reuse detection failed:', err);
        });
      }

      return { refreshed: false, reason: 'token_reuse_detected' };
    }

    // ── Build updated session with incremented generation ─────────────────────
    const updatedSession: SessionData = {
      ...session,
      accessToken: tokenResponse.access_token,
      expiresAt: Date.now() + (tokenResponse.expires_in ?? 900) * 1000,
      refreshToken: tokenResponse.refresh_token ?? session.refreshToken,
      idToken: tokenResponse.id_token ?? session.idToken,
      refreshGeneration: incomingGeneration + 1,
    };

    return { refreshed: true, sessionData: updatedSession };
  } catch (err) {
    const reason = err instanceof Error ? err.message : 'unknown refresh error';
    return { refreshed: false, reason };
  }
}

// ─── Refresh token exchange ────────────────────────────────────────────────────

interface RefreshTokenParams {
  refreshToken: string;
  clientId: string;
  clientSecret: string;
  tokenEndpoint: string;
  fetch: typeof fetch;
}

interface RefreshTokenResponse {
  access_token: string;
  expires_in?: number | undefined;
  refresh_token?: string | undefined;
  id_token?: string | undefined;
}

async function exchangeRefreshToken(params: RefreshTokenParams): Promise<RefreshTokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: params.refreshToken,
    client_id: params.clientId,
    client_secret: params.clientSecret,
  });

  return await exchangeToken({
    tokenEndpoint: params.tokenEndpoint,
    body,
    fetch: params.fetch,
    errorContext: 'Refresh token exchange',
  });
}
