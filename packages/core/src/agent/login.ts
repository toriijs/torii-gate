/**
 * OAuth Agent — Login
 *
 * RFC 9700  — §4: Authorization Code + PKCE
 * RFC 9700  — §4.7: state and nonce generation
 * RFC 7636  — PKCE S256
 *
 * Builds the authorization URL and stores PKCE state via the PendingAuthStore.
 * The default store (CookiePendingStore) is stateless — works on scale-to-zero
 * and multi-instance deployments.
 */

import { generateCodeVerifier, generateCodeChallenge, PKCE_METHOD } from '../security/pkce.js';
import { generateState } from '../security/state.js';
import { generateNonce } from '../security/nonce.js';
import { type PendingAuthStore } from '../adapters/pending.js';

export interface LoginConfig {
  /** Provider authorization_endpoint from OIDC discovery */
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  /** Scopes to request — must include 'openid' */
  scopes: readonly string[];
  /**
   * How long (seconds) the pending auth is valid.
   * Default: 600 (10 minutes)
   */
  pendingTtlSeconds?: number;
}

export interface LoginResult {
  /** Full authorization URL — redirect the browser here */
  redirectUrl: string;
  /**
   * Headers to attach to the login redirect response.
   * For CookiePendingStore: contains Set-Cookie for __Host-torii-pkce.
   * For MemoryPendingStore or Redis: empty object.
   */
  headers: Record<string, string>;
}

/**
 * Builds an authorization URL and stores PKCE state via the PendingAuthStore.
 *
 * Returns the redirect URL and any headers that must be sent with the redirect.
 * The caller must attach the returned headers to the 302 response.
 */
export async function buildLoginUrl(config: LoginConfig, pendingStore: PendingAuthStore): Promise<LoginResult> {
  const ttl = config.pendingTtlSeconds ?? 600;
  const expiresAt = Date.now() + ttl * 1000;

  // Generate all cryptographic values — state and nonce are independent
  const [state, nonce, codeVerifier] = await Promise.all([generateState(), generateNonce(), generateCodeVerifier()]);

  const codeChallenge = await generateCodeChallenge(codeVerifier);

  // Store pending auth — returns headers to attach to the redirect response
  const headers = await pendingStore.set({ codeVerifier, nonce, state, expiresAt });

  // Build authorization URL
  const url = new URL(config.authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', config.redirectUri);
  url.searchParams.set('scope', config.scopes.join(' '));
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', PKCE_METHOD);

  return { redirectUrl: url.toString(), headers };
}
