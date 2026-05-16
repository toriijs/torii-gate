/**
 * OAuth Agent — Logout
 *
 * RFC 9700  — session must be invalidated on logout
 * RFC 7009  — OAuth 2.0 Token Revocation
 * OpenID Connect Session Management — end_session_endpoint
 *
 * Logout is a three-step process:
 *   1. Delete the local session from the adapter (immediate effect)
 *   2. Revoke the tokens at the provider's revocation endpoint (if available)
 *   3. Redirect to the provider's end_session_endpoint (federated logout)
 *
 * Steps 2 and 3 are best-effort — local session deletion (step 1) is
 * the only guaranteed action. If the provider is unreachable, the
 * local session is still destroyed and the user cannot make further
 * authenticated requests through the BFF.
 */

import type { SessionAdapter, CookieOptions } from '../adapters/interface.js';
import { revokeTokens } from './utils/revoke.js';
import { validatePostLogoutRedirectUri } from '../security/redirect.js';

export interface LogoutConfig {
  /** Provider revocation endpoint — optional, from OIDC discovery */
  revocationEndpoint?: string | undefined;
  /** Provider end_session_endpoint — optional, from OIDC discovery */
  endSessionEndpoint?: string | undefined;
  clientId: string;
  /** Client secret — required for confidential clients (e.g., Keycloak) */
  clientSecret?: string | undefined;
  /** Post-logout redirect URI — where to send the user after logout */
  postLogoutRedirectUri?: string | undefined;
  /**
   * Allowlist of permitted post-logout redirect URIs.
   * If provided, postLogoutRedirectUri must be in this list.
   * Prevents open-redirect attacks (RFC 9700 §4.11).
   */
  postLogoutRedirectUris?: readonly string[] | undefined;
  /** Cookie configuration for clearing session cookies */
  cookieOptions: CookieOptions;
  fetch?: typeof fetch | undefined;
}

export interface LogoutResult {
  /**
   * Set-Cookie headers to clear session cookies.
   * Apply all headers to the response before redirecting.
   */
  clearCookieHeaders: string[];
  /**
   * URL to redirect the browser to after clearing the cookie.
   * If end_session_endpoint is available, this is the provider's logout URL.
   * Otherwise it is the postLogoutRedirectUri or '/'.
   */
  redirectUrl: string;
}

/**
 * Performs logout:
 *   1. Retrieves session from request (for token revocation)
 *   2. Deletes the session via adapter
 *   3. Revokes tokens at the provider (best-effort)
 *   4. Returns cookie clear headers and redirect URL
 *
 * Does NOT perform the HTTP redirect itself — the caller applies
 * clearCookieHeaders and redirects to redirectUrl.
 */
export async function handleLogout(request: Request, adapter: SessionAdapter, config: LogoutConfig): Promise<LogoutResult> {
  // ── Step 1: retrieve tokens before deleting (needed for revocation) ────────
  const session = await adapter.get(request);

  // ── Step 2: delete local session immediately ───────────────────────────────
  // This runs regardless of revocation success — local session is always cleared
  const clearCookieHeaders = await adapter.delete(request, config.cookieOptions);

  // ── Step 3: revoke tokens at provider (best-effort, non-blocking) ─────────
  if (session && config.revocationEndpoint) {
    // Fire-and-forget — don't block logout on provider availability
    void revokeTokens({
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      revocationEndpoint: config.revocationEndpoint,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      fetch: config.fetch ?? fetch,
    }).catch((err: unknown) => {
      // Log server-side only — never expose to browser
      console.error('[torii] token revocation failed (non-fatal):', err);
    });
  }

  // ── Step 4: build federated logout URL ────────────────────────────────────
  const redirectUrl = buildLogoutRedirectUrl({
    endSessionEndpoint: config.endSessionEndpoint,
    postLogoutRedirectUri: config.postLogoutRedirectUri,
    postLogoutRedirectUris: config.postLogoutRedirectUris,
    idTokenHint: session?.idToken,
    clientId: config.clientId,
  });

  return {
    clearCookieHeaders,
    redirectUrl,
  };
}

// ─── Federated logout URL builder ─────────────────────────────────────────────

interface LogoutUrlParams {
  endSessionEndpoint?: string | undefined;
  postLogoutRedirectUri?: string | undefined;
  postLogoutRedirectUris?: readonly string[] | undefined;
  idTokenHint?: string | undefined;
  clientId: string;
}

function buildLogoutRedirectUrl(params: LogoutUrlParams): string {
  // Validate post-logout redirect URI against allowlist if provided
  let validatedRedirectUri = params.postLogoutRedirectUri ?? '/';
  if (params.postLogoutRedirectUris && params.postLogoutRedirectUri) {
    validatedRedirectUri = validatePostLogoutRedirectUri(
      params.postLogoutRedirectUri,
      params.postLogoutRedirectUris,
    );
  }

  if (!params.endSessionEndpoint) {
    return validatedRedirectUri;
  }

  const url = new URL(params.endSessionEndpoint);

  if (params.idTokenHint) {
    // Include id_token_hint for cleaner provider-side session termination
    url.searchParams.set('id_token_hint', params.idTokenHint);
  }

  if (validatedRedirectUri !== '/') {
    url.searchParams.set('post_logout_redirect_uri', validatedRedirectUri);
  }

  url.searchParams.set('client_id', params.clientId);

  return url.toString();
}
