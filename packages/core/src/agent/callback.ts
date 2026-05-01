/**
 * OAuth Agent — Callback
 *
 * RFC 9700  — §4: Authorization Code callback processing
 * RFC 9207  — iss parameter validation (mix-up attack defence)
 * RFC 7636  — PKCE code_verifier submission
 * OpenID Connect Core §3.1.3.7 — full ID token validation
 *
 * Validation order — fail-fast:
 *   1. provider error parameter
 *   2. state parameter present
 *   3. pending auth lookup (single-use)
 *   4. redirect_uri exact match (RFC 9700 §2.1)
 *   5. iss parameter (RFC 9207 mix-up defence)
 *   6. client_id echo — if provider returned one, it must match (RFC 9700 §4.4)
 *   7. authorization code present
 *   8. token exchange (PKCE code_verifier submitted)
 *   9. ID token verified — signature, alg, iss, aud, exp, nbf, iat, nonce
 */

import { validateIssuer } from '../security/issuer.js';
import { assertExactRedirectUri } from '../security/redirect.js';
import { SESSION_ID_BYTES } from '../security/constants.js';
import { base64urlEncode } from '../security/utils/index.js';
import { verifyIdToken, JwtError, type JwksKeySource, type VerifiedIdTokenClaims } from '../security/jwt.js';
import { exchangeToken } from './utils/token-exchange.js';
import type { SessionData } from '../adapters/interface.js';
import type { PendingAuthStore } from '../adapters/pending.js';

export interface CallbackContext {
  /** Expected OIDC issuer — validated against iss param (RFC 9207) and id_token.iss */
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  /** Pending auth store — retrieves codeVerifier + nonce by state */
  pendingStore: PendingAuthStore;
  /** Token endpoint URL from OIDC discovery */
  tokenEndpoint: string;
  /**
   * JWKS key source — resolves id_token `kid` → CryptoKey.
   * Required whenever an id_token is expected (default).
   */
  keySource?: JwksKeySource | undefined;
  /**
   * When true (default), the callback requires an id_token in the token response
   * and fully verifies it. Set to false only for pure OAuth 2.0 flows without OIDC.
   */
  requireIdToken?: boolean | undefined;
  /** Clock skew tolerance for ID token exp/nbf/iat in seconds (default 60). */
  clockSkewSec?: number | undefined;
  /** Fetch implementation — injectable for testing */
  fetch?: typeof fetch | undefined;
  /** Incoming request — required for cookie-based pending-store and redirect_uri match */
  request?: Request | undefined;
}

export interface CallbackResult {
  /** Session data returned from OAuth provider — caller stores via adapter.set() */
  sessionData: SessionData;
  /** Verified id_token claims, when an id_token was returned and validated. */
  idTokenClaims?: VerifiedIdTokenClaims | undefined;
}

/**
 * Processes the authorization callback.
 *
 * @returns Promise<CallbackResult> — caller stores sessionData via adapter.set()
 * @throws  CallbackError on any validation failure
 */
export async function handleCallback(params: URLSearchParams, context: CallbackContext): Promise<CallbackResult> {
  // ── Step 1: provider error ─────────────────────────────────────────────────
  const error = params.get('error');
  if (error) {
    const description = params.get('error_description') ?? 'no description';
    throw new CallbackError(`Provider returned error: ${error} — ${description}`, 'provider_error');
  }

  // ── Step 2: state must be present ─────────────────────────────────────────
  const state = params.get('state');
  if (!state) {
    throw new CallbackError('Missing state parameter in callback', 'missing_state');
  }

  // ── Step 3: retrieve pending auth (validates state, single-use) ───────────
  const pending = await context.pendingStore.get(state, context.request);
  if (!pending) {
    throw new CallbackError('Invalid or expired state — possible CSRF attempt', 'invalid_state');
  }

  // ── Step 4: redirect_uri exact match (RFC 9700 §2.1) ──────────────────────
  if (context.request) {
    try {
      assertExactRedirectUri(new URL(context.request.url), context.redirectUri);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'redirect_uri mismatch';
      throw new CallbackError(message, 'invalid_redirect_uri', { cause: err });
    }
  }

  // ── Step 5: iss validation — RFC 9207 mix-up defence ──────────────────────
  const iss = params.get('iss');
  if (!validateIssuer(iss, context.issuer)) {
    throw new CallbackError(`iss parameter mismatch — expected "${context.issuer}", got "${iss ?? 'missing'}"`, 'invalid_iss');
  }

  // ── Step 6: client_id echo (RFC 9700 §4.4, advisory) ──────────────────────
  // Absent is tolerated — many providers don't echo. Present-and-mismatched
  // is a hard error (mix-up attack indicator).
  const echoedClientId = params.get('client_id');
  if (echoedClientId !== null && echoedClientId !== context.clientId) {
    throw new CallbackError(`client_id echo mismatch — expected "${context.clientId}", got "${echoedClientId}"`, 'invalid_client_id');
  }

  // ── Step 7: authorization code must be present ────────────────────────────
  const code = params.get('code');
  if (!code) {
    throw new CallbackError('Missing authorization code in callback', 'missing_code');
  }

  // ── Step 8: token exchange ─────────────────────────────────────────────────
  const tokenResponse = await exchangeCode({
    code,
    codeVerifier: pending.codeVerifier,
    clientId: context.clientId,
    clientSecret: context.clientSecret,
    redirectUri: context.redirectUri,
    tokenEndpoint: context.tokenEndpoint,
    fetch: context.fetch ?? fetch,
  });

  // ── Step 9: id_token verification ─────────────────────────────────────────
  const requireIdToken = context.requireIdToken ?? true;
  let idTokenClaims: VerifiedIdTokenClaims | undefined;

  if (tokenResponse.id_token) {
    if (!context.keySource) {
      throw new CallbackError('id_token returned but no JWKS keySource was configured', 'missing_key_source');
    }
    try {
      idTokenClaims = await verifyIdToken(tokenResponse.id_token, {
        issuer: context.issuer,
        clientId: context.clientId,
        nonce: pending.nonce,
        keySource: context.keySource,
        clockSkewSec: context.clockSkewSec ?? 60,
      });
    } catch (err) {
      if (err instanceof JwtError) {
        throw new CallbackError(`id_token verification failed: ${err.message}`, 'invalid_id_token', { cause: err });
      }
      throw err;
    }
  } else if (requireIdToken) {
    throw new CallbackError('Token response missing id_token', 'missing_id_token');
  }

  // ── Step 10: build session data ──────────────────────────────────────────
  // Caller will store via adapter.set(sessionData, cookieOptions)
  const sessionData: SessionData = {
    accessToken: tokenResponse.access_token,
    expiresAt: Date.now() + (tokenResponse.expires_in ?? 900) * 1000,
    refreshToken: tokenResponse.refresh_token,
    idToken: tokenResponse.id_token,
    refreshGeneration: 0,
  };

  return { sessionData, idTokenClaims };
}

// ─── Token exchange ───────────────────────────────────────────────────────────

interface ExchangeParams {
  code: string;
  codeVerifier: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  tokenEndpoint: string;
  fetch: typeof fetch;
}

async function exchangeCode(params: ExchangeParams): Promise<TokenResponseShape> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: params.clientId,
    client_secret: params.clientSecret,
    code_verifier: params.codeVerifier,
  });

  try {
    return await exchangeToken({
      tokenEndpoint: params.tokenEndpoint,
      body,
      fetch: params.fetch,
      errorContext: 'Token exchange',
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Token exchange failed';
    throw new CallbackError(message, 'token_exchange_failed', { cause: err });
  }
}

interface TokenResponseShape {
  access_token: string;
  token_type?: string;
  expires_in?: number | undefined;
  refresh_token?: string | undefined;
  id_token?: string | undefined;
  scope?: string | undefined;
}

/**
 * Generates a cryptographically random session id — exported so stateful
 * adapters and refresh rotation share the same primitive.
 */
export function generateSessionId(): string {
  const bytes = new Uint8Array(SESSION_ID_BYTES);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

export type CallbackErrorCode =
  | 'provider_error'
  | 'missing_state'
  | 'invalid_state'
  | 'invalid_redirect_uri'
  | 'invalid_iss'
  | 'invalid_client_id'
  | 'missing_code'
  | 'token_exchange_failed'
  | 'invalid_token_response'
  | 'missing_id_token'
  | 'missing_key_source'
  | 'invalid_id_token';

export class CallbackError extends Error {
  readonly code: CallbackErrorCode;

  constructor(message: string, code: CallbackErrorCode, options?: ErrorOptions) {
    super(message, options);
    this.name = 'CallbackError';
    this.code = code;
  }
}
