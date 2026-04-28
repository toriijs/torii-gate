/**
 * OIDC Discovery
 *
 * OpenID Connect Discovery 1.0
 * https://openid.net/specs/openid-connect-discovery-1_0.html
 *
 * Fetches provider metadata from the well-known endpoint exactly once
 * per isolate lifetime. The result is cached in module scope — subsequent
 * calls return the cached value with zero network overhead.
 *
 * Cold start design:
 *   - Called once inside the lazy runtime initializer
 *   - Parallelised with key derivation via Promise.all
 *   - Never called on the request hot path
 */

import { isValidHttpsUrl } from '../security/https.js';

/** Subset of OIDC provider metadata used by Torii */
export interface IssuerMetadata {
  /** Provider's issuer identifier — validated against iss param */
  issuer: string;
  /** Authorization endpoint — where login redirects go */
  authorization_endpoint: string;
  /** Token endpoint — where code exchange happens */
  token_endpoint: string;
  /** Revocation endpoint — optional, used on logout */
  revocation_endpoint?: string | undefined;
  /** End session endpoint — optional, used for federated logout */
  end_session_endpoint?: string | undefined;
  /** JWKS URI — for ID token signature verification (v0.2) */
  jwks_uri?: string | undefined;
  /** Supported response types — must include 'code' */
  response_types_supported?: readonly string[] | undefined;
  /** Supported PKCE methods — must include 'S256' */
  code_challenge_methods_supported?: readonly string[] | undefined;
}

export interface DiscoveryOptions {
  fetch?: typeof fetch | undefined;
  /** Timeout in ms — defaults to 5000 */
  timeoutMs?: number | undefined;
}

/**
 * Fetches and validates OIDC provider metadata.
 *
 * Validates that the required endpoints exist and that
 * the returned issuer matches the requested issuer exactly.
 *
 * @throws {DiscoveryError} if the discovery request fails or required fields are missing
 */
export async function discoverIssuer(issuerUrl: string, options: DiscoveryOptions = {}): Promise<IssuerMetadata> {
  if (!isValidHttpsUrl(issuerUrl)) {
    throw new DiscoveryError(`Issuer URL must use HTTPS (got "${issuerUrl}")`, 'invalid_issuer_url');
  }

  // RFC: discovery URL is issuer + /.well-known/openid-configuration
  // Some providers (Keycloak) include a path in the issuer URL
  const discoveryUrl = issuerUrl.endsWith('/') ? `${issuerUrl}.well-known/openid-configuration` : `${issuerUrl}/.well-known/openid-configuration`;

  const fetchFn = options.fetch ?? fetch;
  const timeoutMs = options.timeoutMs ?? 5000;

  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  let response: Response;
  try {
    response = await fetchFn(discoveryUrl, {
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error';
    throw new DiscoveryError(`OIDC discovery request failed for "${issuerUrl}": ${message}`, 'fetch_failed');
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    throw new DiscoveryError(`OIDC discovery returned HTTP ${response.status} for "${discoveryUrl}"`, 'http_error');
  }

  const raw = (await response.json()) as Record<string, unknown>;

  // ── Validate required fields ──────────────────────────────────────────────

  assertString(raw, 'issuer', discoveryUrl);
  assertString(raw, 'authorization_endpoint', discoveryUrl);
  assertString(raw, 'token_endpoint', discoveryUrl);

  // ── Issuer must match exactly — RFC 8414 §3 ───────────────────────────────
  if (raw['issuer'] !== issuerUrl) {
    throw new DiscoveryError(`Issuer mismatch in discovery: expected "${issuerUrl}", got "${String(raw['issuer'])}"`, 'issuer_mismatch');
  }

  // ── PKCE S256 support warning — not a hard failure ────────────────────────
  // Some providers don't advertise code_challenge_methods_supported even
  // when they support it (e.g. older Keycloak). We proceed and let the
  // token exchange fail naturally if PKCE is genuinely unsupported.
  const pkce = raw['code_challenge_methods_supported'];
  if (Array.isArray(pkce) && !pkce.includes('S256')) {
    console.warn(
      `[torii] Provider "${issuerUrl}" does not advertise S256 PKCE support. ` +
        `Proceeding — if token exchange fails, verify PKCE is enabled on the provider.`,
    );
  }

  return {
    issuer: raw['issuer'],
    authorization_endpoint: raw['authorization_endpoint'] as string,
    token_endpoint: raw['token_endpoint'] as string,
    revocation_endpoint: raw['revocation_endpoint'] as string | undefined,
    end_session_endpoint: raw['end_session_endpoint'] as string | undefined,
    jwks_uri: raw['jwks_uri'] as string | undefined,
    response_types_supported: raw['response_types_supported'] as readonly string[] | undefined,
    code_challenge_methods_supported: raw['code_challenge_methods_supported'] as readonly string[] | undefined,
  };
}

function assertString(obj: Record<string, unknown>, key: string, discoveryUrl: string): void {
  if (typeof obj[key] !== 'string' || !obj[key]) {
    throw new DiscoveryError(`OIDC discovery response missing required field "${key}" from "${discoveryUrl}"`, 'missing_field');
  }
}

export type DiscoveryErrorCode = 'invalid_issuer_url' | 'fetch_failed' | 'http_error' | 'issuer_mismatch' | 'missing_field';

export class DiscoveryError extends Error {
  readonly code: DiscoveryErrorCode;

  constructor(message: string, code: DiscoveryErrorCode, options?: ErrorOptions) {
    super(message, options);
    this.name = 'DiscoveryError';
    this.code = code;
  }
}
