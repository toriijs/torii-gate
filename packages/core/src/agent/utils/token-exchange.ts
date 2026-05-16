/**
 * OAuth Token Endpoint Exchange
 *
 * Shared logic for authorization_code and refresh_token grant types.
 * Both flows POST form-encoded parameters to the token endpoint and
 * expect a JSON response with access_token.
 *
 * This utility eliminates ~50 lines of duplication between callback.ts
 * and refresh.ts while preserving semantic function names at call sites
 * via import aliases.
 */

export interface TokenExchangeParams {
  tokenEndpoint: string;
  body: URLSearchParams;
  fetch: typeof fetch;
  errorContext: string; // e.g., "Token exchange" or "Refresh token exchange"
}

export interface TokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

/**
 * Exchanges parameters for tokens at the OAuth token endpoint.
 *
 * Used by both authorization code and refresh token flows.
 * Import with an alias to preserve semantic clarity at call sites:
 *
 * @example
 * import { exchangeToken as exchangeCode } from './utils/token-exchange.js';
 * const tokens = await exchangeCode({ ... });
 */
export async function exchangeToken(params: TokenExchangeParams): Promise<TokenResponse> {
  const response = await params.fetch(params.tokenEndpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: params.body.toString(),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => 'unknown error');
    throw new Error(`${params.errorContext} failed: ${response.status} ${response.statusText} — ${text}`);
  }

  const data = (await response.json()) as TokenResponse;

  if (!data.access_token) {
    throw new Error(`${params.errorContext} response missing access_token`);
  }

  return data;
}
