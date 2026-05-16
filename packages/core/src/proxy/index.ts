/**
 * OAuth Proxy
 *
 * RFC 9700  — §6.3: Token Handler Pattern — OAuth Proxy responsibilities
 * RFC 6750  — Bearer Token Usage
 *
 * Responsibilities:
 *   1. Extract session ID from __Host- cookie
 *   2. Look up session in adapter (returns null = invalid/expired)
 *   3. Check access token expiry — trigger refresh if needed
 *   4. Forward request to upstream with Authorization: Bearer header injected
 *   5. Strip any auth-related headers from the upstream response
 *      before returning to the browser
 *
 * Tokens NEVER appear in:
 *   - Response bodies returned to the browser
 *   - Response headers returned to the browser
 *   - Logs (callers must not log the full request/response)
 */

import type { SessionAdapter } from '../adapters/interface.js';
import { buildUpstreamUrl, unauthorized } from './utils/index.js';

export interface ProxyConfig {
  /** Upstream API base URL — requests are forwarded here */
  target: string;
  /** Session adapter — provides access tokens */
  adapter: SessionAdapter;
  /**
   * Fetch implementation — injectable for testing.
   * Defaults to the global fetch (Web Standards).
   */
  fetch?: typeof fetch;
  /**
   * Optional token refresh handler.
   * Called when the access token is expired and a refresh token exists.
   * If absent, expired sessions return 401.
   *
   * The handler receives the request and adapter, should refresh the token,
   * and return true if successful.
   */
  onTokenExpired?: (request: Request, adapter: SessionAdapter) => Promise<boolean>;
}

/** Headers stripped from upstream responses before forwarding to browser */
const STRIP_RESPONSE_HEADERS = ['authorization', 'www-authenticate', 'x-access-token', 'x-auth-token'] as const;

/**
 * Creates a proxy middleware function.
 *
 * @returns An async function that takes a Request and returns a Response.
 *          Returns 401 if the session is missing, invalid, or expired.
 */
export function createProxy(config: ProxyConfig): (req: Request) => Promise<Response> {
  const fetchFn = config.fetch ?? fetch;

  return async (req: Request): Promise<Response> => {
    // 1. Extract session from request
    const session = await config.adapter.get(req);

    if (!session) {
      return unauthorized('Session not found or expired');
    }

    // 2. Check access token expiry
    if (Date.now() >= session.expiresAt) {
      if (config.onTokenExpired) {
        const refreshed = await config.onTokenExpired(req, config.adapter);
        if (!refreshed) {
          return unauthorized('Token expired and refresh failed');
        }
        // Re-fetch the refreshed session
        const refreshedSession = await config.adapter.get(req);
        if (!refreshedSession) {
          return unauthorized('Session lost after refresh');
        }
      } else {
        return unauthorized('Access token expired');
      }
    }

    // Re-fetch to get potentially-refreshed session
    const activeSession = await config.adapter.get(req);
    if (!activeSession) {
      return unauthorized('Session unavailable');
    }

    // 4. Build upstream request — inject Bearer token, never send cookie
    const upstreamUrl = buildUpstreamUrl(req.url, config.target);
    const upstreamHeaders = new Headers(req.headers);

    // Inject the access token — this is the core BFF responsibility
    upstreamHeaders.set('authorization', `Bearer ${activeSession.accessToken}`);

    // Never forward the session cookie to the upstream API
    upstreamHeaders.delete('cookie');

    const upstreamRequest = new Request(upstreamUrl, {
      method: req.method,
      headers: upstreamHeaders,
      body: req.body,
      // Required by the Fetch spec when body is a ReadableStream — see src/types/fetch.d.ts
      duplex: 'half',
    });

    // 5. Forward to upstream
    const upstreamResponse = await fetchFn(upstreamRequest);

    // 6. Strip auth headers from upstream response before returning to browser
    const responseHeaders = new Headers(upstreamResponse.headers);
    for (const header of STRIP_RESPONSE_HEADERS) {
      responseHeaders.delete(header);
    }

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders,
    });
  };
}
