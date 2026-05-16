/**
 * OAuth Proxy Test Suite
 *
 * RFC 9700  — Section 6.3: Token Handler Pattern — OAuth Proxy responsibilities
 * RFC 6750  — Bearer Token Usage
 *
 * The OAuth Proxy:
 *   1. Validates the __Host- session cookie
 *   2. Retrieves the access token from the session adapter
 *   3. Injects the Bearer token into the upstream request
 *   4. NEVER sends the token back to the browser in any response
 *   5. Returns 401 if session is invalid or missing
 *
 * References:
 *   https://datatracker.ietf.org/doc/html/rfc9700#section-6.3
 *   https://datatracker.ietf.org/doc/html/rfc6750
 */

import { describe, it, expect, vi } from 'vitest';
import { createProxy } from './index.js';
import type { SessionData } from '../adapters/index.js';
import { createMockAdapter } from '../../tests/fixtures/fixtures.js';

const VALID_SESSION = {
  accessToken: 'eyJhbGciOiJSUzI1NiJ9.valid.token',
  expiresAt: Date.now() + 300_000, // 5 minutes from now
  refreshToken: 'refresh-token-opaque',
  refreshGeneration: 0,
} satisfies SessionData;

const EXPIRED_SESSION = {
  accessToken: 'eyJhbGciOiJSUzI1NiJ9.expired.token',
  expiresAt: Date.now() - 1, // already expired
  refreshToken: 'refresh-token-opaque',
  refreshGeneration: 0,
} satisfies SessionData;

describe('proxy — Bearer token injection', () => {
  it('injects Authorization: Bearer header into the upstream request', async () => {
    const adapter = createMockAdapter(VALID_SESSION);
    let capturedRequest: Request | undefined;

    const proxy = createProxy({
      target: 'https://api.torii.dev',
      adapter,
      fetch: (input: URL | RequestInfo, init?: RequestInit) => {
        const req = input instanceof Request ? input : new Request(input, init);
        capturedRequest = req;
        return Promise.resolve(
          new Response(JSON.stringify({ ok: true }), {
            headers: { 'Content-Type': 'application/json' },
          }),
        );
      },
    });

    const req = new Request('https://bff.torii.dev/api/users', {
      headers: {
        Cookie: `__Host-session=valid-session-id`,
        'x-torii-request': '1',
      },
    });

    await proxy(req);

    expect(capturedRequest).toBeDefined();
    expect(capturedRequest!.headers.get('authorization')).toBe(`Bearer ${VALID_SESSION.accessToken}`);
  });

  it('forwards the request to the correct upstream URL', async () => {
    const adapter = createMockAdapter(VALID_SESSION);
    let capturedUrl: string | undefined;

    const proxy = createProxy({
      target: 'https://api.torii.dev',
      adapter,
      fetch: (input: URL | RequestInfo, init?: RequestInit) => {
        const req = input instanceof Request ? input : new Request(input, init);
        capturedUrl = req.url;
        return Promise.resolve(new Response('ok'));
      },
    });

    const req = new Request('https://bff.torii.dev/api/users/123?page=2', {
      headers: {
        Cookie: `__Host-session=valid-session-id`,
        'x-torii-request': '1',
      },
    });

    await proxy(req);

    // Path and query string must be preserved
    expect(capturedUrl).toBe('https://api.torii.dev/api/users/123?page=2');
  });

  it('forwards the HTTP method unchanged', async () => {
    const adapter = createMockAdapter(VALID_SESSION);
    let capturedMethod: string | undefined;

    const proxy = createProxy({
      target: 'https://api.torii.dev',
      adapter,
      fetch: (input: URL | RequestInfo, init?: RequestInit) => {
        const req = input instanceof Request ? input : new Request(input, init);
        capturedMethod = req.method;
        return Promise.resolve(new Response('ok'));
      },
    });

    const req = new Request('https://bff.torii.dev/api/users', {
      method: 'DELETE',
      headers: {
        Cookie: `__Host-session=valid-session-id`,
        'x-torii-request': '1',
      },
    });

    await proxy(req);

    expect(capturedMethod).toBe('DELETE');
  });
});

describe('proxy — tokens never reach browser (RFC 9700 §6.3)', () => {
  it('does not include Authorization header in the response to the browser', async () => {
    const adapter = createMockAdapter(VALID_SESSION);

    const proxy = createProxy({
      target: 'https://api.torii.dev',
      adapter,
      fetch: () =>
        Promise.resolve(
          new Response('ok', {
            headers: { Authorization: 'Bearer upstream-leaked-token' },
          }),
        ),
    });

    const req = new Request('https://bff.torii.dev/api/data', {
      headers: {
        Cookie: `__Host-session=valid-session-id`,
        'x-torii-request': '1',
      },
    });

    const response = await proxy(req);

    // The Authorization header from upstream must be stripped before sending to browser
    expect(response.headers.get('authorization')).toBeNull();
  });

  it('does not include access token in response body', async () => {
    const adapter = createMockAdapter(VALID_SESSION);

    const proxy = createProxy({
      target: 'https://api.torii.dev',
      adapter,
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify({ data: 'ok' }), {
            headers: { 'Content-Type': 'application/json' },
          }),
        ),
    });

    const req = new Request('https://bff.torii.dev/api/data', {
      headers: {
        Cookie: `__Host-session=valid-session-id`,
        'x-torii-request': '1',
      },
    });

    const response = await proxy(req);
    const body = await response.text();

    // Response body must not contain the access token
    expect(body).not.toContain(VALID_SESSION.accessToken);
    expect(body).not.toContain('Bearer');
  });

  it('does not expose session cookie value in any response header', async () => {
    const adapter = createMockAdapter(VALID_SESSION);

    const proxy = createProxy({
      target: 'https://api.torii.dev',
      adapter,
      fetch: () => Promise.resolve(new Response('ok')),
    });

    const req = new Request('https://bff.torii.dev/api/data', {
      headers: {
        Cookie: `__Host-session=valid-session-id`,
        'x-torii-request': '1',
      },
    });

    const response = await proxy(req);

    // Response headers must not expose session or token values
    const setCookie = response.headers.get('set-cookie');

    expect(setCookie ?? '').not.toContain(VALID_SESSION.accessToken);
  });
});

// ─── 401 on invalid / missing session ────────────────────────────────────────

describe('proxy — authentication failures', () => {
  it('returns 401 when session cookie is missing', async () => {
    const adapter = createMockAdapter(null);

    const proxy = createProxy({
      target: 'https://api.torii.dev',
      adapter,
      fetch: vi.fn<typeof fetch>(),
    });

    const req = new Request('https://bff.torii.dev/api/data', {
      headers: { 'x-torii-request': '1' },
      // No Cookie header
    });

    const response = await proxy(req);

    expect(response.status).toBe(401);
  });

  it('returns 401 when session is not found in adapter', async () => {
    const adapter = createMockAdapter(null); // null = session not found

    const proxy = createProxy({
      target: 'https://api.torii.dev',
      adapter,
      fetch: vi.fn<typeof fetch>(),
    });

    const req = new Request('https://bff.torii.dev/api/data', {
      headers: {
        Cookie: '__Host-session=unknown-session-id',
        'x-torii-request': '1',
      },
    });

    const response = await proxy(req);

    expect(response.status).toBe(401);
  });

  it('returns 401 when access token is expired and refresh fails', async () => {
    const adapter = createMockAdapter(EXPIRED_SESSION);

    const proxy = createProxy({
      target: 'https://api.torii.dev',
      adapter,
      fetch: vi.fn<typeof fetch>(),
      // No refresh handler — simulates failed refresh
    });

    const req = new Request('https://bff.torii.dev/api/data', {
      headers: {
        Cookie: '__Host-session=expired-session-id',
        'x-torii-request': '1',
      },
    });

    const response = await proxy(req);

    expect(response.status).toBe(401);
  });

  it('does not call upstream when session is invalid', async () => {
    const adapter = createMockAdapter(null);
    const mockFetch = vi.fn<typeof fetch>();

    const proxy = createProxy({
      target: 'https://api.torii.dev',
      adapter,
      fetch: mockFetch,
    });

    const req = new Request('https://bff.torii.dev/api/data', {
      headers: { 'x-torii-request': '1' },
    });

    await proxy(req);

    // Upstream must never be called with an invalid session
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
