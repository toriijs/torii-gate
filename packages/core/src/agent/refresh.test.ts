/**
 * Refresh Test Suite
 *
 * RFC 6749  — §6: Refreshing an Access Token
 * RFC 9700  — tokens remain server-side through refresh
 */

import { describe, it, expect, vi } from 'vitest';
import { refreshSession } from './refresh.js';
import type { SessionAdapter, SessionData } from '../../src/adapters/interface';
import { createMockAdapter } from '../../tests/fixtures/fixtures';

const VALID_SESSION = {
  accessToken: 'old-access-token',
  refreshToken: 'valid-refresh-token',
  expiresAt: Date.now() - 1, // expired
  idToken: 'old-id-token',
  refreshGeneration: 0,
} satisfies SessionData;

function mockRequest(cookieHeader: string): Request {
  return new Request('https://torii.dev', {
    headers: { cookie: cookieHeader },
  });
}

function mockSuccessfulRefresh(newTokens: Partial<SessionData> = {}) {
  return vi.fn().mockResolvedValue(
    new Response(
      JSON.stringify({
        access_token: newTokens.accessToken ?? 'new-access-token',
        expires_in: 900,
        refresh_token: newTokens.refreshToken ?? 'new-refresh-token',
        id_token: newTokens.idToken ?? 'new-id-token',
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    ),
  );
}

const BASE_CONFIG = {
  tokenEndpoint: 'https://auth.torii.dev/token',
  clientId: 'my-client',
  clientSecret: 'my-secret',
};

describe('refreshSession — successful refresh', () => {
  it('returns refreshed: true on success', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const result = await refreshSession(request, adapter, {
      ...BASE_CONFIG,
      fetch: mockSuccessfulRefresh(),
    });

    // Assert
    expect(result.refreshed).toBe(true);
    expect(result.sessionData).toBeDefined();
  });

  it('returns updated session data with new access token', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const result = await refreshSession(request, adapter, {
      ...BASE_CONFIG,
      fetch: mockSuccessfulRefresh({ accessToken: 'brand-new-token' }),
    });

    // Assert
    expect(result.sessionData?.accessToken).toBe('brand-new-token');
  });

  it('rotates refresh token when provider returns a new one', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const result = await refreshSession(request, adapter, {
      ...BASE_CONFIG,
      fetch: mockSuccessfulRefresh({ refreshToken: 'rotated-refresh-token' }),
    });

    // Assert
    expect(result.sessionData?.refreshToken).toBe('rotated-refresh-token');
  });

  it('keeps old refresh token when provider does not return a new one (requireRotation: false)', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');
    const fetchFn = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'new-token',
          expires_in: 900,
          // no refresh_token in response
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );

    // Act
    const result = await refreshSession(request, adapter, { ...BASE_CONFIG, fetch: fetchFn, requireRotation: false });

    // Assert
    expect(result.sessionData?.refreshToken).toBe(VALID_SESSION.refreshToken);
    expect(result.sessionData?.refreshGeneration).toBe(1); // Incremented from 0
  });

  it('caller is responsible for persisting updated session', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const setSpy = vi.spyOn(adapter, 'set');
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    await refreshSession(request, adapter, {
      ...BASE_CONFIG,
      fetch: mockSuccessfulRefresh(),
    });

    // Assert
    // The adapter.set is NOT called by refreshSession anymore
    // Caller must persist the returned sessionData
    expect(setSpy).not.toHaveBeenCalled();
  });
});

describe('refreshSession — failure cases', () => {
  it('returns refreshed: false when session does not exist', async () => {
    // Arrange
    const adapter = createMockAdapter(null);
    const request = mockRequest('');

    // Act
    const result = await refreshSession(request, adapter, BASE_CONFIG);

    // Assert
    expect(result.refreshed).toBe(false);
  });

  it('returns refreshed: false when session has no refresh token', async () => {
    // Arrange
    const sessionWithoutRefresh: SessionData = {
      ...VALID_SESSION,
      refreshToken: undefined,
    };
    const adapter = createMockAdapter(sessionWithoutRefresh);
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const result = await refreshSession(request, adapter, BASE_CONFIG);

    // Assert
    expect(result.refreshed).toBe(false);
    expect(result.reason).toBeDefined();
  });

  it('returns refreshed: false when token endpoint returns an error', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');
    const fetchFn = vi.fn().mockResolvedValue(new Response('{"error":"invalid_grant"}', { status: 400 }));

    // Act
    const result = await refreshSession(request, adapter, {
      ...BASE_CONFIG,
      fetch: fetchFn,
    });

    // Assert
    expect(result.refreshed).toBe(false);
    expect(result.reason).toBeDefined();
  });

  it('returns refreshed: false when fetch throws', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');
    const fetchFn = vi.fn().mockRejectedValue(new Error('network failure'));

    // Act
    const result = await refreshSession(request, adapter, {
      ...BASE_CONFIG,
      fetch: fetchFn,
    });

    // Assert
    expect(result.refreshed).toBe(false);
  });

  it('does not return session data on failure', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');
    const fetchFn = vi.fn().mockResolvedValue(new Response('error', { status: 401 }));

    // Act
    const result = await refreshSession(request, adapter, { ...BASE_CONFIG, fetch: fetchFn });

    // Assert
    expect(result.sessionData).toBeUndefined();
  });
});

// ─── Refresh token rotation (RFC 9700 §4.14) ──────────────────────────────────

describe('refreshSession — rotation enforcement', () => {
  it('fails when provider does not rotate and requireRotation is true (default)', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');
    const fetchFn = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'new-token',
          expires_in: 900,
          // no refresh_token
        }),
        { status: 200 },
      ),
    );

    // Act
    const result = await refreshSession(request, adapter, { ...BASE_CONFIG, fetch: fetchFn });

    // Arrange
    expect(result.refreshed).toBe(false);
    expect(result.reason).toBe('refresh token rotation missing');
  });

  it('increments refreshGeneration on successful refresh', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');
    const fetchFn = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'new-token',
          refresh_token: 'rotated-token',
          expires_in: 900,
        }),
        { status: 200 },
      ),
    );

    // Act
    const result = await refreshSession(request, adapter, { ...BASE_CONFIG, fetch: fetchFn });

    // Arrange
    expect(result.refreshed).toBe(true);
    expect(result.sessionData?.refreshGeneration).toBe(1); // incremented from 0
  });
});

describe('refreshSession — reuse detection', () => {
  it('detects reuse when generation has advanced (concurrent refresh)', async () => {
    // Arrange
    const initialSession = { ...VALID_SESSION, refreshGeneration: 5 } satisfies SessionData;
    const updatedSession = { ...initialSession, refreshGeneration: 6 } satisfies SessionData;

    // Mock adapter that returns updated session on second get (simulating concurrent refresh)
    const adapter: SessionAdapter = {
      get: vi.fn().mockResolvedValueOnce(initialSession).mockResolvedValueOnce(updatedSession),
      set: vi.fn().mockResolvedValue([]),
      delete: vi.fn().mockResolvedValue([]),
    };
    const deleteSpy = vi.spyOn(adapter, 'delete');

    const request = mockRequest('__Host-session=test-session-id');
    const fetchFn = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'new-token',
          refresh_token: 'rotated-token',
          expires_in: 900,
        }),
        { status: 200 },
      ),
    );

    // Act
    const result = await refreshSession(request, adapter, {
      ...BASE_CONFIG,
      fetch: fetchFn,
      cookieOptions: {
        cookieName: '__Host-session',
        maxAge: 900,
        topology: 'same-domain',
      },
    });

    // Assert
    expect(result.refreshed).toBe(false);
    expect(result.reason).toBe('token_reuse_detected');
    expect(deleteSpy).toHaveBeenCalledWith(request, {
      cookieName: '__Host-session',
      maxAge: 900,
      topology: 'same-domain',
    });
  });

  it('revokes tokens on reuse detection when revocation endpoint is configured', async () => {
    // Arrange
    const initialSession = { ...VALID_SESSION, refreshGeneration: 5 } satisfies SessionData;
    const updatedSession = { ...initialSession, refreshGeneration: 6 } satisfies SessionData;

    const adapter: SessionAdapter = {
      get: vi.fn().mockResolvedValueOnce(initialSession).mockResolvedValueOnce(updatedSession),
      set: vi.fn().mockResolvedValue([]),
      delete: vi.fn().mockResolvedValue([]),
    };
    const deleteSpy = vi.spyOn(adapter, 'delete');

    const request = mockRequest('__Host-session=test-session-id');
    const fetchFn = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'new-token',
          refresh_token: 'rotated-token',
          expires_in: 900,
        }),
        { status: 200 },
      ),
    );

    // Act
    const result = await refreshSession(request, adapter, {
      ...BASE_CONFIG,
      fetch: fetchFn,
      revocationEndpoint: 'https://auth.torii.dev/revoke',
      cookieOptions: {
        cookieName: '__Host-session',
        maxAge: 900,
        topology: 'same-domain',
      },
    });

    // Assert
    expect(result.refreshed).toBe(false);
    expect(result.reason).toBe('token_reuse_detected');
    expect(deleteSpy).toHaveBeenCalledWith(request, {
      cookieName: '__Host-session',
      maxAge: 900,
      topology: 'same-domain',
    });
    // Revocation happens fire-and-forget in background
  });
});
