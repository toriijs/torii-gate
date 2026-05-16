/**
 * Logout Test Suite
 *
 * RFC 9700  — session must be invalidated on logout
 * RFC 7009  — OAuth 2.0 Token Revocation
 * OpenID Connect Session Management — end_session_endpoint
 */

import { describe, it, expect, vi } from 'vitest';
import { handleLogout } from './logout.js';
import type { SessionData, CookieOptions } from '../../src/adapters/interface';
import { createMockAdapter } from '../../tests/fixtures/fixtures.js';

const VALID_SESSION = {
  accessToken: 'access-token',
  refreshToken: 'refresh-token',
  idToken: 'header.eyJub25jZSI6InRlc3QifQ.sig',
  expiresAt: Date.now() + 300_000,
  refreshGeneration: 0,
} satisfies SessionData;

const CLEAR_COOKIE_HEADER = '__Host-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict';

function mockRequest(cookieHeader: string): Request {
  return new Request('https://torii.dev', {
    headers: { cookie: cookieHeader },
  });
}

const BASE_COOKIE_OPTIONS: CookieOptions = {
  cookieName: '__Host-session',
  maxAge: 900,
  topology: 'same-domain',
};

const BASE_CONFIG = {
  clientId: 'my-client',
  postLogoutRedirectUri: 'https://app.torii.dev',
  cookieOptions: BASE_COOKIE_OPTIONS,
};

describe('handleLogout — session deletion', () => {
  it('deletes the session from the adapter', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const deleteSpy = vi.spyOn(adapter, 'delete');
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    await handleLogout(request, adapter, BASE_CONFIG);

    // Assert
    expect(deleteSpy).toHaveBeenCalledWith(request, BASE_COOKIE_OPTIONS);
  });

  it('deletes the session even when tokens cannot be revoked', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const deleteSpy = vi.spyOn(adapter, 'delete');
    const request = mockRequest('__Host-session=test-session-id');
    const config = {
      ...BASE_CONFIG,
      revocationEndpoint: 'https://auth.torii.dev/revoke',
      fetch: vi.fn().mockRejectedValue(new Error('network error')),
    };

    // Act
    await handleLogout(request, adapter, config);

    // Assert - Session deleted despite revocation failure
    expect(deleteSpy).toHaveBeenCalledWith(request, BASE_COOKIE_OPTIONS);
  });

  it('deletes the session even when no session exists in adapter', async () => {
    // Arrange
    const adapter = createMockAdapter(null);
    const deleteSpy = vi.spyOn(adapter, 'delete');
    const request = mockRequest('');

    // Act & Assert
    await expect(handleLogout(request, adapter, BASE_CONFIG)).resolves.not.toThrow();
    expect(deleteSpy).toHaveBeenCalledWith(request, BASE_COOKIE_OPTIONS);
  });
});

describe('handleLogout — clear cookie header', () => {
  it('returns Set-Cookie headers to clear the session cookie', async () => {
    const adapter = createMockAdapter(VALID_SESSION, { deleteHeaders: [CLEAR_COOKIE_HEADER] });
    const request = mockRequest('__Host-session=test-session-id');
    const { clearCookieHeaders } = await handleLogout(request, adapter, BASE_CONFIG);

    expect(clearCookieHeaders).toHaveLength(1);
    expect(clearCookieHeaders[0]).toContain('__Host-session=');
    expect(clearCookieHeaders[0]).toContain('Max-Age=0');
  });

  it('clear cookie retains all security flags', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION, { deleteHeaders: [CLEAR_COOKIE_HEADER] });
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const { clearCookieHeaders } = await handleLogout(request, adapter, BASE_CONFIG);

    const header = clearCookieHeaders[0]!;

    // Assert
    expect(header).toMatch(/Secure/i);
    expect(header).toMatch(/HttpOnly/i);
    expect(header).toMatch(/Path=\//i);
    expect(header).not.toMatch(/Domain=/i);
  });

  it('clear cookie includes Domain attribute for subdomain topology', async () => {
    // Arrange
    const subdomainCookieOptions: CookieOptions = {
      cookieName: '__Secure-session',
      maxAge: 900,
      topology: 'subdomain',
      cookieDomain: 'torii.dev',
    };
    const adapter = createMockAdapter(VALID_SESSION);
    vi.spyOn(adapter, 'delete').mockResolvedValue(['__Secure-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=torii.dev']);
    const request = mockRequest('__Secure-session=test-session-id');
    const subdomainConfig = {
      clientId: 'my-client',
      postLogoutRedirectUri: 'https://app.torii.dev',
      cookieOptions: subdomainCookieOptions,
    };

    // Act
    const { clearCookieHeaders } = await handleLogout(request, adapter, subdomainConfig);

    const header = clearCookieHeaders[0]!;

    // Assert
    expect(header).toContain('__Secure-session=');
    expect(header).toMatch(/Secure/i);
    expect(header).toMatch(/HttpOnly/i);
    expect(header).toMatch(/Domain=torii\.dev/i);
    expect(header).toContain('Max-Age=0');
  });
});

describe('handleLogout — redirect URL', () => {
  it('returns postLogoutRedirectUri when no end_session_endpoint', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const { redirectUrl } = await handleLogout(request, adapter, BASE_CONFIG);

    // Assert
    expect(redirectUrl).toBe('https://app.torii.dev');
  });

  it('returns / when no postLogoutRedirectUri and no end_session_endpoint', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const { redirectUrl } = await handleLogout(request, adapter, {
      clientId: 'my-client',
      cookieOptions: BASE_COOKIE_OPTIONS,
    });

    // Assert
    expect(redirectUrl).toBe('/');
  });

  it('builds end_session_endpoint URL when provider supports it', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const { redirectUrl } = await handleLogout(request, adapter, {
      ...BASE_CONFIG,
      endSessionEndpoint: 'https://auth.torii.dev/logout',
    });
    const url = new URL(redirectUrl);

    // Assert
    expect(url.origin + url.pathname).toBe('https://auth.torii.dev/logout');
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe('https://app.torii.dev');
    expect(url.searchParams.get('client_id')).toBe('my-client');
  });

  it('includes id_token_hint in end_session URL', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const { redirectUrl } = await handleLogout(request, adapter, {
      ...BASE_CONFIG,
      endSessionEndpoint: 'https://auth.torii.dev/logout',
    });
    const url = new URL(redirectUrl);

    // Assert
    expect(url.searchParams.get('id_token_hint')).toBe(VALID_SESSION.idToken);
  });
});

// ─── Post-logout redirect allowlist (RFC 9700 §4.11) ─────────────────────────

describe('handleLogout — post-logout redirect allowlist', () => {
  it('accepts redirect URI when it is in the allowlist', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const { redirectUrl } = await handleLogout(request, adapter, {
      ...BASE_CONFIG,
      postLogoutRedirectUri: 'https://app.torii.dev',
      postLogoutRedirectUris: ['https://app.torii.dev', 'https://other.torii.dev'],
    });

    // Assert
    expect(redirectUrl).toBe('https://app.torii.dev');
  });

  it('rejects redirect URI when it is not in the allowlist', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act & Assert
    await expect(
      handleLogout(request, adapter, {
        ...BASE_CONFIG,
        postLogoutRedirectUri: 'https://attacker.com',
        postLogoutRedirectUris: ['https://app.torii.dev'],
      }),
    ).rejects.toThrow('not in the allowlist');
  });

  it('allows redirect when no allowlist is configured — backward compatibility', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const { redirectUrl } = await handleLogout(request, adapter, {
      ...BASE_CONFIG,
      postLogoutRedirectUri: 'https://app.torii.dev',
      // No postLogoutRedirectUris configured
    });

    // Assert
    expect(redirectUrl).toBe('https://app.torii.dev');
  });

  it('validates allowlist when end_session_endpoint is configured', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act & Assert
    await expect(
      handleLogout(request, adapter, {
        ...BASE_CONFIG,
        endSessionEndpoint: 'https://auth.torii.dev/logout',
        postLogoutRedirectUri: 'https://attacker.com',
        postLogoutRedirectUris: ['https://app.torii.dev'],
      }),
    ).rejects.toThrow('not in the allowlist');
  });

  it('normalises trailing slash when matching allowlist entries', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');

    // Act
    const { redirectUrl } = await handleLogout(request, adapter, {
      ...BASE_CONFIG,
      postLogoutRedirectUri: 'https://app.torii.dev/callback',
      postLogoutRedirectUris: ['https://app.torii.dev/callback/'],
    });

    // Assert
    expect(redirectUrl).toBe('https://app.torii.dev/callback');
  });
});

describe('handleLogout — token revocation', () => {
  it('calls revocation endpoint when configured', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));

    // Act
    await handleLogout(request, adapter, {
      ...BASE_CONFIG,
      revocationEndpoint: 'https://auth.torii.dev/revoke',
      fetch: mockFetch,
    });
    // Allow fire-and-forget to settle
    await new Promise((r) => setTimeout(r, 10));

    // Assert - Expect two revocation calls: refresh_token first, then access_token
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(mockFetch).toHaveBeenCalledWith(
      'https://auth.torii.dev/revoke',
      expect.objectContaining({
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      }),
    );
  });

  it('does not call revocation endpoint when not configured', async () => {
    // Arrange
    const adapter = createMockAdapter(VALID_SESSION);
    const request = mockRequest('__Host-session=test-session-id');
    const mockFetch = vi.fn();

    // Act
    await handleLogout(request, adapter, { ...BASE_CONFIG, fetch: mockFetch });
    await new Promise((r) => setTimeout(r, 10));

    // Assert
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
