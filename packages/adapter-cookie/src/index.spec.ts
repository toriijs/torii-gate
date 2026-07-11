/**
 * CookieAdapter Test Suite
 *
 * Covers: encryption round-trips, expiry, chunk partitioning for large payloads,
 * chunk reassembly, partial chunk clearing, and security properties.
 */

import { describe, it, expect } from 'vitest';
import { CookieAdapter } from '../src/index';
import type { SessionData, CookieOptions } from '@torii-gate/core/adapters/interface';
import { runAdapterContractTests, VALID_SESSION } from '@torii-gate/test-contracts';

const SECRET = 'test-secret-for-cookie-adapter-min-32!!';

const DEFAULT_COOKIE_OPTIONS: CookieOptions = {
  cookieName: '__Host-session',
  maxAge: 900,
  topology: 'same-domain',
};

// Helper to create a mock Request with Cookie header
function mockRequest(cookieHeader: string): Request {
  return new Request('https://example.com', {
    headers: { cookie: cookieHeader },
  });
}

// Helper to extract cookie name=value pairs from Set-Cookie headers
function extractCookieHeader(setCookieHeaders: string[]): string {
  return setCookieHeaders.map((h) => h.split(';')[0] ?? '').join('; ');
}

// ─── Contract tests — every adapter must pass these ───────────────────────────

runAdapterContractTests(() => new CookieAdapter({ secret: SECRET }), { type: 'stateless' });

// ─── Encryption round-trip ────────────────────────────────────────────────────

describe('CookieAdapter — encryption', () => {
  it('set() returns at least one Set-Cookie header', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET });

    // Act
    const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);

    // Assert
    expect(headers.length).toBeGreaterThanOrEqual(1);
    expect(headers[0]).toMatch(/^__Host-session=/);
  });

  it('round-trips a session through set/get', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET });
    const setCookieHeaders = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const cookieHeader = extractCookieHeader(setCookieHeaders);
    const request = mockRequest(cookieHeader);

    // Act
    const result = await adapter.get(request);

    // Assert
    expect(result).not.toBeNull();
    expect(result?.accessToken).toBe(VALID_SESSION.accessToken);
    expect(result?.refreshToken).toBe(VALID_SESSION.refreshToken);
  });

  it('returns null for empty request (no cookies)', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET });
    const request = mockRequest('');

    // Act
    const result = await adapter.get(request);

    // Assert
    expect(result).toBeNull();
  });

  it('returns null for a tampered cookie value', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET });
    const request = mockRequest('__Host-session=tampered-value-AAAA');

    // Act
    const result = await adapter.get(request);

    // Assert
    expect(result).toBeNull();
  });

  it('returns null for an expired session', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET });
    const expired: SessionData = { ...VALID_SESSION, expiresAt: Date.now() - 1 };
    const setCookieHeaders = await adapter.set(expired, DEFAULT_COOKIE_OPTIONS);
    const cookieHeader = extractCookieHeader(setCookieHeaders);
    const request = mockRequest(cookieHeader);

    // Act
    const result = await adapter.get(request);

    // Assert
    expect(result).toBeNull();
  });

  it('returns null when decrypted with wrong secret', async () => {
    // Arrange
    const adapter1 = new CookieAdapter({ secret: SECRET });
    const adapter2 = new CookieAdapter({ secret: 'different-secret-min-32-characters!!' });

    const setCookieHeaders = await adapter1.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const cookieHeader = extractCookieHeader(setCookieHeaders);
    const request = mockRequest(cookieHeader);

    // Act
    const result = await adapter2.get(request);

    // Assert
    expect(result).toBeNull();
  });
});

describe('CookieAdapter — chunk partitioning', () => {
  it('small payload fits in one cookie — no chunk suffix', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET });

    // Act
    const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);

    // Assert
    expect(headers).toHaveLength(1);
    expect(headers[0]).toMatch(/^__Host-session=/);
    expect(headers[0]).not.toMatch(/^__Host-session\.\d=/);
  });

  it('large payload splits across multiple numbered cookies', async () => {
    // Arrange - chunkSize=100 forces chunking for any real session payload
    const adapter = new CookieAdapter({ secret: SECRET, chunkSize: 100 });

    // Act
    const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);

    // Assert
    expect(headers.length).toBeGreaterThan(1);
    expect(headers[0]).toMatch(/^__Host-session\.0=/);
    expect(headers[1]).toMatch(/^__Host-session\.1=/);
  });

  it('each chunk cookie has all security attributes', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET, chunkSize: 100 });

    // Act
    const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);

    // Assert
    expect(headers.every((h) => /HttpOnly/i.test(h))).toBe(true);
    expect(headers.every((h) => /Secure/i.test(h))).toBe(true);
    expect(headers.every((h) => /Path=\//i.test(h))).toBe(true);
    expect(headers.every((h) => /SameSite=Strict/i.test(h))).toBe(true);
  });

  it('round-trips a chunked session through set/get', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET, chunkSize: 100 });
    const setCookieHeaders = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const cookieHeader = extractCookieHeader(setCookieHeaders);
    const request = mockRequest(cookieHeader);

    // Act
    const result = await adapter.get(request);

    // Assert
    expect(result).not.toBeNull();
    expect(result?.accessToken).toBe(VALID_SESSION.accessToken);
    expect(result?.refreshToken).toBe(VALID_SESSION.refreshToken);
    expect(result?.idToken).toBe(VALID_SESSION.idToken);
  });

  it('reassembles chunks regardless of order in Cookie header', async () => {
    // Arrange - Browsers don't guarantee cookie order — adapter must use index not position
    const adapter = new CookieAdapter({ secret: SECRET, chunkSize: 100 });
    const setCookieHeaders = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const values = setCookieHeaders.map((h) => h.split(';')[0] ?? '');
    // Reverse the chunk order in the cookie header
    const reversedCookieHeader = [...values].reverse().join('; ');
    const request = mockRequest(reversedCookieHeader);

    // Act
    const result = await adapter.get(request);

    // Assert - Still reassembles correctly because adapter uses .0, .1, .2 keys
    expect(result).not.toBeNull();
    expect(result?.accessToken).toBe(VALID_SESSION.accessToken);
  });

  it('custom chunkSize is respected', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET, chunkSize: 200 });

    // Act
    const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);

    const values = headers.map((h) => (h.split(';')[0] ?? '').split('=').slice(1).join('='));

    // Assert
    expect(values.every((v) => v.length <= 200)).toBe(true);
  });

  it('large real-world payload (Keycloak-sized) round-trips correctly', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET });
    // Simulate a large Keycloak session with many claims
    const largeSession: SessionData = {
      ...VALID_SESSION,
      accessToken: 'a'.repeat(2000), // ~2KB access token
      idToken: 'b'.repeat(1500), // ~1.5KB ID token
      refreshToken: 'c'.repeat(400), // ~400 byte refresh token
    };

    const setCookieHeaders = await adapter.set(largeSession, DEFAULT_COOKIE_OPTIONS);
    const cookieHeader = extractCookieHeader(setCookieHeaders);
    const request = mockRequest(cookieHeader);

    // Act
    const result = await adapter.get(request);

    // Assert
    expect(result).not.toBeNull();
    expect(result?.accessToken).toBe(largeSession.accessToken);
    expect(result?.idToken).toBe(largeSession.idToken);
    expect(result?.refreshToken).toBe(largeSession.refreshToken);
  });
});

describe('CookieAdapter — delete', () => {
  it('clears the base cookie for a single-chunk session', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET });
    const setHeaders = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const cookieHeader = extractCookieHeader(setHeaders);
    const request = mockRequest(cookieHeader);

    // Act
    const clearHeaders = await adapter.delete(request, DEFAULT_COOKIE_OPTIONS);

    // Assert
    expect(clearHeaders).toHaveLength(1);
    expect(clearHeaders[0]).toMatch(/^__Host-session=;/);
    expect(clearHeaders[0]).toMatch(/Max-Age=0/);
  });

  it('clears all chunk cookies for a multi-chunk session', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET, chunkSize: 100 });
    const setHeaders = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const cookieHeader = extractCookieHeader(setHeaders);
    const request = mockRequest(cookieHeader);

    // Act
    const clearHeaders = await adapter.delete(request, DEFAULT_COOKIE_OPTIONS);

    // Assert
    expect(clearHeaders).toHaveLength(setHeaders.length);
    expect(clearHeaders.every((h) => h.includes('Max-Age=0'))).toBe(true);
  });

  it('defensively clears base + chunks 0-9 when no cookies present', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET });
    const emptyRequest = mockRequest('');

    // Act
    const clearHeaders = await adapter.delete(emptyRequest, DEFAULT_COOKIE_OPTIONS);

    // Assert
    expect(clearHeaders.length).toBe(11); // base + 10 chunks
    expect(clearHeaders.every((h) => h.includes('Max-Age=0'))).toBe(true);
  });

  it('cleared cookies retain security attributes', async () => {
    // Arrange
    const adapter = new CookieAdapter({ secret: SECRET });
    const emptyRequest = mockRequest('');

    // Act
    const clearHeaders = await adapter.delete(emptyRequest, DEFAULT_COOKIE_OPTIONS);

    // Assert
    expect(clearHeaders.every((h) => /HttpOnly/i.test(h))).toBe(true);
    expect(clearHeaders.every((h) => /Secure/i.test(h))).toBe(true);
    expect(clearHeaders.every((h) => /Path=\//i.test(h))).toBe(true);
  });
});

// ─── Constructor validation ───────────────────────────────────────────────────

describe('CookieAdapter — constructor', () => {
  it('throws when secret is shorter than 32 characters', () => {
    expect(() => new CookieAdapter({ secret: 'short' })).toThrow(/32/);
  });

  it('accepts exactly 32 character secret', () => {
    expect(() => new CookieAdapter({ secret: 'a'.repeat(32) })).not.toThrow();
  });

  it('accepts custom cookieName starting with __Host-', () => {
    const adapter = new CookieAdapter({
      secret: SECRET,
      cookieName: '__Host-my-app-session',
    });
    expect(adapter).toBeDefined();
  });
});
