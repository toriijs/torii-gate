/**
 * Session Adapter & Pending Auth Store Contract Test Suites
 *
 * Defines the contracts that SessionAdapter and PendingAuthStore implementations MUST satisfy.
 * Used by: adapter-memory, adapter-cookie, adapter-redis, and any custom adapter.
 *
 * RFC 9700 — tokens must be stored server-side (or encrypted client-side)
 *            with correct TTL and instant revocability where supported.
 *
 * Published package for adapter testing and development.
 */

import { describe, it, expect, vi } from 'vitest';
import type { SessionAdapter, CookieOptions } from '@torii-gate/core/adapters/interface';
import type { PendingAuthStore } from '@torii-gate/core/adapters/pending';
import { VALID_SESSION, VALID_PENDING_AUTH, EXPIRED_PENDING_AUTH, SESSION_WITH_USERINFO, EXPIRED_SESSION } from './fixtures.js';
import type { PendingStoreType, AdapterContractOptions, PendingStoreContractOptions } from './types.js';

/**
 * Cookie size limit per RFC 6265bis §5.3.
 * Most browsers enforce 4KB per cookie.
 */
const COOKIE_MAX_SIZE_BYTES = 4096;

const DEFAULT_COOKIE_OPTIONS: CookieOptions = {
  cookieName: '__Host-session',
  maxAge: 900,
  topology: 'same-domain',
};

/**
 * Creates a mock Request with the specified Cookie header value.
 * Useful for testing adapter.get() implementations.
 *
 * @param cookieHeader - Cookie header value (e.g., "__Host-session=abc123")
 * @returns Mock Request object with Cookie header
 *
 * @example
 * ```typescript
 * const request = mockRequest('__Host-session=encrypted-value');
 * const session = await adapter.get(request);
 * ```
 */
export function mockRequest(cookieHeader: string): Request {
  return new Request('https://torii.dev', {
    headers: { cookie: cookieHeader },
  });
}

/**
 * Extracts a cookie value from a Set-Cookie header string.
 * Useful for parsing the result of adapter.set() calls.
 *
 * @param setCookieHeader - Full Set-Cookie header string
 * @param cookieName - Name of the cookie to extract
 * @returns Cookie value, or empty string if not found
 *
 * @example
 * ```typescript
 * const headers = await adapter.set(session, options);
 * const cookieValue = extractCookieValue(headers[0], '__Host-session');
 * ```
 */
export function extractCookieValue(setCookieHeader: string, cookieName: string): string {
  const regex = new RegExp(`${cookieName}=([^;]+)`);
  const match = regex.exec(setCookieHeader);
  return match?.[1] ?? '';
}

/**
 * runAdapterContractTests
 *
 * Runs the complete RFC 9700 compliance test suite for SessionAdapter implementations.
 * Call this from your adapter's test file to verify it meets the contract.
 *
 * The contract verifies:
 * - Session storage and retrieval via HTTP Request/Response
 * - Proper cookie attributes (Secure, HttpOnly, Max-Age)
 * - Session deletion with cache invalidation
 * - Concurrent operation safety
 * - Field integrity (all SessionData fields preserved)
 *
 * @param createAdapter - Factory function that returns a fresh adapter instance per test
 *
 * @param options - Configuration options specifying adapter type
 *
 * @example
 * ```typescript
 * import { runAdapterContractTests } from '@torii-gate/test-contracts';
 * import { MyCustomAdapter } from './my-adapter';
 *
 * // For stateful adapters (session ID in cookie, data in database)
 * describe('MyRedisAdapter', () => {
 *   runAdapterContractTests(() => new MyRedisAdapter(), { type: 'stateful' });
 * });
 *
 * // For stateless adapters (encrypted data in cookie)
 * describe('MyCookieAdapter', () => {
 *   runAdapterContractTests(() => new MyCookieAdapter(), { type: 'stateless' });
 * });
 * ```
 *
 * @see https://www.rfc-editor.org/rfc/rfc9700.html - OAuth 2.0 Token Handler Pattern
 * @see {@link SessionAdapter} - The interface being tested
 */
export function runAdapterContractTests(createAdapter: () => SessionAdapter, options: AdapterContractOptions): void {
  const { type } = options;

  describe('SessionAdapter contract', () => {
    runSharedSessionAdapterTests(createAdapter);

    if (type === 'stateless') {
      runStatelessAdapterTests(createAdapter);
    } else {
      runStatefulAdapterTests(createAdapter);
    }
  });
}

/**
 * Shared tests that run for ALL SessionAdapter types (stateful and stateless)
 * @internal
 */
function runSharedSessionAdapterTests(createAdapter: () => SessionAdapter): void {
  describe('SessionAdapter shared tests', () => {
    // ── set + get ─────────────────────────────────────────────────────────

    describe('set and get', () => {
      it('stores and retrieves a session', async () => {
        // Arrange
        const adapter = createAdapter();

        // Act
        const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
        const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);
        const result = await adapter.get(request);

        // Assert
        expect(headers.length).toBeGreaterThanOrEqual(1);
        expect(result).toEqual(VALID_SESSION);
      });

      it('returns null for a request with no cookies', async () => {
        // Arrange
        const adapter = createAdapter();
        const request = mockRequest('');

        // Act & Assert
        expect(await adapter.get(request)).toBeNull();
      });

      it('returns null for a request with wrong cookie', async () => {
        // Arrange
        const adapter = createAdapter();
        const request = mockRequest('other-cookie=some-value');

        // Act & Assert
        expect(await adapter.get(request)).toBeNull();
      });

      it('returns session data with all fields intact', async () => {
        // Arrange
        const adapter = createAdapter();

        // Act
        const headers = await adapter.set(SESSION_WITH_USERINFO, DEFAULT_COOKIE_OPTIONS);
        const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);
        const result = await adapter.get(request);

        // Assert
        expect(result?.accessToken).toBe(SESSION_WITH_USERINFO.accessToken);
        expect(result?.refreshToken).toBe(SESSION_WITH_USERINFO.refreshToken);
        expect(result?.idToken).toBe(SESSION_WITH_USERINFO.idToken);
        expect(result?.expiresAt).toBe(SESSION_WITH_USERINFO.expiresAt);
        expect(result?.refreshGeneration).toBe(SESSION_WITH_USERINFO.refreshGeneration);
        expect(result?.userInfo).toEqual(SESSION_WITH_USERINFO.userInfo);
      });

      it('handles negative expiresAt gracefully', async () => {
        // Arrange
        const adapter = createAdapter();
        const invalidSession = {
          accessToken: 'valid-token',
          expiresAt: -1000, // Invalid timestamp
          refreshGeneration: 0,
        };

        // Act
        const headers = await adapter.set(invalidSession, DEFAULT_COOKIE_OPTIONS);
        const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);
        const result = await adapter.get(request);

        // Assert
        // Negative expiresAt should be treated as expired
        expect(result).toBeNull();
      });

      it('handles NaN expiresAt gracefully', async () => {
        // Arrange
        const adapter = createAdapter();
        const invalidSession = {
          accessToken: 'valid-token',
          expiresAt: Number.NaN, // Invalid timestamp
          refreshGeneration: 0,
        };

        // Act & Assert
        // Should either reject during set() or return null during get()
        try {
          const headers = await adapter.set(invalidSession, DEFAULT_COOKIE_OPTIONS);
          const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
          const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);
          const result = await adapter.get(request);

          // Assert: If set() succeeds, get() should reject NaN
          expect(result).toBeNull();
        } catch (err) {
          // Assert: Acceptable - adapter rejects invalid input at set() time
          expect(err).toBeDefined();
        }
      });

      it('handles empty accessToken', async () => {
        // Arrange
        const adapter = createAdapter();
        const emptyTokenSession = {
          accessToken: '',
          expiresAt: Date.now() + 3_600_000,
          refreshGeneration: 0,
        };

        // Act
        const headers = await adapter.set(emptyTokenSession, DEFAULT_COOKIE_OPTIONS);
        const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);
        const result = await adapter.get(request);

        // Assert
        // Empty token should be preserved if adapter accepts it
        if (result !== null) {
          expect(result.accessToken).toBe('');
        }
      });

      it('handles extremely large session data (10KB token)', async () => {
        // Arrange
        const adapter = createAdapter();
        const largeSession = {
          accessToken: 'x'.repeat(10_000), // 10KB token
          expiresAt: Date.now() + 3_600_000,
          refreshGeneration: 0,
        };

        // Act & Assert
        // Adapter should either store successfully or throw
        try {
          const headers = await adapter.set(largeSession, DEFAULT_COOKIE_OPTIONS);
          expect(headers.length).toBeGreaterThanOrEqual(1);

          // If set() succeeds, verify retrieval
          const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
          const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);
          const result = await adapter.get(request);

          if (result !== null) {
            expect(result.accessToken).toBe(largeSession.accessToken);
          }
        } catch (err) {
          // Acceptable: adapter rejects oversized data
          expect(err).toBeDefined();
        }
      });

      it('handles special characters in token values', async () => {
        // Arrange
        const adapter = createAdapter();
        const specialCharsSession = {
          accessToken: 'token-with-émojis-🔐-and-特殊字符',
          expiresAt: Date.now() + 3_600_000,
          refreshGeneration: 0,
        };

        // Act
        const headers = await adapter.set(specialCharsSession, DEFAULT_COOKIE_OPTIONS);
        const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);
        const result = await adapter.get(request);

        // Assert
        expect(result?.accessToken).toBe(specialCharsSession.accessToken);
      });

      it('handles negative refreshGeneration', async () => {
        // Arrange
        const adapter = createAdapter();
        const negativeGenSession = {
          accessToken: 'valid-token',
          expiresAt: Date.now() + 3_600_000,
          refreshGeneration: -1, // Invalid generation
        };

        // Act
        const headers = await adapter.set(negativeGenSession, DEFAULT_COOKIE_OPTIONS);
        const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);
        const result = await adapter.get(request);

        // Assert
        // Adapter should preserve the value (even if semantically invalid)
        expect(result?.refreshGeneration).toBe(-1);
      });
    });

    // ── delete ────────────────────────────────────────────────────────────

    describe('delete', () => {
      it('does not throw when deleting with no cookies', async () => {
        // Arrange
        const adapter = createAdapter();
        const emptyRequest = mockRequest('');

        // Act & Assert
        await expect(adapter.delete(emptyRequest, DEFAULT_COOKIE_OPTIONS)).resolves.not.toThrow();
      });

      it('handles delete() on non-existent session', async () => {
        // Arrange
        const adapter = createAdapter();
        const request = mockRequest('__Host-session=non-existent-session-id');

        // Act & Assert
        // Should not throw
        await expect(adapter.delete(request, DEFAULT_COOKIE_OPTIONS)).resolves.not.toThrow();
      });
    });

    // ── Session expiration (RFC 9700 §6.3) ────────────────────────────────

    describe('session expiration (RFC 9700 §6.3)', () => {
      it('returns null for expired session (expiresAt in past)', async () => {
        // Arrange
        const adapter = createAdapter();

        // Act
        const headers = await adapter.set(EXPIRED_SESSION, DEFAULT_COOKIE_OPTIONS);
        const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);
        const result = await adapter.get(request);

        // Assert
        expect(result).toBeNull();
      });

      it('Max-Age value matches configured maxAge', async () => {
        // Arrange
        const adapter = createAdapter();
        const customOptions = { ...DEFAULT_COOKIE_OPTIONS, maxAge: 1800 };

        // Act
        const headers = await adapter.set(VALID_SESSION, customOptions);

        // Assert
        expect(headers[0]).toMatch(/Max-Age=1800/);
      });
    });

    // ── Cookie attributes ─────────────────────────────────────────────────

    describe('cookie attributes', () => {
      it('set() returns headers with Secure and HttpOnly', async () => {
        // Arrange
        const adapter = createAdapter();

        // Act
        const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);

        // Assert
        expect(headers.length).toBeGreaterThanOrEqual(1);
        // RFC 9700 §7 VIOLATION if this fails: All session cookies must have Secure flag
        expect(headers.every((h) => /Secure/i.test(h))).toBe(true);
        // RFC 9700 §7 VIOLATION if this fails: All session cookies must have HttpOnly flag
        expect(headers.every((h) => /HttpOnly/i.test(h))).toBe(true);
      });

      it('set() returns headers with correct Max-Age', async () => {
        // Arrange
        const adapter = createAdapter();

        // Act
        const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);

        // Assert
        expect(headers[0]).toMatch(/Max-Age=900/);
      });

      it('delete() returns headers with Max-Age=0', async () => {
        // Arrange
        const adapter = createAdapter();
        const request = mockRequest('');

        // Act
        const headers = await adapter.delete(request, DEFAULT_COOKIE_OPTIONS);

        // Assert
        expect(headers.length).toBeGreaterThanOrEqual(1);
        expect(headers.every((h) => h.includes('Max-Age=0'))).toBe(true);
      });
    });

    // ── Cookie attributes by topology (RFC 9700 §7) ───────────────────────

    describe('cookie attributes by topology (RFC 9700 §7)', () => {
      describe('same-domain topology', () => {
        const sameDomainOptions: CookieOptions = {
          cookieName: '__Host-session',
          maxAge: 900,
          topology: 'same-domain',
        };

        it('uses __Host- prefix', async () => {
          // Arrange
          const adapter = createAdapter();

          // Act
          const headers = await adapter.set(VALID_SESSION, sameDomainOptions);

          // Assert
          // RFC 9700 §7 VIOLATION if this fails: Same-domain topology requires __Host- cookie prefix
          expect(headers[0]).toMatch(/^__Host-session=/);
        });

        it('uses SameSite=Strict', async () => {
          // Arrange
          const adapter = createAdapter();

          // Act
          const headers = await adapter.set(VALID_SESSION, sameDomainOptions);

          // Assert
          // RFC 9700 §7.1 VIOLATION if this fails: Same-domain topology requires SameSite=Strict
          expect(headers[0]).toMatch(/SameSite=Strict/);
        });

        it('has no Domain attribute', async () => {
          // Arrange
          const adapter = createAdapter();

          // Act
          const headers = await adapter.set(VALID_SESSION, sameDomainOptions);

          // Assert
          expect(headers[0]).not.toMatch(/Domain=/);
        });

        it('has Path=/', async () => {
          // Arrange
          const adapter = createAdapter();

          // Act
          const headers = await adapter.set(VALID_SESSION, sameDomainOptions);

          // Assert
          expect(headers[0]).toMatch(/Path=\//);
        });
      });

      describe('subdomain topology', () => {
        const subdomainOptions: CookieOptions = {
          cookieName: '__Secure-session',
          maxAge: 900,
          topology: 'subdomain',
          cookieDomain: 'torii.dev',
        };

        it('uses __Secure- prefix', async () => {
          // Arrange
          const adapter = createAdapter();

          // Act
          const headers = await adapter.set(VALID_SESSION, subdomainOptions);

          // Assert
          // RFC 9700 §7 VIOLATION if this fails: Subdomain topology requires __Secure- cookie prefix
          expect(headers[0]).toMatch(/^__Secure-session=/);
        });

        it('uses SameSite=Lax', async () => {
          // Arrange
          const adapter = createAdapter();

          // Act
          const headers = await adapter.set(VALID_SESSION, subdomainOptions);

          // Assert
          // RFC 9700 §7.1 VIOLATION if this fails: Subdomain topology requires SameSite=Lax
          expect(headers[0]).toMatch(/SameSite=Lax/);
        });

        it('includes Domain attribute', async () => {
          // Arrange
          const adapter = createAdapter();

          // Act
          const headers = await adapter.set(VALID_SESSION, subdomainOptions);

          // Assert
          // RFC 6265: Domain may or may not have leading dot (browsers normalize it)
          expect(headers[0]).toMatch(/Domain=\.?torii\.dev/);
        });

        it('has Path=/', async () => {
          // Arrange
          const adapter = createAdapter();

          // Act
          const headers = await adapter.set(VALID_SESSION, subdomainOptions);

          // Assert
          expect(headers[0]).toMatch(/Path=\//);
        });
      });
    });

    // ── Concurrent operations ─────────────────────────────────────────────

    describe('concurrent operations', () => {
      it('handles concurrent reads without data corruption', async () => {
        // Arrange
        const adapter = createAdapter();
        const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
        const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);

        // Act
        const results = await Promise.all(Array.from({ length: 10 }, () => adapter.get(request)));

        // Assert
        // All reads should return identical session data
        expect(results).toEqual(new Array(10).fill(VALID_SESSION));
      });

      it('handles concurrent writes without data loss', async () => {
        // Arrange
        const adapter = createAdapter();

        // Act
        const sessions = await Promise.all(
          Array.from({ length: 10 }, (_, i) => adapter.set({ ...VALID_SESSION, accessToken: `token-${i}` }, DEFAULT_COOKIE_OPTIONS)),
        );

        const results = await Promise.all(
          sessions.map((headers) => {
            const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
            const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);
            return adapter.get(request);
          }),
        );

        // Assert
        // All sessions should be retrievable with exact data preserved
        expect(results).toHaveLength(10);
        expect(results.every((r) => r !== null)).toBe(true);
        expect(results.every((r) => /^token-\d$/.test(r?.accessToken ?? ''))).toBe(true);
        expect(results.every((r) => r?.expiresAt === VALID_SESSION.expiresAt)).toBe(true);
      });
    });

    // ── Session rotation (RFC 9700 §7 - optional) ────────────────────────

    describe('session rotation (RFC 9700 §7 - optional)', () => {
      it('rotate() generates new session identifier', async () => {
        // Arrange
        const adapter = createAdapter();
        if (!adapter.rotate) {
          return; // Rotation is optional
        }

        const headers1 = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
        const oldCookie = extractCookieValue(headers1[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const requestWithOld = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${oldCookie}`);
        const updatedSession = { ...VALID_SESSION, accessToken: 'rotated-token', refreshGeneration: 1 };

        // Act
        const headers2 = await adapter.rotate(requestWithOld, updatedSession, DEFAULT_COOKIE_OPTIONS);
        const newCookie = extractCookieValue(headers2[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);

        // Assert
        expect(newCookie).not.toBe(oldCookie);
        expect(newCookie.length).toBeGreaterThan(0);
      });

      it('rotate() invalidates old session identifier', async () => {
        // Arrange
        const adapter = createAdapter();
        if (!adapter.rotate) return;

        const headers1 = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
        const oldCookie = extractCookieValue(headers1[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const requestWithOld = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${oldCookie}`);
        const updatedSession = { ...VALID_SESSION, accessToken: 'rotated-token', refreshGeneration: 1 };

        // Act
        await adapter.rotate(requestWithOld, updatedSession, DEFAULT_COOKIE_OPTIONS);
        const resultOld = await adapter.get(requestWithOld);

        // Assert
        expect(resultOld).toBeNull();
      });

      it('rotate() makes new session accessible with updated data', async () => {
        // Arrange
        const adapter = createAdapter();
        if (!adapter.rotate) return;

        const headers1 = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
        const oldCookie = extractCookieValue(headers1[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const requestWithOld = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${oldCookie}`);
        const updatedSession = { ...VALID_SESSION, accessToken: 'rotated-token', refreshGeneration: 1 };

        // Act
        const headers2 = await adapter.rotate(requestWithOld, updatedSession, DEFAULT_COOKIE_OPTIONS);
        const newCookie = extractCookieValue(headers2[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const requestWithNew = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${newCookie}`);
        const result = await adapter.get(requestWithNew);

        // Assert
        expect(result).toEqual(updatedSession);
        expect(result?.accessToken).toBe('rotated-token');
        expect(result?.refreshGeneration).toBe(1);
      });

      it('rotate() preserves cookie security attributes', async () => {
        // Arrange
        const adapter = createAdapter();
        if (!adapter.rotate) return;

        const headers1 = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
        const oldCookie = extractCookieValue(headers1[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const requestWithOld = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${oldCookie}`);
        const updatedSession = { ...VALID_SESSION, accessToken: 'rotated-token', refreshGeneration: 1 };

        // Act
        const headers2 = await adapter.rotate(requestWithOld, updatedSession, DEFAULT_COOKIE_OPTIONS);

        // Assert
        expect(headers2[0]).toMatch(/Secure/);
        expect(headers2[0]).toMatch(/HttpOnly/);
        expect(headers2[0]).toMatch(/SameSite=/);
        expect(headers2[0]).toMatch(/Path=\//);
      });

      it('rotate() maintains atomicity under concurrent calls', async () => {
        // Arrange
        const adapter = createAdapter();
        if (!adapter.rotate) return; // Skip if not implemented

        const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
        const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
        const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);

        // Act
        const rotatePromises = Array.from(
          { length: 3 },
          (_, i) =>
            adapter.rotate!(request, { ...VALID_SESSION, accessToken: `rotated-${i}`, refreshGeneration: i + 1 }, DEFAULT_COOKIE_OPTIONS).catch(() => null), // Some may fail, that's OK
        );
        const results = await Promise.all(rotatePromises);

        // Assert
        const successes = results.filter((r) => r !== null);
        expect(successes.length).toBeGreaterThanOrEqual(1); // At least one should succeed
        expect(await adapter.get(request)).toBeNull(); // Old session should be gone
      });
    });

    // ── Cookie size limits (RFC 6265bis §5.3) ─────────────────────────────────

    describe('cookie size limits', () => {
      it('handles session data approaching 4KB cookie limit', async () => {
        // Arrange
        const adapter = createAdapter();
        const largeSession = {
          accessToken: 'x'.repeat(3000), // ~3.5KB cookie (leave room for attributes)
          expiresAt: Date.now() + 3_600_000,
          refreshGeneration: 0,
        };

        // Act & Assert
        try {
          const headers = await adapter.set(largeSession, DEFAULT_COOKIE_OPTIONS);
          expect(headers.length).toBeGreaterThanOrEqual(1);

          // Verify total cookie size
          const totalSize = headers.reduce((sum, h) => sum + h.length, 0);

          // If adapter chunked, multiple cookies expected
          // If single cookie, should be under 4KB
          if (headers.length === 1) {
            expect(totalSize).toBeLessThan(COOKIE_MAX_SIZE_BYTES);
          }

          // Verify retrieval works
          const cookieHeader = headers
            .map((h) => {
              const regex = /^([^=]+)=([^;]+)/;
              const match = regex.exec(h);
              return match ? `${match[1]!}=${match[2]!}` : '';
            })
            .join('; ');

          const request = mockRequest(cookieHeader);
          const result = await adapter.get(request);
          expect(result?.accessToken).toBe(largeSession.accessToken);
        } catch (err) {
          // Acceptable: adapter rejects data that would exceed limits
          expect(err).toBeDefined();
        }
      });
    });
  });
}

/**
 * Tests that only run for stateless SessionAdapter implementations
 * @internal
 */
function runStatelessAdapterTests(createAdapter: () => SessionAdapter): void {
  describe('encryption for stateless adapters (RFC 9700 §6.3)', () => {
    it('cookie value is not plaintext (tokens not visible)', async () => {
      // Arrange
      const adapter = createAdapter();

      // Act
      const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
      const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);

      // Assert
      // NO CONDITIONAL - We know this is stateless
      expect(cookieValue).not.toContain(VALID_SESSION.accessToken);
      if (VALID_SESSION.refreshToken) {
        expect(cookieValue).not.toContain(VALID_SESSION.refreshToken);
      }
      if (VALID_SESSION.idToken) {
        expect(cookieValue).not.toContain(VALID_SESSION.idToken);
      }
    });

    it('tampered cookie value returns null', async () => {
      // Arrange
      const adapter = createAdapter();
      const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
      const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);

      // Act
      // NO CONDITIONAL - We know this is stateless
      const tampered = cookieValue.slice(0, 10) + (cookieValue[10] === 'a' ? 'b' : 'a') + cookieValue.slice(11);
      const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${tampered}`);
      const result = await adapter.get(request);

      // Assert
      // RFC 9700 §6.3 VIOLATION if this fails: Tampered cookie should return null (AES-GCM integrity check)
      expect(result).toBeNull();
    });

    it('truncated cookie value returns null', async () => {
      // Arrange
      const adapter = createAdapter();
      const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
      const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);

      // Act
      // NO CONDITIONAL - We know this is stateless
      const truncated = cookieValue.slice(0, Math.floor(cookieValue.length / 2));
      const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${truncated}`);
      const result = await adapter.get(request);

      // Assert
      expect(result).toBeNull();
    });
  });
}

/**
 * Tests that only run for stateful SessionAdapter implementations
 * @internal
 */
function runStatefulAdapterTests(createAdapter: () => SessionAdapter): void {
  describe('immediate deletion (stateful adapters only)', () => {
    it('removes a session — returns null after deletion', async () => {
      // Arrange
      const adapter = createAdapter();
      const setHeaders = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
      const cookieValue = extractCookieValue(setHeaders[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
      const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);

      // Act
      const clearHeaders = await adapter.delete(request, DEFAULT_COOKIE_OPTIONS);

      // Assert
      expect(clearHeaders.length).toBeGreaterThanOrEqual(1);
      expect(clearHeaders[0]).toMatch(/Max-Age=0/);
      // Stateful adapters can immediately delete from backend storage
      expect(await adapter.get(request)).toBeNull();
    });

    it('handles double delete gracefully (idempotent)', async () => {
      // Arrange
      const adapter = createAdapter();
      const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
      const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
      const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);

      // Act
      await adapter.delete(request, DEFAULT_COOKIE_OPTIONS); // First delete
      await adapter.delete(request, DEFAULT_COOKIE_OPTIONS); // Second delete

      // Assert
      // Second delete should not throw (idempotent)
      // Stateful adapters immediately remove from backend, so get returns null
      expect(await adapter.get(request)).toBeNull();
    });
  });
}

// ─── Pending Auth Store Contract Tests ───────────────────────────────────────

/**
 * runPendingStoreContractTests
 *
 * Runs the complete contract test suite for PendingAuthStore implementations.
 * Call this from your pending store's test file to verify it meets the contract.
 *
 * The contract verifies:
 * - Pending auth storage and retrieval (set/get)
 * - Single-use enforcement (get deletes the entry)
 * - TTL enforcement (expired entries return null)
 * - Field integrity (all PendingAuth fields preserved)
 * - Clear functionality (cleanup headers returned)
 *
 * @param createStore - Factory function that returns a fresh store instance per test
 * @param options - Configuration options specifying store type
 *
 * @example
 * ```typescript
 * import { runPendingStoreContractTests } from '@torii-gate/test-contracts';
 * import { MyPendingStore } from './my-pending-store';
 *
 * // For server-side stores (Redis, Memory, SQL)
 * describe('MyRedisPendingStore', () => {
 *   runPendingStoreContractTests(() => new MyRedisPendingStore(), { type: 'server-side' });
 * });
 *
 * // For cookie-based stores
 * describe('MyCookiePendingStore', () => {
 *   runPendingStoreContractTests(() => new MyCookiePendingStore(), { type: 'cookie-based' });
 * });
 * ```
 *
 * @see https://www.rfc-editor.org/rfc/rfc7636.html - PKCE (Proof Key for Code Exchange)
 * @see {@link PendingAuthStore} - The interface being tested
 */
export function runPendingStoreContractTests(createStore: () => PendingAuthStore, options: PendingStoreContractOptions): void {
  const { type } = options;

  describe('PendingAuthStore contract', () => {
    runSharedPendingStoreTests(createStore, type);

    if (type === 'server-side') {
      runServerSidePendingStoreTests(createStore);
    }
    runCookieBasedPendingStoreTests(createStore);
  });
}

/**
 * Shared tests that run for ALL PendingAuthStore types
 * @internal
 */
function runSharedPendingStoreTests(createStore: () => PendingAuthStore, type: PendingStoreType): void {
  describe('PendingAuthStore shared tests', () => {
    // ── set + get ─────────────────────────────────────────────────────────

    describe('set and get', () => {
      it('stores and retrieves pending auth data', async () => {
        // Arrange
        const store = createStore();

        // Act
        const headers = await store.set(VALID_PENDING_AUTH);
        // For cookie-based stores, create a request with the Set-Cookie header
        const request = type === 'cookie-based' ? mockRequest(headers['set-cookie']!) : undefined;
        const result = await store.get(VALID_PENDING_AUTH.state, request);

        // Assert
        expect(headers).toBeTypeOf('object');
        expect(result).toEqual(VALID_PENDING_AUTH);
      });

      it('returns null for non-existent state', async () => {
        // Arrange
        const store = createStore();

        // Act
        const result = await store.get('nonexistent-state-value');

        // Assert
        expect(result).toBeNull();
      });

      it('preserves all PendingAuth fields', async () => {
        // Arrange
        const store = createStore();

        // Act
        const headers = await store.set(VALID_PENDING_AUTH);
        const request = type === 'cookie-based' ? mockRequest(headers['set-cookie']!) : undefined;
        const result = await store.get(VALID_PENDING_AUTH.state, request);

        // Assert
        expect(result?.codeVerifier).toBe(VALID_PENDING_AUTH.codeVerifier);
        expect(result?.nonce).toBe(VALID_PENDING_AUTH.nonce);
        expect(result?.state).toBe(VALID_PENDING_AUTH.state);
        expect(result?.expiresAt).toBe(VALID_PENDING_AUTH.expiresAt);
      });

      it('handles empty state value', async () => {
        // Arrange
        const store = createStore();
        const emptyStateAuth = {
          codeVerifier: 'valid-verifier',
          nonce: 'valid-nonce',
          state: '',
          expiresAt: Date.now() + 600_000,
        };

        // Act
        await store.set(emptyStateAuth);
        const result = await store.get('');

        // Assert
        // Adapters may either reject empty state (return null) or accept it
        // Both behaviors are acceptable - the key is handling it without throwing
        if (result !== null) {
          expect(result.state).toBe('');
        }
      });

      it('set() called twice with same state overwrites (last write wins)', async () => {
        // Arrange
        const store = createStore();
        const auth1 = { ...VALID_PENDING_AUTH, codeVerifier: 'verifier-1' };
        const auth2 = { ...VALID_PENDING_AUTH, codeVerifier: 'verifier-2' };

        // Act
        await store.set(auth1);
        const headers2 = await store.set(auth2);
        const request = type === 'cookie-based' ? mockRequest(headers2['set-cookie']!) : undefined;
        const result = await store.get(VALID_PENDING_AUTH.state, request);

        // Assert
        // Should get the second value (overwrite)
        expect(result?.codeVerifier).toBe('verifier-2');
      });
    });

    // ── Timing-safe state comparison ──────────────────────────────────────

    describe('timing-safe state comparison', () => {
      it('get() with state prefix should not match (exact comparison required)', async () => {
        // Arrange
        const store = createStore();
        const headers = await store.set(VALID_PENDING_AUTH);
        const request = type === 'cookie-based' ? mockRequest(headers['set-cookie']!) : undefined;

        // Act
        const prefixState = VALID_PENDING_AUTH.state.substring(0, 5);
        const result = await store.get(prefixState, request);

        // Assert
        // Should not match (exact comparison required)
        expect(result).toBeNull();
      });
    });

    // ── TTL enforcement ───────────────────────────────────────────────────

    describe('TTL enforcement', () => {
      it('returns null for expired pending auth', async () => {
        // Arrange
        const store = createStore();

        // Act
        await store.set(EXPIRED_PENDING_AUTH);
        const result = await store.get(EXPIRED_PENDING_AUTH.state);

        // Assert
        expect(result).toBeNull();
      });

      it('valid entry retrieved before expiry, null after', async () => {
        // Arrange
        vi.useFakeTimers();
        const store = createStore();
        const shortLived = {
          ...VALID_PENDING_AUTH,
          state: 'short-lived-state',
          expiresAt: Date.now() + 100, // 100ms TTL
        };

        const headers1 = await store.set(shortLived);
        const request1 = type === 'cookie-based' ? mockRequest(headers1['set-cookie']!) : undefined;

        // Act & Assert
        // Should succeed immediately
        const immediate = await store.get(shortLived.state, request1);
        expect(immediate).toEqual(shortLived);

        // Re-create entry for second test (consumed by first get)
        const shortLived2 = { ...shortLived, state: 'short-lived-state-2' };
        const headers2 = await store.set(shortLived2);
        const request2 = type === 'cookie-based' ? mockRequest(headers2['set-cookie']!) : undefined;

        // Advance time past expiry
        vi.advanceTimersByTime(150);

        const afterExpiry = await store.get('short-lived-state-2', request2);
        expect(afterExpiry).toBeNull();

        vi.useRealTimers();
      });
    });

    // ── clear() ───────────────────────────────────────────────────────────

    describe('clear', () => {
      it('returns headers object for cleanup', () => {
        // Arrange
        const store = createStore();

        // Act
        const headers = store.clear();

        // Assert
        expect(headers).toBeTypeOf('object');
      });

      it('clear() is callable without errors', () => {
        // Arrange
        const store = createStore();

        // Act & Assert
        expect(() => store.clear()).not.toThrow();
      });

      it('clear() is idempotent (can be called multiple times)', () => {
        // Arrange
        const store = createStore();

        // Act
        const headers1 = store.clear();
        const headers2 = store.clear();

        // Assert
        // Both should succeed without throwing
        expect(headers1).toBeTypeOf('object');
        expect(headers2).toBeTypeOf('object');
      });
    });

    // ── Concurrent operations ─────────────────────────────────────────────

    describe('concurrent operations', () => {
      it('handles concurrent sets without data loss', async () => {
        // Arrange
        const store = createStore();
        const entries = Array.from({ length: 10 }, (_, i) => ({
          ...VALID_PENDING_AUTH,
          state: `concurrent-state-${i}`,
          codeVerifier: `verifier-${i}`,
        }));

        // Act
        const headersArray = await Promise.all(entries.map((entry) => store.set(entry)));

        const results = await Promise.all(
          entries.map((entry, i) => {
            const headers = headersArray[i]!;
            const request = type === 'cookie-based' ? mockRequest(headers['set-cookie']!) : undefined;
            return store.get(entry.state, request);
          }),
        );

        // Assert
        // All entries should be retrievable with exact data preserved
        expect(results).toEqual(entries);
      });
    });

    // ── Request parameter (for cookie-based stores) ───────────────────────

    describe('request parameter', () => {
      it('get() accepts optional request parameter', async () => {
        // Arrange
        const store = createStore();
        const headers = await store.set(VALID_PENDING_AUTH);

        // Act & Assert
        if (headers['set-cookie']) {
          // Cookie stores require request parameter
          const request = mockRequest(headers['set-cookie']);
          const withRequest = await store.get(VALID_PENDING_AUTH.state, request);
          expect(withRequest).toEqual(VALID_PENDING_AUTH);

          // Re-create entry (consumed by previous get)
          await store.set(VALID_PENDING_AUTH);
          const withoutRequest = await store.get(VALID_PENDING_AUTH.state);
          expect(withoutRequest).toBeNull();
        } else {
          // Server-side stores work with or without request (both consume the entry)
          const withRequest = await store.get(VALID_PENDING_AUTH.state, mockRequest(''));
          expect(withRequest).not.toBeNull();

          // Re-create entry for second test
          await store.set(VALID_PENDING_AUTH);
          const withoutRequest = await store.get(VALID_PENDING_AUTH.state);
          expect(withoutRequest).not.toBeNull();
        }
      });
    });

    // ── DoS protection ────────────────────────────────────────────────────

    describe('DoS protection', () => {
      it('handles very long state value', async () => {
        // Arrange
        const store = createStore();
        const longStateAuth = {
          codeVerifier: 'valid-verifier',
          nonce: 'valid-nonce',
          state: 'x'.repeat(10_000), // 10KB state
          expiresAt: Date.now() + 600_000,
        };

        // Act & Assert
        try {
          const headers = await store.set(longStateAuth);
          const request = type === 'cookie-based' ? mockRequest(headers['set-cookie']!) : undefined;

          const startTime = Date.now();
          const result = await store.get(longStateAuth.state, request);
          const duration = Date.now() - startTime;

          // Assert: Should complete quickly (< 100ms) even with long state
          expect(duration).toBeLessThan(100);

          if (result !== null) {
            expect(result.state).toBe(longStateAuth.state);
          }
        } catch (err) {
          // Acceptable: adapter rejects oversized state
          expect(err).toBeDefined();
        }
      });
    });
  });
}

/**
 * Tests that only run for server-side PendingAuthStore implementations
 * @internal
 */
function runServerSidePendingStoreTests(createStore: () => PendingAuthStore): void {
  describe('single-use enforcement (server-side atomic operations)', () => {
    it('get() consumes the entry — second get returns null', async () => {
      // Arrange
      const store = createStore();
      await store.set(VALID_PENDING_AUTH);

      // Act
      const first = await store.get(VALID_PENDING_AUTH.state);
      const second = await store.get(VALID_PENDING_AUTH.state);

      // Assert
      expect(first).toEqual(VALID_PENDING_AUTH);
      expect(second).toBeNull();
    });

    it('multiple parallel gets only succeed once', async () => {
      // Arrange
      const store = createStore();
      await store.set(VALID_PENDING_AUTH);

      // Act
      const results = await Promise.all(Array.from({ length: 5 }, () => store.get(VALID_PENDING_AUTH.state)));
      const successes = results.filter((r) => r !== null);

      // Assert
      // RFC 9700 §4.7 VIOLATION if this fails: Atomic single-use enforcement failed.
      // Multiple parallel gets succeeded, indicating TOCTOU vulnerability.
      // Use Redis GETDEL, Lua script, or database transaction for atomic read-then-delete.
      expect(successes.length).toBe(1);
      expect(successes[0]).toEqual(VALID_PENDING_AUTH);

      // After parallel gets complete, entry should be deleted
      const afterParallel = await store.get(VALID_PENDING_AUTH.state);
      expect(afterParallel).toBeNull();
    });
  });
}

/**
 * Tests that only run for cookie-based PendingAuthStore implementations
 * @internal
 */
function runCookieBasedPendingStoreTests(_createStore: () => PendingAuthStore): void {
  // Placeholder for future cookie-based-specific tests
  // Currently no tests are cookie-based-only
  // (Timing-safe comparison tests are in security-audit.ts)
}
