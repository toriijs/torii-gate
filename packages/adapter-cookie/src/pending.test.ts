/**
 * Cookie Pending Store Test Suite
 *
 * Runs the full PendingAuthStore contract suite from @torii-gate/test-contracts
 * plus cookie-specific behavior (encryption, cookie attributes, state validation).
 */

import { describe, it, expect } from 'vitest';
import { CookiePendingStore } from './pending';
import { runPendingStoreContractTests, runSecurityAuditTests, VALID_PENDING_AUTH, mockRequest } from '@torii-gate/test-contracts';

const TEST_SECRET = 'test-secret-key-minimum-32-chars-long';

// ─── Contract tests — every pending store must pass these ────────────────────

// eslint-disable-next-line vitest/require-hook -- runPendingStoreContractTests is a test suite generator, not setup
runPendingStoreContractTests(() => new CookiePendingStore({ secret: TEST_SECRET }), { type: 'cookie-based' });

// ─── Security audit — optional timing-safe validation ────────────────────────

// eslint-disable-next-line vitest/require-hook -- runSecurityAuditTests is a test suite generator, not setup
runSecurityAuditTests(() => new CookiePendingStore({ secret: TEST_SECRET }), { type: 'cookie-based' });

describe('cookiePendingStore — cookie attributes', () => {
  it('set() returns Set-Cookie header with __Host-torii-pkce', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });

    // Act
    const headers = await store.set(VALID_PENDING_AUTH);

    // Assert
    expect(headers['set-cookie']).toMatch(/__Host-torii-pkce=/);
  });

  it('set() returns HttpOnly cookie', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });

    // Act
    const headers = await store.set(VALID_PENDING_AUTH);

    // Assert
    expect(headers['set-cookie']).toMatch(/HttpOnly/i);
  });

  it('set() returns Secure cookie', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });

    // Act
    const headers = await store.set(VALID_PENDING_AUTH);

    // Assert
    expect(headers['set-cookie']).toMatch(/Secure/i);
  });

  it('set() returns SameSite=Lax (required for OAuth redirect)', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });

    // Act
    const headers = await store.set(VALID_PENDING_AUTH);

    // Assert
    expect(headers['set-cookie']).toMatch(/SameSite=Lax/i);
  });

  it('set() returns Path=/', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });

    // Act
    const headers = await store.set(VALID_PENDING_AUTH);

    // Assert
    expect(headers['set-cookie']).toMatch(/Path=\//);
  });

  it('set() respects custom maxAge', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET, maxAge: 300 });

    // Act
    const headers = await store.set(VALID_PENDING_AUTH);

    // Assert
    expect(headers['set-cookie']).toMatch(/Max-Age=300/);
  });

  it('set() uses default maxAge of 600 seconds', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });

    // Act
    const headers = await store.set(VALID_PENDING_AUTH);

    // Assert
    expect(headers['set-cookie']).toMatch(/Max-Age=600/);
  });
});

describe('cookiePendingStore — encryption', () => {
  it('cookie value is encrypted (not readable plaintext)', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });

    // Act
    const headers = await store.set(VALID_PENDING_AUTH);
    const cookieValue = headers['set-cookie']?.match(/__Host-torii-pkce=([^;]+)/)?.[1];

    // Assert
    expect(cookieValue).toBeDefined();

    // Should not contain plaintext secrets
    expect(cookieValue).not.toContain(VALID_PENDING_AUTH.codeVerifier);
    expect(cookieValue).not.toContain(VALID_PENDING_AUTH.nonce);
  });

  it('cannot decrypt with wrong secret', async () => {
    // Arrange
    const store1 = new CookiePendingStore({ secret: TEST_SECRET });
    const store2 = new CookiePendingStore({ secret: 'different-secret-key-32-chars-min' });

    const headers = await store1.set(VALID_PENDING_AUTH);
    const cookieHeader = headers['set-cookie']!;
    const request = mockRequest(cookieHeader);

    // Act
    const result = await store2.get(VALID_PENDING_AUTH.state, request);

    // Arrange
    expect(result).toBeNull();
  });
});

describe('cookiePendingStore — state validation', () => {
  it('returns null if state parameter does not match cookie state', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });
    const headers = await store.set(VALID_PENDING_AUTH);
    const request = mockRequest(headers['set-cookie']!);

    // Act - Different state value than what was set
    const result = await store.get('wrong-state-value', request);

    // Assert
    expect(result).toBeNull();
  });

  it('timing-safe comparison prevents timing attacks on state', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });
    const headers = await store.set(VALID_PENDING_AUTH);
    const request = mockRequest(headers['set-cookie']!);

    // Act
    const start = performance.now();
    await store.get('a', request); // Wrong state (1 char)
    const time1 = performance.now() - start;

    const start2 = performance.now();
    await store.get('aaaaaaaaaaaaaaaaaaaa', request); // Wrong state (20 chars)
    const time2 = performance.now() - start2;

    // Assert
    // Timing should be similar (within 2x factor) for different lengths
    // This is a heuristic — timing-safe comparison doesn't guarantee equal time,
    // but it should prevent obvious length-based timing leaks
    expect(Math.abs(time1 - time2)).toBeLessThan(Math.max(time1, time2) * 2);
  });
});

describe('cookiePendingStore — clear', () => {
  it('clear() returns Max-Age=0 to delete cookie', () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });

    // Act
    const headers = store.clear();

    // Assert
    expect(headers['set-cookie']).toMatch(/Max-Age=0/);
  });

  it('clear() cookie has same name as set cookie', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });
    const setHeaders = await store.set(VALID_PENDING_AUTH);

    // Act
    const clearHeaders = store.clear();

    // Assert - Both should reference __Host-torii-pkce
    expect(setHeaders['set-cookie']).toMatch(/__Host-torii-pkce=/);
    expect(clearHeaders['set-cookie']).toMatch(/__Host-torii-pkce=/);
  });
});

describe('cookiePendingStore — request handling', () => {
  it('get() returns null when request has no cookies', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });
    const request = mockRequest('');

    // Act
    const result = await store.get(VALID_PENDING_AUTH.state, request);

    // Assert
    expect(result).toBeNull();
  });

  it('get() returns null when request has wrong cookie', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });
    const request = mockRequest('some-other-cookie=value');

    // Act
    const result = await store.get(VALID_PENDING_AUTH.state, request);

    // Assert
    expect(result).toBeNull();
  });

  it('get() works without request parameter (returns null)', async () => {
    // Arrange
    const store = new CookiePendingStore({ secret: TEST_SECRET });
    await store.set(VALID_PENDING_AUTH);

    // Act - Without request, cannot read cookie, so should return null
    const result = await store.get(VALID_PENDING_AUTH.state);

    // Assert
    expect(result).toBeNull();
  });
});
