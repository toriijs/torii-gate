/**
 * Memory Adapter Test Suite
 *
 * Runs the full SessionAdapter contract suite from @torii-gate/test-contracts
 * plus memory-specific behaviour (TTL enforcement, size, clear).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MemoryAdapter } from '../src/index';
import { runAdapterContractTests, VALID_SESSION } from '@torii-gate/test-contracts';
import type { CookieOptions } from '@torii-gate/core/adapters/interface';

const DEFAULT_COOKIE_OPTIONS: CookieOptions = {
  cookieName: '__Host-session',
  maxAge: 900,
  topology: 'same-domain',
};

function mockRequest(cookieHeader: string): Request {
  return new Request('https://torii.dev', {
    headers: { cookie: cookieHeader },
  });
}

function extractCookieValue(setCookieHeader: string, cookieName: string): string {
  const match = new RegExp(`${cookieName}=([^;]+)`).exec(setCookieHeader);
  return match?.[1] ?? '';
}

// ─── Contract tests — every adapter must pass these ───────────────────────────

// eslint-disable-next-line vitest/require-hook -- runAdapterContractTests is a test suite generator, not setup
runAdapterContractTests(() => new MemoryAdapter(), { type: 'stateful' });

describe('memoryAdapter — TTL enforcement', () => {
  let adapter: MemoryAdapter;

  beforeEach(() => {
    adapter = new MemoryAdapter();
  });

  it('returns null for an expired session (expiresAt in the past)', async () => {
    // Arrange
    const expiredSession = { ...VALID_SESSION, expiresAt: Date.now() - 1000 };
    const headers = await adapter.set(expiredSession, DEFAULT_COOKIE_OPTIONS);
    const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
    const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);

    // Act
    const result = await adapter.get(request);

    // Assert
    expect(result).toBeNull();
  });

  it('removes expired entry from internal store on get()', async () => {
    // Arrange
    const expiredSession = { ...VALID_SESSION, expiresAt: Date.now() - 1000 };
    const headers = await adapter.set(expiredSession, DEFAULT_COOKIE_OPTIONS);
    const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
    const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);

    // Act
    await adapter.get(request); // triggers lazy cleanup

    // Assert
    expect(adapter.size).toBe(0);
  });
});

describe('memoryAdapter — size and clear', () => {
  let adapter: MemoryAdapter;

  beforeEach(() => {
    adapter = new MemoryAdapter();
  });

  it('size returns number of active sessions', async () => {
    // Arrange
    await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);

    // Act & Assert
    expect(adapter.size).toBe(2);
  });

  it('size excludes expired sessions', async () => {
    // Arrange
    await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const expiredSession = { ...VALID_SESSION, expiresAt: Date.now() - 1000 };
    await adapter.set(expiredSession, DEFAULT_COOKIE_OPTIONS);

    // Act & Assert
    expect(adapter.size).toBe(1);
  });

  it('size is 0 after clear()', async () => {
    // Arrange
    await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    adapter.clear();

    // Act & Assert
    expect(adapter.size).toBe(0);
  });

  it('get() returns null after clear()', async () => {
    // Arrange
    const headers = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
    const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);

    adapter.clear();

    // Act & Assert
    await expect(adapter.get(request)).resolves.toBeNull();
  });
});

describe('memoryAdapter — session rotation RFC 9700 §7', () => {
  let adapter: MemoryAdapter;

  beforeEach(() => {
    adapter = new MemoryAdapter();
  });

  it('creates a new session with a different ID', async () => {
    // Arrange
    const headers1 = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const oldCookieValue = extractCookieValue(headers1[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
    const requestWithOld = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${oldCookieValue}`);

    // Act
    const updatedSession = { ...VALID_SESSION, accessToken: 'new-token', refreshGeneration: 1 };
    const headers2 = await adapter.rotate(requestWithOld, updatedSession, DEFAULT_COOKIE_OPTIONS);
    const newCookieValue = extractCookieValue(headers2[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);

    // Assert
    expect(newCookieValue).not.toBe(oldCookieValue);
    expect(newCookieValue).toHaveLength(64);
  });

  it('deletes the old session', async () => {
    // Arrange
    const headers1 = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const oldCookieValue = extractCookieValue(headers1[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
    const requestWithOld = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${oldCookieValue}`);

    const updatedSession = { ...VALID_SESSION, accessToken: 'new-token', refreshGeneration: 1 };
    await adapter.rotate(requestWithOld, updatedSession, DEFAULT_COOKIE_OPTIONS);

    // Act - Old session ID should no longer be valid
    const result = await adapter.get(requestWithOld);

    // Assert
    expect(result).toBeNull();
  });

  it('returns updated session data when accessed with new cookie', async () => {
    // Arrange
    const headers1 = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const oldCookieValue = extractCookieValue(headers1[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
    const requestWithOld = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${oldCookieValue}`);

    const updatedSession = { ...VALID_SESSION, accessToken: 'new-token', refreshGeneration: 1 };
    const headers2 = await adapter.rotate(requestWithOld, updatedSession, DEFAULT_COOKIE_OPTIONS);
    const newCookieValue = extractCookieValue(headers2[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
    const requestWithNew = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${newCookieValue}`);

    // Act
    const retrieved = await adapter.get(requestWithNew);

    // Assert
    expect(retrieved).toStrictEqual(updatedSession);
    expect(retrieved?.accessToken).toBe('new-token');
    expect(retrieved?.refreshGeneration).toBe(1);
  });

  it('maintains session count at 1 (old deleted, new created)', async () => {
    // Arrange
    const headers1 = await adapter.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const oldCookieValue = extractCookieValue(headers1[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
    const requestWithOld = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${oldCookieValue}`);

    // Assert
    expect(adapter.size).toBe(1);

    // Act
    const updatedSession = { ...VALID_SESSION, accessToken: 'new-token', refreshGeneration: 1 };
    await adapter.rotate(requestWithOld, updatedSession, DEFAULT_COOKIE_OPTIONS);

    // Assert
    expect(adapter.size).toBe(1);
  });
});

describe('memoryAdapter — production guard', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('throws when NODE_ENV=production without allowInProduction', () => {
    // Arrange
    vi.stubEnv('NODE_ENV', 'production');

    // Act & Assert
    expect(() => new MemoryAdapter()).toThrow('[torii] MemoryAdapter is not safe for production use');
  });

  it('succeeds in production when allowInProduction is true', () => {
    // Arrange
    vi.stubEnv('NODE_ENV', 'production');

    // Act & Assert
    expect(() => new MemoryAdapter({ allowInProduction: true })).not.toThrow();
  });

  it('succeeds in development without allowInProduction', () => {
    // Arrange
    vi.stubEnv('NODE_ENV', 'development');

    // Act & Assert
    expect(() => new MemoryAdapter()).not.toThrow();
  });

  it('succeeds in test without allowInProduction', () => {
    // Arrange
    vi.stubEnv('NODE_ENV', 'test');

    // Act & Assert
    expect(() => new MemoryAdapter()).not.toThrow();
  });

  it('succeeds when NODE_ENV is undefined', () => {
    // Act & Assert - Don't stub NODE_ENV — let it be undefined
    expect(() => new MemoryAdapter()).not.toThrow();
  });
});

describe('memoryAdapter — instance isolation', () => {
  it('two adapter instances do not share sessions', async () => {
    // Arrange
    const a1 = new MemoryAdapter();
    const a2 = new MemoryAdapter();

    const headers = await a1.set(VALID_SESSION, DEFAULT_COOKIE_OPTIONS);
    const cookieValue = extractCookieValue(headers[0]!, DEFAULT_COOKIE_OPTIONS.cookieName);
    const request = mockRequest(`${DEFAULT_COOKIE_OPTIONS.cookieName}=${cookieValue}`);

    // Act & Assert
    await expect(a1.get(request)).resolves.toStrictEqual(VALID_SESSION);
    await expect(a2.get(request)).resolves.toBeNull();
  });
});
