/**
 * Runtime Initializer Test Suite
 *
 * Tests the lazy singleton pattern and cold start behaviour.
 * Uses _resetRuntime() to isolate each test.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { parse } from 'valibot';
import { getRuntime, deriveSessionKey, _resetRuntime } from './initializer.js';
import { ToriiConfigSchema } from '../../src/config/schema.js';
import type { ToriiConfig } from '../../src/config/schema.js';
import type { SessionAdapter } from '../../src/adapters/interface.js';

const ISSUER = 'https://auth.chathu.me/realms/test';

/**
 * Use parse() to build configs — Valibot fills in all defaults
 * (security, rbac, agentPrefix, proxyPrefix, keyPrefix, maxAge etc.)
 * so the result satisfies ToriiConfig without manually specifying
 * every optional field that has a default value.
 */
const VALID_CONFIG: ToriiConfig = parse(ToriiConfigSchema, {
  oidc: {
    issuer: ISSUER,
    clientId: 'test-client',
    clientSecret: 'test-secret',
    redirectUri: 'https://app.chathu.me/auth/callback',
  },
  session: {
    type: 'cookie',
    secret: 'a'.repeat(32),
  },
  routing: {
    upstreamUrl: 'https://api.chathu.me',
  },
});

const REDIS_CONFIG: ToriiConfig = parse(ToriiConfigSchema, {
  oidc: {
    issuer: ISSUER,
    clientId: 'test-client',
    clientSecret: 'test-secret',
    redirectUri: 'https://app.chathu.me/auth/callback',
  },
  session: {
    type: 'redis',
    url: 'redis://localhost:6379',
    // maxAge and keyPrefix filled by Valibot defaults
  },
  routing: {
    upstreamUrl: 'https://api.chathu.me',
  },
});

const MEMORY_CONFIG: ToriiConfig = parse(ToriiConfigSchema, {
  oidc: {
    issuer: ISSUER,
    clientId: 'test-client',
    clientSecret: 'test-secret',
    redirectUri: 'https://app.chathu.me/auth/callback',
  },
  session: {
    type: 'memory',
    // maxAge filled by Valibot default
  },
  routing: {
    upstreamUrl: 'https://api.chathu.me',
  },
});

const VALID_METADATA = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/auth`,
  token_endpoint: `${ISSUER}/token`,
};

function mockDiscoveryFetch() {
  return vi.fn().mockResolvedValue(
    new Response(JSON.stringify(VALID_METADATA), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  );
}

function mockAdapterFactory(): (config: ToriiConfig) => Promise<SessionAdapter> {
  return vi.fn().mockResolvedValue({
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    touch: vi.fn(),
  });
}

describe('getRuntime — lazy singleton', () => {
  beforeEach(() => {
    _resetRuntime();
  });

  it('returns a RuntimeState on first call', async () => {
    // Act
    const state = await getRuntime(VALID_CONFIG, mockAdapterFactory(), mockDiscoveryFetch());

    // Assert
    expect(state).toHaveProperty('config');
    expect(state).toHaveProperty('issuerMetadata');
    expect(state).toHaveProperty('sessionKey');
    expect(state).toHaveProperty('adapter');
  });

  it('sessionKey is a CryptoKey when session type is cookie', async () => {
    // Act
    const state = await getRuntime(VALID_CONFIG, mockAdapterFactory(), mockDiscoveryFetch());

    // Assert
    expect(state.sessionKey).toBeInstanceOf(CryptoKey);
  });

  it('sessionKey is null when session type is redis', async () => {
    // Act
    const state = await getRuntime(REDIS_CONFIG, mockAdapterFactory(), mockDiscoveryFetch());

    // Assert
    expect(state.sessionKey).toBeNull();
  });

  it('sessionKey is null when session type is memory', async () => {
    // Act
    const state = await getRuntime(MEMORY_CONFIG, mockAdapterFactory(), mockDiscoveryFetch());

    // Assert
    expect(state.sessionKey).toBeNull();
  });

  it('returns the same instance on subsequent calls', async () => {
    // Arrange
    const fetchFn = mockDiscoveryFetch();
    const factory = mockAdapterFactory();

    // Act
    const state1 = await getRuntime(VALID_CONFIG, factory, fetchFn);
    const state2 = await getRuntime(VALID_CONFIG, factory, fetchFn);

    // Assert
    expect(state1).toBe(state2);
  });

  it('calls discovery fetch exactly once across multiple getRuntime calls', async () => {
    // Arrange
    const fetchFn = mockDiscoveryFetch();
    const factory = mockAdapterFactory();

    // Act
    await getRuntime(VALID_CONFIG, factory, fetchFn);
    await getRuntime(VALID_CONFIG, factory, fetchFn);
    await getRuntime(VALID_CONFIG, factory, fetchFn);

    // Assert
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('concurrent calls only initialize once', async () => {
    // Arrange
    const fetchFn = mockDiscoveryFetch();
    const factory = mockAdapterFactory();

    // Act
    // Simulate 10 concurrent requests hitting cold start simultaneously
    // Unused intermediates prefixed with _ to satisfy noUnusedLocals
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const [s1, s2, _s3, _s4, s5, _s6, _s7, _s8, _s9, s10] = await Promise.all(Array.from({ length: 10 }, () => getRuntime(VALID_CONFIG, factory, fetchFn)));

    // Assert - All references must be the same object instance
    expect(s1).toBe(s2);
    expect(s1).toBe(s5);
    expect(s1).toBe(s10);
    // Discovery called exactly once despite 10 concurrent callers
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });
});

describe('getRuntime — OIDC discovery', () => {
  beforeEach(() => {
    _resetRuntime();
  });

  it('stores issuer metadata in the state', async () => {
    // Act
    const { issuerMetadata } = await getRuntime(VALID_CONFIG, mockAdapterFactory(), mockDiscoveryFetch());

    // Assert
    expect(issuerMetadata.issuer).toBe(ISSUER);
    expect(issuerMetadata.authorization_endpoint).toBe(VALID_METADATA.authorization_endpoint);
    expect(issuerMetadata.token_endpoint).toBe(VALID_METADATA.token_endpoint);
  });

  it('throws when discovery fails — fail-fast on misconfiguration', async () => {
    // Arrange
    const failFetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    // Act & Assert
    await expect(getRuntime(VALID_CONFIG, mockAdapterFactory(), failFetch)).rejects.toThrow(Error);
  });
});

describe('getRuntime — topology validation', () => {
  beforeEach(() => {
    _resetRuntime();
  });

  it('throws with formatted errors when topology config is invalid', async () => {
    // Arrange
    const invalidConfig = {
      ...VALID_CONFIG,
      security: {
        ...VALID_CONFIG.security,
        topology: 'subdomain' as const,
        // Missing cookieDomain (required for subdomain)
        allowedOrigins: [], // Empty (required for subdomain)
        cookieName: '__Host-session', // Wrong prefix for subdomain
      },
    };

    // Act & Assert
    await expect(getRuntime(invalidConfig as never, mockAdapterFactory(), mockDiscoveryFetch())).rejects.toThrow(/topology configuration errors/);
  });

  it('error message includes all validation failures', async () => {
    // Arrange
    const invalidConfig = {
      ...VALID_CONFIG,
      security: {
        ...VALID_CONFIG.security,
        topology: 'subdomain' as const,
        // All errors: missing cookieDomain, empty allowedOrigins, wrong cookie prefix
      },
    };

    // Act & Assert
    const error = await getRuntime(invalidConfig as never, mockAdapterFactory(), mockDiscoveryFetch()).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain('security.cookieDomain');
    expect((error as Error).message).toContain('security.allowedOrigins');
    expect((error as Error).message).toContain('security.cookieName');
  });
});

describe(deriveSessionKey, () => {
  beforeEach(() => {
    _resetRuntime();
  });

  it('returns a CryptoKey', async () => {
    // Act
    const key = await deriveSessionKey('a'.repeat(32));

    // Assert
    expect(key).toBeInstanceOf(CryptoKey);
  });

  it('key algorithm is AES-GCM-256', async () => {
    // Act
    const key = await deriveSessionKey('a'.repeat(32));

    // Assert
    expect(key.algorithm.name).toBe('AES-GCM');
    // Cast to the concrete algorithm shape — AesKeyAlgorithm is not in
    // edge-runtime lib types, so we use a plain structural assertion
    expect(key.algorithm as { name: string; length: number }).toHaveLength(256);
  });

  it('key is not extractable — cannot leave runtime memory', async () => {
    // Act
    const key = await deriveSessionKey('a'.repeat(32));

    // Assert
    expect(key.extractable).toBe(false);
  });

  it('key usages are encrypt and decrypt only', async () => {
    // Act
    const key = await deriveSessionKey('a'.repeat(32));

    // Assert
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');
    expect(key.usages).toHaveLength(2);
  });

  it('different secrets produce different keys', async () => {
    // Act
    const key1 = await deriveSessionKey('a'.repeat(32));
    const key2 = await deriveSessionKey('b'.repeat(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode('test');
    const [ct1, ct2] = await Promise.all([
      crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key1, plaintext),
      crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key2, plaintext),
    ]);

    // Assert - Use Uint8Array comparison — Buffer not available in edge-runtime
    expect(new Uint8Array(ct1)).not.toStrictEqual(new Uint8Array(ct2));
  });

  it('same secret always produces functionally equivalent keys', async () => {
    // Arrange
    const secret = 'consistent-secret-value'.padEnd(32, '!');

    // Act
    const key1 = await deriveSessionKey(secret);
    const key2 = await deriveSessionKey(secret);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode('hello world');
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key1, plaintext);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ciphertext);

    // Assert
    expect(new TextDecoder().decode(decrypted)).toBe('hello world');
  });
});
