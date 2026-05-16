/**
 * JWKS Client tests — RFC 7517 JWK Set fetching and caching.
 *
 * Covers:
 *   - JWKS fetch and parse
 *   - kid-based lookup
 *   - Unknown kid triggers single refetch (rotation handling)
 *   - Cache expiry
 *   - Non-HTTPS jwks_uri rejected
 *   - Malformed JWKS rejected
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createJwksClient, JwksError } from './jwks.js';

interface JwkWithExtensions extends JsonWebKey {
  kid?: string;
  use?: string;
  alg?: string;
}

describe('jwks — RFC 7517 JWKS client', () => {
  let rsaJwk: JwkWithExtensions;
  let ecJwk: JwkWithExtensions;

  beforeEach(async () => {
    vi.clearAllMocks();
    // Generate real keys for tests
    const rsaKeyPair = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );
    const rsaExported = await crypto.subtle.exportKey('jwk', rsaKeyPair.publicKey);
    rsaJwk = { ...rsaExported, kid: 'key-1', use: 'sig', alg: 'RS256' };

    const ecKeyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const ecExported = await crypto.subtle.exportKey('jwk', ecKeyPair.publicKey);
    ecJwk = { ...ecExported, kid: 'key-2', use: 'sig', alg: 'ES256' };
  });

  function getMockJwksDoc() {
    return {
      keys: [{ ...rsaJwk }, { ...ecJwk }, { kty: 'RSA', kid: 'key-3', use: 'enc', n: rsaJwk.n, e: rsaJwk.e }],
    };
  }

  describe('construction', () => {
    it('accepts HTTPS jwks_uri', () => {
      // Arrange
      const fetchMock = vi.fn();

      // Act & Assert
      expect(() => createJwksClient({ jwksUri: 'https://issuer.torii.dev/.well-known/jwks.json', fetch: fetchMock })).not.toThrow();
    });

    it('rejects HTTP jwks_uri', () => {
      // Arrange
      const fetchMock = vi.fn();

      // Act & Assert
      expect(() => createJwksClient({ jwksUri: 'http://issuer.torii.dev/jwks.json', fetch: fetchMock })).toThrow(JwksError);
      expect(() => createJwksClient({ jwksUri: 'http://issuer.torii.dev/jwks.json', fetch: fetchMock })).toThrow(/HTTPS/i);
    });

    it('rejects invalid jwks_uri', () => {
      // Arrange
      const fetchMock = vi.fn();

      // Act & Assert
      expect(() => createJwksClient({ jwksUri: 'not a url', fetch: fetchMock })).toThrow(JwksError);
    });
  });

  describe('getKey — fetch and cache', () => {
    it('fetches JWKS on first call', async () => {
      // Arrange
      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(getMockJwksDoc()), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act
      await client.getKey('key-1', 'RS256');

      // Assert
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledWith('https://issuer.torii.dev/jwks.json', expect.objectContaining({ headers: { accept: 'application/json' } }));
    });

    it('caches JWKS and does not refetch on second call', async () => {
      // Arrange
      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(getMockJwksDoc()), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock, maxCacheMs: 60000 });

      // Act
      await client.getKey('key-1', 'RS256');
      await client.getKey('key-2', 'ES256');

      // Assert
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('returns CryptoKey for matching kid', async () => {
      // Arrange
      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(getMockJwksDoc()), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act
      const key = await client.getKey('key-1', 'RS256');

      // Assert
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.type).toBe('public');
    });

    it('filters by use=sig', async () => {
      // Arrange
      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(getMockJwksDoc()), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act & Assert
      await expect(client.getKey('key-3', 'RS256')).rejects.toThrow(JwksError);
      await expect(client.getKey('key-3', 'RS256')).rejects.toMatchObject({ code: 'key_not_found' });
    });

    it('filters by alg if present in JWK', async () => {
      // Arrange
      const jwksDocWithAlg = {
        keys: [
          { kty: 'RSA', kid: 'key-1', use: 'sig', n: 'abc', e: 'AQAB', alg: 'RS256' },
          { kty: 'RSA', kid: 'key-2', use: 'sig', n: 'def', e: 'AQAB', alg: 'PS256' },
        ],
      };
      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(jwksDocWithAlg), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act
      const key1 = await client.getKey('key-1', 'RS256');

      // Assert
      expect(key1).toBeInstanceOf(CryptoKey);
      await expect(client.getKey('key-1', 'PS256')).rejects.toMatchObject({ code: 'key_not_found' });
    });
  });

  describe('getKey — unknown kid triggers refetch', () => {
    it('refetches JWKS once when kid is unknown', async () => {
      // Arrange
      let callCount = 0;
      const fetchMock = vi.fn(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.resolve(
            new Response(JSON.stringify({ keys: [{ kty: 'RSA', kid: 'old-key', use: 'sig', n: 'abc', e: 'AQAB', alg: 'RS256' }] }), { status: 200 }),
          );
        }
        return Promise.resolve(new Response(JSON.stringify(getMockJwksDoc()), { status: 200 }));
      });
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act
      await client.getKey('key-1', 'RS256');

      // Assert
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it('throws key_not_found if kid still missing after refetch', async () => {
      // Arrange
      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(getMockJwksDoc()), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act - Single call triggers initial fetch + refetch for unknown kid (2 total)
      const promise = client.getKey('nonexistent-kid', 'RS256');

      //  Assert
      await expect(promise).rejects.toThrow(JwksError);
      await expect(promise).rejects.toMatchObject({ code: 'key_not_found' });
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  });

  describe('getKey — no kid in header', () => {
    it('returns single candidate when exactly one key matches alg', async () => {
      // Arrange
      const jwksSingleKey = {
        keys: [{ kty: 'RSA', use: 'sig', n: 'abc', e: 'AQAB', alg: 'RS256' }],
      };
      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(jwksSingleKey), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act
      const key = await client.getKey(undefined, 'RS256');

      // Assert
      expect(key).toBeInstanceOf(CryptoKey);
    });

    it('throws ambiguous_key when multiple keys match and no kid', async () => {
      // Arrange
      // Create JWKS with TWO RS256 sig keys to create ambiguity
      const rsaKeyPair2 = await crypto.subtle.generateKey(
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['sign', 'verify'],
      );
      const rsaExported2 = await crypto.subtle.exportKey('jwk', rsaKeyPair2.publicKey);
      const rsaJwk2: JwkWithExtensions = { ...rsaExported2, kid: 'key-4', use: 'sig', alg: 'RS256' };

      const ambiguousDoc = {
        keys: [{ ...rsaJwk }, { ...rsaJwk2 }],
      };

      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(ambiguousDoc), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act & Assert
      await expect(client.getKey(undefined, 'RS256')).rejects.toThrow(JwksError);
      await expect(client.getKey(undefined, 'RS256')).rejects.toMatchObject({ code: 'ambiguous_key' });
    });

    it('throws key_not_found when no keys match alg', async () => {
      // Arrange
      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(getMockJwksDoc()), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act & Assert
      await expect(client.getKey(undefined, 'PS512')).rejects.toThrow(JwksError);
      await expect(client.getKey(undefined, 'PS512')).rejects.toMatchObject({ code: 'key_not_found' });
    });
  });

  describe('fetch errors', () => {
    it('throws fetch_failed on network error', async () => {
      // Arrange
      const fetchMock = vi.fn(() => Promise.reject(new Error('Network failure')));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act & Assert
      await expect(client.getKey('key-1', 'RS256')).rejects.toThrow(JwksError);
      await expect(client.getKey('key-1', 'RS256')).rejects.toMatchObject({ code: 'fetch_failed' });
    });

    it('throws http_error on non-200 response', async () => {
      // Arrange
      const fetchMock = vi.fn(() => Promise.resolve(new Response('Not Found', { status: 404 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act & Assert
      await expect(client.getKey('key-1', 'RS256')).rejects.toThrow(JwksError);
      await expect(client.getKey('key-1', 'RS256')).rejects.toMatchObject({ code: 'http_error' });
    });

    it('throws malformed_jwks when response is not JSON', async () => {
      // Arrange
      const fetchMock = vi.fn(() => Promise.resolve(new Response('not json', { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act & Assert
      await expect(client.getKey('key-1', 'RS256')).rejects.toThrow(JwksError);
      await expect(client.getKey('key-1', 'RS256')).rejects.toMatchObject({ code: 'malformed_jwks' });
    });

    it('throws malformed_jwks when keys array is missing', async () => {
      // Arrange
      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify({ notKeys: [] }), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act & Assert
      await expect(client.getKey('key-1', 'RS256')).rejects.toThrow(JwksError);
      await expect(client.getKey('key-1', 'RS256')).rejects.toMatchObject({ code: 'malformed_jwks' });
    });
  });

  describe('cache expiry', () => {
    it('refetches after maxCacheMs expires', async () => {
      // Arrange
      vi.useFakeTimers();
      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(getMockJwksDoc()), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock, maxCacheMs: 1000 });

      // Act & Assert
      await client.getKey('key-1', 'RS256');

      expect(fetchMock).toHaveBeenCalledTimes(1);

      vi.advanceTimersByTime(1001);

      await client.getKey('key-1', 'RS256');

      expect(fetchMock).toHaveBeenCalledTimes(2);

      vi.useRealTimers();
    });
  });

  describe('refresh', () => {
    it('invalidates cache and refetches', async () => {
      // Arrange
      const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(getMockJwksDoc()), { status: 200 })));
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock });

      // Act & Assert
      await client.getKey('key-1', 'RS256');

      expect(fetchMock).toHaveBeenCalledTimes(1);

      await client.refresh();

      expect(fetchMock).toHaveBeenCalledTimes(2);

      await client.getKey('key-1', 'RS256');

      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  });

  describe('timeout', () => {
    it('aborts fetch after timeoutMs', async () => {
      // Arrange
      let aborted = false;
      const fetchMock = vi.fn<typeof fetch>(
        (_url, options) =>
          new Promise((_resolve, reject) => {
            options?.signal?.addEventListener('abort', () => {
              aborted = true;
              reject(new Error('Aborted'));
            });
            // Never resolve to simulate slow network
          }),
      );

      // Act
      const client = createJwksClient({ jwksUri: 'https://issuer.torii.dev/jwks.json', fetch: fetchMock, timeoutMs: 100 });

      // Assert
      await expect(client.getKey('key-1', 'RS256')).rejects.toThrow(JwksError);
      await expect(client.getKey('key-1', 'RS256')).rejects.toMatchObject({ code: 'fetch_failed' });
      expect(aborted).toBe(true);
    });
  });
});
