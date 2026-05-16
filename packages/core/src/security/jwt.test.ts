/**
 * ID Token verification tests — RFC 9700 §4.5.1, OIDC Core §3.1.3.7.
 *
 * Covers:
 *   - JWS structure parsing (3 segments, base64url)
 *   - alg allowlist (RS256/PS256/ES256 family accept; none/HS256 family reject)
 *   - Signature verification (happy + tampered)
 *   - iss, aud (string + array), exp, nbf, iat, nonce claims
 *   - Clock skew tolerance
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { verifyIdToken, JwtError, type JwksKeySource } from './jwt.js';
import { base64urlEncode } from './utils/index.js';
import type { JwsAlgorithm } from './webcrypto.js';
import { generateRsaKeyPair, generateEcdsaKeyPair, tamperFirstByte, buildIdToken, encodeJsonToBase64url } from '../../tests/fixtures/crypto.js';

interface JwkWithKid extends JsonWebKey {
  kid: string;
}

function mockKeySource(keys: Record<string, { jwk: JsonWebKey; alg: JwsAlgorithm }>): JwksKeySource {
  return {
    async getKey(kid: string | undefined, alg: JwsAlgorithm): Promise<CryptoKey> {
      if (!kid) throw new Error('kid required in test');
      const entry = keys[kid];
      if (!entry) throw new Error(`Unknown kid: ${kid}`);
      if (entry.alg !== alg) throw new Error(`alg mismatch: expected ${entry.alg}, got ${alg}`);
      return crypto.subtle.importKey('jwk', entry.jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    },
  };
}

function createJwtPayload(
  overrides?: Partial<{
    iss: string;
    aud: string | string[];
    sub: string;
    exp: number;
    iat: number;
    nbf: number;
    nonce: string;
  }>,
): Record<string, unknown> {
  const now = nowSec();

  return {
    iss: 'https://issuer.torii.dev',
    aud: 'client-id',
    sub: 'user-123',
    exp: now + 300,
    iat: now,
    nonce: 'test-nonce',
    ...overrides,
  };
}

/**
 * Get current Unix timestamp in seconds
 *
 * Standard helper for JWT exp/iat/nbf claims.
 * Used extensively across jwt.test.ts.
 *
 * @returns Current time in seconds since epoch
 */
const nowSec = (): number => Math.floor(Date.now() / 1000);

describe('jwt — ID token verification (RFC 9700 §4.5.1 / OIDC Core §3.1.3.7)', () => {
  let rsaKeyPair: CryptoKeyPair;
  let rsaJwk: JwkWithKid;
  let ecKeyPair: CryptoKeyPair;
  let ecJwk: JwkWithKid;

  beforeAll(async () => {
    rsaKeyPair = await generateRsaKeyPair();
    const rsaExported = await crypto.subtle.exportKey('jwk', rsaKeyPair.publicKey);
    rsaJwk = { ...rsaExported, kid: 'rsa-test-key' };

    ecKeyPair = await generateEcdsaKeyPair();
    const ecExported = await crypto.subtle.exportKey('jwk', ecKeyPair.publicKey);
    ecJwk = { ...ecExported, kid: 'ec-test-key' };
  });

  const nowSec = () => Math.floor(Date.now() / 1000);

  describe('happy path', () => {
    it('verifies valid RS256 ID token', async () => {
      // Arrange
      const payload = createJwtPayload();

      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act
      const claims = await verifyIdToken(idToken, {
        issuer: 'https://issuer.torii.dev',
        clientId: 'client-id',
        nonce: 'test-nonce',
        keySource,
      });

      // Assert
      expect(claims.iss).toBe('https://issuer.torii.dev');
      expect(claims.aud).toStrictEqual(['client-id'] as const);
      expect(claims.sub).toBe('user-123');
      expect(claims.nonce).toBe('test-nonce');
    });

    it('verifies valid ES256 ID token', async () => {
      // Arrange
      const payload = createJwtPayload();
      const idToken = await buildIdToken(payload, 'ES256', 'ec-test-key', ecKeyPair);

      const keySource: JwksKeySource = {
        async getKey(kid, _alg) {
          if (kid !== 'ec-test-key') throw new Error('Unknown kid');
          return crypto.subtle.importKey('jwk', ecJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        },
      };

      // Act
      const claims = await verifyIdToken(idToken, {
        issuer: 'https://issuer.torii.dev',
        clientId: 'client-id',
        nonce: 'test-nonce',
        keySource,
      });

      // Assert
      expect(claims.iss).toBe('https://issuer.torii.dev');
      expect(claims.nonce).toBe('test-nonce');
    });

    it('accepts aud as array', async () => {
      // Arrange
      const payload = createJwtPayload({ aud: ['client-id', 'other-audience'] });
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act
      const claims = await verifyIdToken(idToken, {
        issuer: 'https://issuer.torii.dev',
        clientId: 'client-id',
        nonce: 'test-nonce',
        keySource,
      });

      // Asset
      expect(claims.aud).toStrictEqual(['client-id', 'other-audience'] as const);
    });
  });

  describe('malformed JWS', () => {
    it('rejects token with wrong segment count', async () => {
      // Act & Assert
      await expect(
        verifyIdToken('only.two', {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'nonce',
          keySource: mockKeySource({}),
        }),
      ).rejects.toThrow(JwtError);
      await expect(
        verifyIdToken('only.two', {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'nonce',
          keySource: mockKeySource({}),
        }),
      ).rejects.toMatchObject({ code: 'malformed' });
    });

    it('rejects token with empty segment', async () => {
      // Act & Assert
      await expect(
        verifyIdToken('..', {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'nonce',
          keySource: mockKeySource({}),
        }),
      ).rejects.toMatchObject({ code: 'malformed' });
    });

    it('rejects header without alg', async () => {
      // Arrange
      const headerB64 = encodeJsonToBase64url({ typ: 'JWT' });
      const payloadB64 = encodeJsonToBase64url({ iss: 'x' });

      // Act & Assert
      await expect(
        verifyIdToken(`${headerB64}.${payloadB64}.sig`, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'nonce',
          keySource: mockKeySource({}),
        }),
      ).rejects.toMatchObject({ code: 'malformed' });
    });

    it('rejects invalid base64url in segments', async () => {
      // Act & Assert
      await expect(
        verifyIdToken('!!!.aaa.bbb', {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'nonce',
          keySource: mockKeySource({}),
        }),
      ).rejects.toMatchObject({ code: 'malformed' });
    });
  });

  describe('alg allowlist (RFC 8725 §3.1 — none/HMAC forbidden)', () => {
    it('rejects alg: none', async () => {
      // Arrange
      const header = { alg: 'none', typ: 'JWT' };
      const payload = { iss: 'https://issuer.torii.dev', aud: 'client-id', exp: nowSec() + 300, nonce: 'nonce' };
      const headerB64 = encodeJsonToBase64url(header);
      const payloadB64 = encodeJsonToBase64url(payload);
      // RFC 8725 requires rejecting alg:none, but the signature must be present (even if empty)
      const idToken = `${headerB64}.${payloadB64}.fake`;

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'nonce',
          keySource: mockKeySource({}),
        }),
      ).rejects.toMatchObject({ code: 'alg_not_allowed' });
    });

    it.each(['HS256', 'HS384', 'HS512'])('rejects HMAC alg: %s', async (alg) => {
      // Arrange
      const header = { alg, kid: 'k', typ: 'JWT' };
      const payload = { iss: 'https://issuer.torii.dev', aud: 'client-id', exp: nowSec() + 300, nonce: 'nonce' };
      const headerB64 = encodeJsonToBase64url(header);
      const payloadB64 = encodeJsonToBase64url(payload);
      const idToken = `${headerB64}.${payloadB64}.fakesig`;

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'nonce',
          keySource: mockKeySource({}),
        }),
      ).rejects.toMatchObject({ code: 'alg_not_allowed' });
    });
  });

  describe('signature verification', () => {
    it('rejects tampered signature', async () => {
      // Arrange
      const payload = createJwtPayload();
      let idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);

      const parts = idToken.split('.');
      const sigPart = parts[2] ?? '';
      const sigBytes = Uint8Array.from(atob(sigPart.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.codePointAt(0) ?? 0);
      tamperFirstByte(sigBytes);
      parts[2] = base64urlEncode(sigBytes);
      idToken = parts.join('.');

      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'test-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'invalid_signature' });
    });

    it('throws unknown_kid when keySource fails', async () => {
      // Arrange
      const payload = createJwtPayload();
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({});

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'test-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'unknown_kid' });
    });
  });

  describe('iss validation (RFC 9700 §4.4)', () => {
    it('rejects wrong issuer', async () => {
      // Arrange
      const payload = {
        iss: 'https://wrong-issuer.torii.dev',
        aud: 'client-id',
        exp: nowSec() + 300,
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'test-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'wrong_issuer' });
    });
  });

  describe('aud validation (OIDC Core §3.1.3.7 item 3)', () => {
    it('rejects when aud does not contain clientId (string)', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: 'other-client',
        exp: nowSec() + 300,
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'test-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'wrong_audience' });
    });

    it('rejects when aud array does not contain clientId', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: ['other-1', 'other-2'],
        exp: nowSec() + 300,
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'test-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'wrong_audience' });
    });

    it('rejects when aud is missing', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        exp: nowSec() + 300,
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'test-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'wrong_audience' });
    });

    it('rejects when aud is not string or array', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: 123,
        exp: nowSec() + 300,
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'test-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'wrong_audience' });
    });
  });

  describe('exp validation', () => {
    it('rejects expired token', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: 'client-id',
        exp: nowSec() - 300,
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'test-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'expired' });
    });

    it('accepts token within clockSkewSec', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: 'client-id',
        exp: nowSec() - 30,
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act
      const claims = await verifyIdToken(idToken, {
        issuer: 'https://issuer.torii.dev',
        clientId: 'client-id',
        nonce: 'test-nonce',
        keySource,
        clockSkewSec: 60,
      });

      // Assert
      expect(claims.iss).toBe('https://issuer.torii.dev');
    });

    it('rejects when exp is missing', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: 'client-id',
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'test-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'expired' });
    });
  });

  describe('nbf validation', () => {
    it('rejects token not yet valid', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: 'client-id',
        exp: nowSec() + 300,
        nbf: nowSec() + 300,
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'test-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'not_yet_valid' });
    });

    it('accepts token with nbf within clockSkewSec', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: 'client-id',
        exp: nowSec() + 300,
        nbf: nowSec() + 30,
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act
      const claims = await verifyIdToken(idToken, {
        issuer: 'https://issuer.torii.dev',
        clientId: 'client-id',
        nonce: 'test-nonce',
        keySource,
        clockSkewSec: 60,
      });

      // Assert
      expect(claims.nbf).toBe(payload.nbf);
    });
  });

  describe('iat validation', () => {
    it('rejects iat in the future beyond clockSkewSec', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: 'client-id',
        exp: nowSec() + 300,
        iat: nowSec() + 120,
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'test-nonce',
          keySource,
          clockSkewSec: 60,
        }),
      ).rejects.toMatchObject({ code: 'issued_in_future' });
    });

    it('accepts iat within clockSkewSec', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: 'client-id',
        exp: nowSec() + 300,
        iat: nowSec() + 30,
        nonce: 'test-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act
      const claims = await verifyIdToken(idToken, {
        issuer: 'https://issuer.torii.dev',
        clientId: 'client-id',
        nonce: 'test-nonce',
        keySource,
        clockSkewSec: 60,
      });

      // Assert
      expect(claims.iat).toBe(payload.iat);
    });
  });

  describe('nonce validation (OIDC Core §3.1.3.7 item 11)', () => {
    it('rejects nonce mismatch', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: 'client-id',
        exp: nowSec() + 300,
        nonce: 'wrong-nonce',
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'expected-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'nonce_mismatch' });
    });

    it('rejects missing nonce', async () => {
      // Arrange
      const payload = {
        iss: 'https://issuer.torii.dev',
        aud: 'client-id',
        exp: nowSec() + 300,
      };
      const idToken = await buildIdToken(payload, 'RS256', 'rsa-test-key', rsaKeyPair);
      const keySource = mockKeySource({ 'rsa-test-key': { jwk: rsaJwk, alg: 'RS256' } });

      // Act & Assert
      await expect(
        verifyIdToken(idToken, {
          issuer: 'https://issuer.torii.dev',
          clientId: 'client-id',
          nonce: 'expected-nonce',
          keySource,
        }),
      ).rejects.toMatchObject({ code: 'nonce_mismatch' });
    });
  });
});
