/**
 * Web Crypto primitives tests — RFC 7515/7518 JWS verification.
 *
 * Covers:
 *   - Algorithm allowlist (RS256/PS256/ES256 accept; none/HS* reject)
 *   - JWK import → CryptoKey round-trip per alg
 *   - JWS signature verify (happy path + tampered signature)
 */

import { describe, it, expect } from 'vitest';
import { SUPPORTED_JWS_ALGORITHMS, isSupportedJwsAlg, algParams, importJwkVerifyKey, verifyJws, type JwsAlgorithm } from './webcrypto.js';
import { generateRsaKeyPair, generateEcdsaKeyPair, tamperFirstByte } from '../../tests/fixtures/crypto.js';

describe('webcrypto — JWS primitives', () => {
  describe(isSupportedJwsAlg, () => {
    it.each(SUPPORTED_JWS_ALGORITHMS)('accepts %s', (alg) => {
      expect(isSupportedJwsAlg(alg)).toBe(true);
    });

    it.each(['none', 'HS256', 'HS384', 'HS512', 'INVALID', '', null, undefined, 42])('rejects %s', (alg) => {
      expect(isSupportedJwsAlg(alg)).toBe(false);
    });
  });

  describe(algParams, () => {
    it.each<[JwsAlgorithm, string, string]>([
      ['RS256', 'RSASSA-PKCS1-v1_5', 'SHA-256'],
      ['RS384', 'RSASSA-PKCS1-v1_5', 'SHA-384'],
      ['RS512', 'RSASSA-PKCS1-v1_5', 'SHA-512'],
      ['PS256', 'RSA-PSS', 'SHA-256'],
      ['PS384', 'RSA-PSS', 'SHA-384'],
      ['PS512', 'RSA-PSS', 'SHA-512'],
    ])('%s (RSA) → %s + %s', (alg, expectedName, expectedHash) => {
      const params = algParams(alg);

      expect(params.import.name).toBe(expectedName);
      expect(params.import.hash).toBe(expectedHash);
      expect(params.verify.name).toBe(expectedName);
      // RSA algorithms don't include hash in verify params
    });

    it.each<[JwsAlgorithm, string, string]>([
      ['ES256', 'ECDSA', 'SHA-256'],
      ['ES384', 'ECDSA', 'SHA-384'],
      ['ES512', 'ECDSA', 'SHA-512'],
    ])('%s (ECDSA) → %s + %s', (alg, expectedName, expectedHash) => {
      const params = algParams(alg);

      expect(params.import.name).toBe(expectedName);
      expect(params.import.hash).toBe(expectedHash);
      expect(params.verify.name).toBe(expectedName);
      // ECDSA includes hash in both import and verify params
      expect(params.verify.hash).toBe(expectedHash);
    });
  });

  describe('importJwkVerifyKey + verifyJws — round-trip', () => {
    it('rS256: imports RSA public key and verifies signature', async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair();

      const jwk = await crypto.subtle.exportKey('jwk', publicKey);
      const imported = await importJwkVerifyKey(jwk, 'RS256');

      const data = new TextEncoder().encode('test payload');
      const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, data);

      const valid = await verifyJws('RS256', imported, data, new Uint8Array(signature));

      expect(valid).toBe(true);
    });

    it('eS256: imports ECDSA public key and verifies signature', async () => {
      const { publicKey, privateKey } = await generateEcdsaKeyPair();

      const jwk = await crypto.subtle.exportKey('jwk', publicKey);
      const imported = await importJwkVerifyKey(jwk, 'ES256');

      const data = new TextEncoder().encode('test payload');
      const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data);

      const valid = await verifyJws('ES256', imported, data, new Uint8Array(signature));

      expect(valid).toBe(true);
    });

    it('pS256: imports RSA-PSS public key and verifies signature', async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair('RSA-PSS');

      const jwk = await crypto.subtle.exportKey('jwk', publicKey);
      const imported = await importJwkVerifyKey(jwk, 'PS256');

      const data = new TextEncoder().encode('test payload');
      const signature = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, privateKey, data);

      const valid = await verifyJws('PS256', imported, data, new Uint8Array(signature));

      expect(valid).toBe(true);
    });

    it('rejects tampered signature', async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair();

      const jwk = await crypto.subtle.exportKey('jwk', publicKey);
      const imported = await importJwkVerifyKey(jwk, 'RS256');

      const data = new TextEncoder().encode('test payload');
      const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, data);
      const tampered = new Uint8Array(signature);
      tamperFirstByte(tampered);

      const valid = await verifyJws('RS256', imported, data, tampered);

      expect(valid).toBe(false);
    });
  });
});
