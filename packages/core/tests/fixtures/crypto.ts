/**
 * Crypto Test Fixtures for Security Test Suite
 *
 * IMPORTANT: These are test-only utilities.
 */

import { algParams, type JwsAlgorithm } from '../../src/security/webcrypto.js';
import { base64urlEncode } from '../../src/security/utils/index.js';

/**
 * Encode a JSON object to base64url string (test helper)
 *
 * Used 8+ times in jwt.test.ts for encoding JWT headers/payloads.
 * Composition of JSON.stringify + TextEncoder + base64urlEncode.
 *
 * @param obj - Any JSON-serializable object
 * @returns base64url-encoded string (no padding)
 */
export function encodeJsonToBase64url(obj: unknown): string {
  const json = JSON.stringify(obj);
  const bytes = new TextEncoder().encode(json);
  return base64urlEncode(bytes);
}

/**
 * Generate RSA keypair for testing (2048-bit, SHA-256)
 *
 * Eliminates duplication across jwt.test.ts and webcrypto.test.ts.
 * Standard parameters: 2048-bit modulus, public exponent 65537.
 *
 * @param algorithm - RSA algorithm variant (default: RSASSA-PKCS1-v1_5)
 * @returns Extractable keypair with sign/verify usages
 */
export async function generateRsaKeyPair(algorithm: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' = 'RSASSA-PKCS1-v1_5'): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: algorithm,
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
}

/**
 * Generate ECDSA keypair for testing (P-256)
 *
 * Eliminates duplication across jwt.test.ts and webcrypto.test.ts.
 * Standard parameters: P-256 curve (secp256r1).
 *
 * @returns Extractable keypair with sign/verify usages
 */
export async function generateEcdsaKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

/**
 * Tamper with the first byte of a signature (for negative testing)
 *
 * Flips all bits in the first byte using XOR with 0xFF.
 * Used to create invalid signatures for testing signature verification failures.
 *
 * Eliminates duplication between jwt.test.ts:262-267 and webcrypto.test.ts:119-124.
 *
 * @param bytes - Signature bytes to tamper with (mutated in place)
 */
export function tamperFirstByte(bytes: Uint8Array): void {
  const firstByte = bytes[0];
  if (firstByte !== undefined) {
    bytes[0] = firstByte ^ 0xff;
  }
}

/**
 * Build a signed ID token for testing
 *
 * Extracted from jwt.test.ts:41-60 to avoid duplication.
 * Creates a properly signed JWT with header, payload, and signature.
 *
 * @param payload - JWT payload claims
 * @param alg - JWS algorithm (RS256, ES256, etc.)
 * @param kid - Key ID for the JWK
 * @param keyPair - Keypair to sign with
 * @returns Signed JWT in compact serialization format
 */
export async function buildIdToken(payload: Record<string, unknown>, alg: JwsAlgorithm, kid: string, keyPair: CryptoKeyPair): Promise<string> {
  const header = { alg, kid, typ: 'JWT' };
  const headerB64 = encodeJsonToBase64url(header);
  const payloadB64 = encodeJsonToBase64url(payload);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  const params = algParams(alg);

  let signAlg: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
  if (alg.startsWith('RS')) {
    signAlg = 'RSASSA-PKCS1-v1_5';
  } else if (alg.startsWith('PS')) {
    signAlg = { name: 'RSA-PSS', saltLength: 32 };
  } else {
    signAlg = { name: 'ECDSA', hash: params.import.hash };
  }

  const signature = await crypto.subtle.sign(signAlg, keyPair.privateKey, signingInput);
  const signatureB64 = base64urlEncode(new Uint8Array(signature));

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}
