/**
 * Web Crypto primitives for JWS signature verification.
 *
 * Centralises the JWK → CryptoKey import and verify steps used by
 * `security/jwt.ts`. Any future JWS consumer (DPoP, signed JAR, etc.)
 * must go through these helpers so algorithm parameters are defined
 * exactly once.
 *
 * RFC 7515 — JSON Web Signature
 * RFC 7518 — JSON Web Algorithms
 * RFC 7517 — JSON Web Key
 */

/** JWS algorithms Torii will import / verify. */
export const SUPPORTED_JWS_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'] as const;

export type JwsAlgorithm = (typeof SUPPORTED_JWS_ALGORITHMS)[number];

const SUPPORTED_JWS_ALGS_SET = new Set<string>(SUPPORTED_JWS_ALGORITHMS);

export function isSupportedJwsAlg(alg: unknown): alg is JwsAlgorithm {
  return typeof alg === 'string' && SUPPORTED_JWS_ALGS_SET.has(alg);
}

interface ImportAlgParams {
  name: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'ECDSA';
  hash: 'SHA-256' | 'SHA-384' | 'SHA-512';
  namedCurve?: 'P-256' | 'P-384' | 'P-521';
}

interface VerifyAlgParams {
  name: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'ECDSA';
  hash?: 'SHA-256' | 'SHA-384' | 'SHA-512';
  saltLength?: number;
}

/**
 * Maps a JWS `alg` value to the Web Crypto import and verify parameter pairs.
 *
 * Throws if the alg is not in the supported allowlist — `none` and any HMAC
 * family are intentionally excluded: HMAC requires a shared secret which does
 * not belong in a public JWK, and `none` is forbidden by RFC 8725 §3.1.
 */
export function algParams(alg: JwsAlgorithm): { import: ImportAlgParams; verify: VerifyAlgParams } {
  switch (alg) {
    case 'RS256':
      return { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verify: { name: 'RSASSA-PKCS1-v1_5' } };
    case 'RS384':
      return { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }, verify: { name: 'RSASSA-PKCS1-v1_5' } };
    case 'RS512':
      return { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }, verify: { name: 'RSASSA-PKCS1-v1_5' } };
    case 'PS256':
      return { import: { name: 'RSA-PSS', hash: 'SHA-256' }, verify: { name: 'RSA-PSS', saltLength: 32 } };
    case 'PS384':
      return { import: { name: 'RSA-PSS', hash: 'SHA-384' }, verify: { name: 'RSA-PSS', saltLength: 48 } };
    case 'PS512':
      return { import: { name: 'RSA-PSS', hash: 'SHA-512' }, verify: { name: 'RSA-PSS', saltLength: 64 } };
    case 'ES256':
      return { import: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }, verify: { name: 'ECDSA', hash: 'SHA-256' } };
    case 'ES384':
      return { import: { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' }, verify: { name: 'ECDSA', hash: 'SHA-384' } };
    case 'ES512':
      return { import: { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' }, verify: { name: 'ECDSA', hash: 'SHA-512' } };
  }
}

/**
 * Imports a public JWK as a Web Crypto verify key bound to `alg`.
 *
 * The import is bound to a single algorithm — callers that want to use the
 * same JWK with multiple algorithms must import twice.
 */
export async function importJwkVerifyKey(jwk: JsonWebKey, alg: JwsAlgorithm): Promise<CryptoKey> {
  const { import: importParams } = algParams(alg);
  return crypto.subtle.importKey('jwk', jwk, importParams, false, ['verify']);
}

/**
 * Verifies a JWS signature over (`signingInput`) using `key`.
 *
 * `signingInput` is the ASCII bytes of `base64url(header) + "." + base64url(payload)`,
 * per RFC 7515 §5.2. `signature` is the raw decoded signature bytes.
 */
export async function verifyJws(alg: JwsAlgorithm, key: CryptoKey, signingInput: BufferSource, signature: BufferSource): Promise<boolean> {
  const { verify: verifyParams } = algParams(alg);
  return crypto.subtle.verify(verifyParams, key, signature, signingInput);
}
