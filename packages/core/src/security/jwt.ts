/**
 * OpenID Connect ID Token verification.
 *
 * RFC 9700 §4.5.1       — ID token signature + claims must be validated
 * OpenID Connect Core §3.1.3.7 — ID token validation requirements
 * RFC 7515              — JSON Web Signature
 * RFC 8725              — JWT Best Current Practices (alg confusion, `none`)
 *
 * Torii verifies:
 *   - compact JWS structure (3 segments)
 *   - `alg` is in the supported allowlist and is NOT `none` / HMAC
 *   - signature over `header.payload` using the JWKS-provided public key
 *   - `iss` exactly matches the expected issuer
 *   - `aud` contains the configured client_id (string or array form)
 *   - `exp` is in the future (± clockSkewSec)
 *   - `nbf` is in the past (± clockSkewSec) if present
 *   - `iat` is not in the future beyond clockSkewSec
 *   - `nonce` matches the nonce stored in PendingAuthStore
 *
 * The nonce check is the only claim whose value is caller-supplied;
 * everything else is verified against configuration.
 */

import { base64urlDecode } from './utils/index.js';
import { isSupportedJwsAlg, verifyJws, type JwsAlgorithm } from './webcrypto.js';

/** Abstract provider of JWKS public keys keyed by `kid` + `alg`. */
export interface JwksKeySource {
  /**
   * Returns a CryptoKey bound to `alg` for the given key id.
   *
   * When `kid` is undefined the source should return the only key bound
   * to `alg`, or throw if there is ambiguity.
   */
  getKey(kid: string | undefined, alg: JwsAlgorithm): Promise<CryptoKey>;
}

export interface VerifyIdTokenOptions {
  /** Expected `iss` claim — must match exactly (RFC 9700 §4.4). */
  issuer: string;
  /** Expected `aud` claim — must include this value. */
  clientId: string;
  /** Expected `nonce` claim — raw nonce stored in PendingAuthStore. */
  nonce: string;
  /** JWKS client that resolves `kid` → CryptoKey. */
  keySource: JwksKeySource;
  /** Clock skew tolerance in seconds. Defaults to 60. */
  clockSkewSec?: number;
  /**
   * Override `Date.now()` for deterministic testing. The returned value MUST
   * be milliseconds since epoch, matching `Date.now()`.
   */
  now?: () => number;
}

/** Claims surfaced back to the caller after successful verification. */
export interface VerifiedIdTokenClaims {
  iss: string;
  aud: readonly string[];
  sub?: string;
  exp: number;
  iat?: number;
  nbf?: number;
  nonce?: string;
  [claim: string]: unknown;
}

interface JwsHeader {
  alg: string;
  kid?: string;
  typ?: string;
}

/**
 * Verifies the signature and required claims on an OIDC ID token.
 *
 * Throws `JwtError` on any failure. Returns the parsed claims on success.
 */
export async function verifyIdToken(idToken: string, options: VerifyIdTokenOptions): Promise<VerifiedIdTokenClaims> {
  const { header, payload, signature, signingInput } = splitJws(idToken);

  if (!isSupportedJwsAlg(header.alg)) {
    throw new JwtError(`Unsupported JWS alg "${header.alg}"`, 'alg_not_allowed');
  }
  const alg: JwsAlgorithm = header.alg;

  let key: CryptoKey;
  try {
    key = await options.keySource.getKey(header.kid, alg);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown kid';
    throw new JwtError(`JWKS lookup failed for kid="${header.kid ?? ''}": ${message}`, 'unknown_kid');
  }

  // TypeScript limitation: Uint8Array<ArrayBufferLike> not directly assignable to BufferSource
  // due to SharedArrayBuffer in the union. Runtime: Uint8Array IS BufferSource.
  const valid = await verifyJws(alg, key, signingInput as BufferSource, signature as BufferSource);
  if (!valid) {
    throw new JwtError('ID token signature verification failed', 'invalid_signature');
  }

  validateClaims(payload, options);

  return payload;
}

interface ParsedJws {
  header: JwsHeader;
  payload: VerifiedIdTokenClaims;
  signature: Uint8Array;
  signingInput: Uint8Array;
}

function splitJws(token: string): ParsedJws {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new JwtError('ID token is not a compact JWS (expected 3 segments)', 'malformed');
  }

  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
  if (!headerB64 || !payloadB64 || !signatureB64) {
    throw new JwtError('ID token contains empty segment', 'malformed');
  }

  const header = decodeJwtSegment(headerB64, 'header');
  const payload = decodeJwtSegment(payloadB64, 'payload');

  if (typeof header.alg !== 'string' || !header.alg) {
    throw new JwtError('ID token header missing alg', 'malformed');
  }

  let signature: Uint8Array;
  try {
    signature = base64urlDecode(signatureB64);
  } catch {
    throw new JwtError('ID token signature is not valid base64url', 'malformed');
  }

  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  return { header, payload, signature, signingInput };
}

function decodeJwtSegment(segment: string, label: 'header'): JwsHeader;
function decodeJwtSegment(segment: string, label: 'payload'): VerifiedIdTokenClaims;
function decodeJwtSegment(segment: string, label: 'header' | 'payload'): JwsHeader | VerifiedIdTokenClaims {
  let bytes: Uint8Array;
  try {
    bytes = base64urlDecode(segment);
  } catch {
    throw new JwtError(`ID token ${label} is not valid base64url`, 'malformed');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new JwtError(`ID token ${label} is not valid JSON`, 'malformed');
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new JwtError(`ID token ${label} is not a JSON object`, 'malformed');
  }

  return parsed as JwsHeader | VerifiedIdTokenClaims;
}

function validateClaims(payload: VerifiedIdTokenClaims, options: VerifyIdTokenOptions): void {
  const skewSec = options.clockSkewSec ?? 60;
  const nowMs = options.now ? options.now() : Date.now();
  const nowSec = Math.floor(nowMs / 1000);

  // iss — exact match, RFC 9700 §4.4
  if (payload.iss !== options.issuer) {
    throw new JwtError(`ID token iss "${payload.iss}" does not match expected "${options.issuer}"`, 'wrong_issuer');
  }

  // aud — must contain clientId, OIDC Core §3.1.3.7 item 3
  const audList = toAudienceList(payload.aud);
  if (!audList.includes(options.clientId)) {
    throw new JwtError(`ID token aud does not contain clientId "${options.clientId}"`, 'wrong_audience');
  }
  // Re-project as an array on the returned claims for consistency.
  (payload as { aud: readonly string[] }).aud = audList;

  // exp — required
  if (typeof payload.exp !== 'number') {
    throw new JwtError('ID token missing exp claim', 'expired');
  }
  if (payload.exp + skewSec < nowSec) {
    throw new JwtError('ID token has expired', 'expired');
  }

  // nbf — optional
  if (typeof payload.nbf === 'number' && payload.nbf - skewSec > nowSec) {
    throw new JwtError('ID token is not yet valid (nbf in the future)', 'not_yet_valid');
  }

  // iat — optional; reject if issued too far in the future
  if (typeof payload.iat === 'number' && payload.iat - skewSec > nowSec) {
    throw new JwtError('ID token iat is in the future', 'issued_in_future');
  }

  // nonce — required by OIDC Core when sent on the auth request; we always send one
  if (typeof payload.nonce !== 'string' || payload.nonce !== options.nonce) {
    throw new JwtError('ID token nonce does not match expected value', 'nonce_mismatch');
  }
}

function toAudienceList(aud: unknown): string[] {
  if (typeof aud === 'string') return [aud];
  if (Array.isArray(aud) && aud.every((entry) => typeof entry === 'string')) return aud;
  throw new JwtError('ID token aud is not a string or array of strings', 'wrong_audience');
}

export type JwtErrorCode =
  | 'malformed'
  | 'alg_not_allowed'
  | 'unknown_kid'
  | 'invalid_signature'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'expired'
  | 'not_yet_valid'
  | 'issued_in_future'
  | 'nonce_mismatch';

export class JwtError extends Error {
  readonly code: JwtErrorCode;

  constructor(message: string, code: JwtErrorCode, options?: ErrorOptions) {
    super(message, options);
    this.name = 'JwtError';
    this.code = code;
  }
}
