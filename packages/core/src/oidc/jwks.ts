/**
 * JWKS Client
 *
 * Fetches and caches the provider's JSON Web Key Set, exposing it through
 * the `JwksKeySource` contract consumed by `security/jwt.ts`.
 *
 * RFC 7517 — JSON Web Key
 * RFC 7515 — JSON Web Signature
 *
 * Caching strategy:
 *   - Keys are cached per `kid` for `maxCacheMs` (default 10 minutes).
 *   - A lookup for an unknown `kid` triggers at most one forced refresh
 *     (handles provider-side key rotation without manual invalidation).
 *   - Keys with no `kid` in the JWKS are accepted only when the JWKS has
 *     a single entry bound to the requested alg — otherwise the caller
 *     would be making an algorithm-confusion bet.
 */

import { isValidHttpsUrl } from '../security/https.js';
import { importJwkVerifyKey, type JwsAlgorithm } from '../security/webcrypto.js';
import type { JwksKeySource } from '../security/jwt.js';

/** Raw JWK entry as fetched from a JWKS document. */
interface Jwk extends JsonWebKey {
  kid?: string;
  alg?: string;
  use?: string;
}

interface JwksDocument {
  keys: Jwk[];
}

export interface JwksClientOptions {
  /** JWKS URI from OIDC discovery — MUST be HTTPS. */
  jwksUri: string;
  /** Injectable fetch — defaults to global fetch. */
  fetch?: typeof fetch | undefined;
  /** Max cache age in milliseconds. Defaults to 10 minutes. */
  maxCacheMs?: number | undefined;
  /** HTTP timeout for a single JWKS fetch in ms. Defaults to 5000. */
  timeoutMs?: number | undefined;
}

/**
 * Creates a JWKS client. The returned object implements `JwksKeySource`
 * directly and exposes `refresh()` for tests / manual invalidation.
 */
export function createJwksClient(options: JwksClientOptions): JwksKeySource & { refresh: () => Promise<void> } {
  if (!isValidHttpsUrl(options.jwksUri)) {
    throw new JwksError(`JWKS URI must be HTTPS (got "${options.jwksUri}")`, 'invalid_jwks_uri');
  }

  const fetchFn = options.fetch ?? fetch;
  const maxCacheMs = options.maxCacheMs ?? 10 * 60 * 1000;
  const timeoutMs = options.timeoutMs ?? 5000;

  let cache: { keys: Jwk[]; expiresAt: number } | null = null;
  let inflight: Promise<void> | null = null;

  async function fetchJwks(): Promise<void> {
    if (inflight) return inflight;

    inflight = (async () => {
      const controller = new AbortController();
      const timeout = setTimeout(() => {
        controller.abort();
      }, timeoutMs);

      let response: Response;
      try {
        response = await fetchFn(options.jwksUri, {
          headers: { accept: 'application/json' },
          signal: controller.signal,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'unknown error';
        throw new JwksError(`JWKS fetch failed for "${options.jwksUri}": ${message}`, 'fetch_failed');
      } finally {
        clearTimeout(timeout);
      }

      if (!response.ok) {
        throw new JwksError(`JWKS endpoint returned HTTP ${response.status}`, 'http_error');
      }

      const raw = (await response.json().catch(() => null)) as JwksDocument | null;
      if (!raw || !Array.isArray(raw.keys)) {
        throw new JwksError('JWKS document missing "keys" array', 'malformed_jwks');
      }

      cache = { keys: raw.keys, expiresAt: Date.now() + maxCacheMs };
    })();

    try {
      await inflight;
    } finally {
      inflight = null;
    }
  }

  async function ensureCache(): Promise<void> {
    if (!cache || Date.now() > cache.expiresAt) {
      await fetchJwks();
    }
  }

  function selectJwk(keys: readonly Jwk[], kid: string | undefined, alg: JwsAlgorithm): Jwk | null {
    const candidates = keys.filter((k) => {
      if (k.use && k.use !== 'sig') return false;
      if (k.alg && k.alg !== alg) return false;
      return true;
    });

    if (kid !== undefined) {
      return candidates.find((k) => k.kid === kid) ?? null;
    }

    // No kid in header — only safe when exactly one candidate key exists.
    if (candidates.length === 1) return candidates[0] ?? null;
    if (candidates.length === 0) return null;
    throw new JwksError('JWKS contains multiple keys but JWT header has no kid', 'ambiguous_key');
  }

  async function getKey(kid: string | undefined, alg: JwsAlgorithm): Promise<CryptoKey> {
    await ensureCache();
    // Safe: ensureCache() guarantees cache is populated
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    let jwk = selectJwk(cache!.keys, kid, alg);

    if (!jwk && kid !== undefined) {
      // Unknown kid — provider may have rotated; force one refresh.
      await fetchJwks();
      // Safe: fetchJwks() guarantees cache is populated
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      jwk = selectJwk(cache!.keys, kid, alg);
    }

    if (!jwk) {
      throw new JwksError(`JWKS has no key matching kid="${kid ?? ''}" alg="${alg}"`, 'key_not_found');
    }

    return importJwkVerifyKey(jwk, alg);
  }

  async function refresh(): Promise<void> {
    cache = null;
    await fetchJwks();
  }

  return { getKey, refresh };
}

export type JwksErrorCode = 'invalid_jwks_uri' | 'fetch_failed' | 'http_error' | 'malformed_jwks' | 'key_not_found' | 'ambiguous_key';

export class JwksError extends Error {
  readonly code: JwksErrorCode;

  constructor(message: string, code: JwksErrorCode, options?: ErrorOptions) {
    super(message, options);
    this.name = 'JwksError';
    this.code = code;
  }
}
