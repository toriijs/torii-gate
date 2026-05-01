/**
 * Runtime Initializer
 *
 * Cold start design — four sources of latency eliminated:
 *
 *   1. JS parse time       → nothing in module scope, zero parse overhead
 *   2. Module init         → no top-level await, no side effects at import
 *   3. OIDC discovery      → fetched once, cached forever in module scope
 *   4. Crypto key derive   → derived once for cookie adapter, reused across requests
 *
 * The lazy singleton pattern:
 *   - Module scope holds null until first request
 *   - First request triggers initialize() exactly once
 *   - All subsequent requests receive the cached RuntimeState instantly
 *   - Concurrent first requests await the same Promise — no duplicate init
 *
 * Lifecycle:
 *   Cold start:   JS parse → module scope (null) → first request → initialize()
 *   Warm request: getRuntime() → state exists → return immediately (zero cost)
 */

import { discoverIssuer, type IssuerMetadata } from '../oidc/discovery.js';
import { createJwksClient } from '../oidc/jwks.js';
import type { JwksKeySource } from '../security/jwt.js';
import type { SessionAdapter } from '../adapters/interface.js';
import type { ToriiConfig } from '../config/schema.js';
import { validateTopologyConfig } from '../security/topology.js';

export interface RuntimeState {
  /** Validated, parsed configuration */
  config: ToriiConfig;
  /** OIDC provider metadata — fetched once at startup */
  issuerMetadata: IssuerMetadata;
  /**
   * Pre-derived AES-GCM key for cookie session encryption.
   * null when session type is 'redis' or 'memory' — no key needed.
   * Never re-derived on the request hot path.
   */
  sessionKey: CryptoKey | null;
  /** Session adapter instance — created once */
  adapter: SessionAdapter;
  /** JWKS key source — for ID token signature verification */
  keySource: JwksKeySource | null;
}

// ─── Module-scope cache — nothing runs at parse time ─────────────────────────

let _state: RuntimeState | null = null;
let _initPromise: Promise<RuntimeState> | null = null;

/**
 * Returns the runtime state, initializing it on the first call.
 *
 * Safe to call concurrently — concurrent callers await the same Promise.
 * After initialization, returns the cached state synchronously (via Promise).
 */
export async function getRuntime(
  config: ToriiConfig,
  adapterFactory: (config: ToriiConfig) => Promise<SessionAdapter>,
  fetchFn?: typeof fetch,
): Promise<RuntimeState> {
  // Hot path — already initialized, return immediately
  if (_state !== null) return _state;

  // Initialization in flight — await same Promise, don't double-init
  if (_initPromise !== null) return _initPromise;

  // First request in this isolate — initialize once
  _initPromise = initialize(config, adapterFactory, fetchFn).then((state) => {
    _state = state;
    _initPromise = null;
    return state;
  });

  return _initPromise;
}

/**
 * Resets the runtime state — testing only.
 * Never call in production code.
 */
export function _resetRuntime(): void {
  _state = null;
  _initPromise = null;
}

async function initialize(
  config: ToriiConfig,
  adapterFactory: (config: ToriiConfig) => Promise<SessionAdapter>,
  fetchFn?: typeof fetch,
): Promise<RuntimeState> {
  // Cross-field topology validation — catches misconfiguration at startup
  // (e.g. subdomain topology with wrong cookie prefix, missing allowedOrigins)
  const security = config.security;
  const topologyErrors = validateTopologyConfig(
    security.topology,
    security.topology === 'subdomain' ? security.cookieDomain : undefined,
    security.allowedOrigins,
    security.cookieName,
  );

  if (topologyErrors.length > 0) {
    const messages = topologyErrors.map((e) => `  [${e.field}] ${e.message}`).join('\n');
    throw new Error(`Torii topology configuration errors:\n${messages}`);
  }

  // Parallelise all async init work — total time = max(tasks) not sum(tasks)
  const [issuerMetadata, sessionKey, adapter] = await Promise.all([
    discoverIssuer(config.oidc.issuer, {
      fetch: fetchFn,
    }),
    deriveSessionKeyFromConfig(config),
    adapterFactory(config),
  ]);

  // Create JWKS client if jwks_uri is available (required for ID token verification)
  const keySource = issuerMetadata.jwks_uri
    ? createJwksClient({
        jwksUri: issuerMetadata.jwks_uri,
        fetch: fetchFn,
      })
    : null;

  return { config, issuerMetadata, sessionKey, adapter, keySource };
}

/**
 * Derives a session key only when the cookie adapter is configured.
 *
 * Narrows the discriminated union on session.type before accessing .secret —
 * TypeScript requires this because .secret only exists on the cookie variant.
 *
 * Returns null for redis and memory adapters — they don't use a client-side key.
 */
async function deriveSessionKeyFromConfig(config: ToriiConfig): Promise<CryptoKey | null> {
  // Discriminated union narrowing — type guard on session.type
  if (config.session.type !== 'cookie') return null;
  // TypeScript now knows config.session is CookieSessionConfig
  // .secret is safely accessible
  return deriveSessionKey(config.session.secret);
}

/**
 * Derives an AES-GCM-256 key from a secret string using HKDF-SHA256.
 *
 * Called at most once per isolate lifetime — never on the request hot path.
 * The resulting CryptoKey is stored in RuntimeState and reused for all
 * cookie session encrypt/decrypt operations.
 *
 * Web Crypto API only — runs identically on all edge runtimes.
 */
export async function deriveSessionKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();

  // Import the raw secret as HKDF key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    'HKDF',
    false, // not extractable — key never leaves runtime memory
    ['deriveKey'],
  );

  // Derive AES-GCM-256 — versioned salt means changing the version
  // invalidates all existing cookie sessions cleanly
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode('torii-session-v1'),
      info: encoder.encode('session-encryption'),
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, // not extractable
    ['encrypt', 'decrypt'],
  );
}
