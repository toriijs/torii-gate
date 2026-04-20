/**
 * Configuration Schema
 *
 * Validated once at startup inside the lazy runtime initializer.
 * Never called on the request hot path.
 *
 * Valibot is used for its minimal bundle size (~1.37 kB) which matters
 * for edge runtime cold starts. Validation cost is paid exactly once
 * per isolate lifetime.
 */

import * as v from 'valibot';
import { isValidHttpsUrl } from '../security/https.js';

// ─── Session adapter sub-schemas ──────────────────────────────────────────────

const CookieSessionSchema = v.object({
  type: v.literal('cookie'),
  /** Minimum 32 characters — used to derive the AES-GCM encryption key */
  secret: v.pipe(v.string(), v.minLength(32, 'Session secret must be at least 32 characters')),
  /** Seconds until cookie expires — defaults to 900 (15 minutes) */
  maxAge: v.optional(v.pipe(v.number(), v.minValue(60), v.maxValue(28 * 60 * 60)), 900),
});

const RedisSessionSchema = v.object({
  type: v.literal('redis'),
  /** Redis connection URL — redis:// or rediss:// */
  url: v.pipe(v.string(), v.url('Redis URL must be a valid URL')),
  /** Upstash REST API token — optional, Upstash HTTP adapter only */
  token: v.optional(v.string()),
  /** Session TTL in seconds — defaults to 28800 (8 hours) */
  maxAge: v.optional(v.pipe(v.number(), v.minValue(60)), 28800),
  /** Redis key prefix — defaults to 'torii:session:' */
  keyPrefix: v.optional(v.string(), 'torii:session:'),
});

const UpstashSessionSchema = v.object({
  type: v.literal('upstash'),
  /** Upstash Redis REST URL — https:// for REST API or redis:// for native protocol */
  url: v.pipe(v.string(), v.url('Upstash URL must be a valid URL')),
  /** Upstash REST API token — required for authentication */
  token: v.string(),
  /** Session TTL in seconds — defaults to 28800 (8 hours) */
  maxAge: v.optional(v.pipe(v.number(), v.minValue(60)), 28800),
  /** Redis key prefix — defaults to 'torii:session:' */
  keyPrefix: v.optional(v.string(), 'torii:session:'),
});

const MemorySessionSchema = v.object({
  type: v.literal('memory'),
  /** Session TTL in seconds — defaults to 900 */
  maxAge: v.optional(v.pipe(v.number(), v.minValue(1)), 900),
});

const SessionSchema = v.variant('type', [CookieSessionSchema, RedisSessionSchema, UpstashSessionSchema, MemorySessionSchema]);

// ─── OIDC sub-schema ──────────────────────────────────────────────────────────

const OidcSchema = v.object({
  /** OIDC provider issuer URL — must be HTTPS */
  issuer: v.pipe(v.string(), v.url('OIDC issuer must be a valid URL')),
  clientId: v.pipe(v.string(), v.minLength(1, 'clientId must not be empty')),
  clientSecret: v.pipe(v.string(), v.minLength(1, 'clientSecret must not be empty')),
  /** Must be an HTTPS URL */
  redirectUri: v.pipe(v.string(), v.url('redirectUri must be a valid URL')),
  /** Must include 'openid' */
  scopes: v.optional(v.pipe(v.array(v.string()), v.minLength(1)), ['openid', 'profile', 'email']),
});

// ─── Routing sub-schema ───────────────────────────────────────────────────────

const RoutingSchema = v.object({
  /** Path prefix for OAuth Agent routes — defaults to '/auth' */
  agentPrefix: v.optional(v.string(), '/auth'),
  /** Path prefix for API proxy routes — defaults to '/api' */
  proxyPrefix: v.optional(v.string(), '/api'),
  /** Upstream API base URL — requests are forwarded here */
  upstreamUrl: v.pipe(v.string(), v.url('upstreamUrl must be a valid URL')),
});

// ─── Security sub-schema ──────────────────────────────────────────────────────

/**
 * Base security fields common to both topologies.
 */
const BaseSecurityFields = {
  /**
   * Required custom header name for CSRF protection.
   * Any non-empty value is accepted — presence is what matters.
   * Default: 'x-torii-request'
   */
  csrfHeader: v.optional(v.string(), 'x-torii-request'),
  /**
   * Session cookie name.
   * Defaults to '__Host-session' for same-domain topology.
   * Defaults to '__Secure-session' for subdomain topology.
   *
   * Must start with __Host- (same-domain) or __Secure- (subdomain).
   * Torii derives the correct default automatically from the topology.
   */
  cookieName: v.optional(v.string()),
  /**
   * Allowed CORS origins — explicit HTTPS origins only.
   * No wildcards permitted.
   * Required (non-empty) when topology is 'subdomain'.
   */
  allowedOrigins: v.optional(v.array(v.string()), []),
};

/**
 * Same-domain topology security config.
 *
 * SPA and Torii gate (BFF) on the same origin (app.torii.dev for both).
 * Uses __Host- cookie prefix — strongest security.
 * SameSite=Strict. No Domain attribute. No CORS needed.
 */
const SameDomainSecuritySchema = v.pipe(
  v.object({
    topology: v.literal('same-domain' as const),
    // cookieDomain should not be set for same-domain — validated by refinement
    cookieDomain: v.optional(v.any()),
    ...BaseSecurityFields,
  }),
  v.check((data) => data.cookieDomain === undefined, 'cookieDomain must not be set for same-domain topology'),
);

/**
 * Subdomain topology security config.
 *
 * SPA and Torii gate(BFF) on separate subdomains (app.torii.dev + gate.torii.dev).
 * Uses __Secure- cookie prefix + Domain=.torii.dev.
 * SameSite=Lax. Full CORS required. cookieDomain must be set.
 */
const SubdomainSecuritySchema = v.object({
  topology: v.literal('subdomain' as const),
  /**
   * Shared parent domain — required for subdomain topology.
   *
   * @example 'example.com' — for app.torii.dev + gate.torii.dev
   *
   * Do not include a leading dot, scheme, or port.
   * Torii adds the leading dot automatically: Domain=.torii.dev
   */
  cookieDomain: v.string(),
  ...BaseSecurityFields,
});

/**
 * Discriminated union for security config based on topology.
 *
 * TypeScript will automatically narrow the type based on the topology value:
 * - topology: 'same-domain' → cookieDomain is never
 * - topology: 'subdomain' → cookieDomain is string (required)
 */
const SecuritySchema = v.variant('topology', [SameDomainSecuritySchema, SubdomainSecuritySchema]);

// ─── Root config schema ───────────────────────────────────────────────────────

const RawToriiConfigSchema = v.pipe(
  v.object({
    oidc: OidcSchema,
    session: SessionSchema,
    routing: RoutingSchema,
    /**
     * Security config is optional here — the transform will create a default
     * same-domain config if not provided. We can't provide a default value
     * directly on the variant schema because the discriminant cannot have defaults.
     */
    security: v.optional(SecuritySchema),
  }),
  // HTTPS validation for all URLs
  v.check((config) => {
    // Validate OIDC issuer
    if (!isValidHttpsUrl(config.oidc.issuer)) {
      return false;
    }

    // Validate OIDC redirectUri
    if (!isValidHttpsUrl(config.oidc.redirectUri)) {
      return false;
    }

    // Validate allowedOrigins if security is provided
    if (config.security?.allowedOrigins) {
      for (const origin of config.security.allowedOrigins) {
        if (!isValidHttpsUrl(origin)) {
          return false;
        }
      }
    }

    return true;
  }, 'URL must use HTTPS'),
);

/**
 * ToriiConfigSchema
 *
 * After field-level Valibot validation, a transform handles:
 * 1. Default security config creation when not provided (same-domain topology)
 * 2. cookieName default derivation based on topology:
 *    - same-domain → '__Host-session'
 *    - subdomain   → '__Secure-session'
 *
 * The SecuritySchema is a discriminated union on 'topology', which enables
 * TypeScript to automatically narrow types (e.g., cookieDomain is required
 * for subdomain topology). This eliminates the need for type casts downstream.
 *
 * Cross-field validation (topology vs allowedOrigins, cookie prefix) is still
 * enforced at runtime in validateTopologyConfig() called by the initializer.
 */
export const ToriiConfigSchema = v.pipe(
  RawToriiConfigSchema,
  v.transform((config) => {
    // If security not provided at all, create default same-domain config
    if (!config.security) {
      return {
        ...config,
        security: {
          topology: 'same-domain' as const,
          csrfHeader: 'x-torii-request',
          cookieName: '__Host-session' as const,
          allowedOrigins: [],
        },
      };
    }

    // Security provided — derive cookieName default based on topology
    const topology = config.security.topology;
    const defaultCookieName = topology === 'same-domain' ? ('__Host-session' as const) : ('__Secure-session' as const);

    return {
      ...config,
      security: {
        ...config.security,
        cookieName: config.security.cookieName ?? defaultCookieName,
      },
    };
  }),
);

export type ToriiConfig = v.InferOutput<typeof ToriiConfigSchema>;

// ─── Re-export sub-types ──────────────────────────────────────────────────────

export type CookieSessionConfig = v.InferOutput<typeof CookieSessionSchema>;
export type RedisSessionConfig = v.InferOutput<typeof RedisSessionSchema>;
export type UpstashSessionConfig = v.InferOutput<typeof UpstashSessionSchema>;
export type MemorySessionConfig = v.InferOutput<typeof MemorySessionSchema>;
export type SessionConfig = v.InferOutput<typeof SessionSchema>;
export type OidcConfig = v.InferOutput<typeof OidcSchema>;
export type RoutingConfig = v.InferOutput<typeof RoutingSchema>;

/**
 * Manually defined discriminated union for SecurityConfig.
 *
 * This overrides Valibot's inferred type to ensure TypeScript properly narrows
 * based on the topology discriminant. When topology is 'subdomain', cookieDomain
 * is guaranteed to be string (not string | undefined).
 */
export type SecurityConfig =
  | {
      topology: 'same-domain';
      csrfHeader: string;
      cookieName: string;
      allowedOrigins: string[];
    }
  | {
      topology: 'subdomain';
      cookieDomain: string;
      csrfHeader: string;
      cookieName: string;
      allowedOrigins: string[];
    };
