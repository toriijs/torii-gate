/**
 * Environment Variable Loader
 *
 * Maps flat environment variables to the ToriiConfig shape.
 * Runs synchronously once inside the lazy runtime initializer.
 * Valibot schema validation follows immediately after.
 *
 * Environment variable naming convention:
 *   TORII_OIDC_ISSUER         → config.oidc.issuer
 *   TORII_OIDC_CLIENT_ID      → config.oidc.clientId
 *   TORII_SESSION_TYPE        → config.session.type
 *   TORII_UPSTREAM_URL        → config.routing.upstreamUrl
 *   etc.
 *
 * All variables are optional at this stage — Valibot validation
 * will throw with clear field-level messages if required vars are missing.
 */

import { parse } from 'valibot';
import { ToriiConfigSchema, type ToriiConfig } from './schema.js';

/** Raw environment — Record<string, string> works for all edge runtimes */
export type Env = Record<string, string | undefined>;

/**
 * Loads and validates configuration from environment variables.
 *
 * @throws ValiError with field-level messages if required vars are missing
 *         or values are invalid.
 */
export function loadConfigFromEnv(env: Env): ToriiConfig {
  const sessionType = env['TORII_SESSION_TYPE'] ?? 'cookie';

  const rawConfig = {
    oidc: {
      issuer: env['TORII_OIDC_ISSUER'],
      clientId: env['TORII_OIDC_CLIENT_ID'],
      clientSecret: env['TORII_OIDC_CLIENT_SECRET'],
      redirectUri: env['TORII_OIDC_REDIRECT_URI'],
      scopes: env['TORII_OIDC_SCOPES']?.split(',').map((s) => s.trim()),
    },

    session: buildSessionConfig(sessionType, env),

    routing: {
      agentPrefix: env['TORII_AGENT_PREFIX'] ?? '/auth',
      proxyPrefix: env['TORII_PROXY_PREFIX'] ?? '/api',
      upstreamUrl: env['TORII_UPSTREAM_URL'],
    },

    security: {
      topology: (env['TORII_TOPOLOGY'] ?? 'same-domain') as 'same-domain' | 'subdomain',
      // Only include cookieDomain if it's provided (required for subdomain, forbidden for same-domain)
      ...(env['TORII_COOKIE_DOMAIN'] ? { cookieDomain: env['TORII_COOKIE_DOMAIN'] } : {}),
      csrfHeader: env['TORII_CSRF_HEADER'] ?? 'x-torii-request',
      cookieName: env['TORII_COOKIE_NAME'], // undefined → derived from topology
      allowedOrigins: env['TORII_ALLOWED_ORIGINS']
        ?.split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    },
  };

  // Valibot validates the shape, required fields, and type constraints
  // Throws ValiError with precise field-level error messages on failure
  return parse(ToriiConfigSchema, rawConfig);
}

function buildSessionConfig(type: string, env: Env): unknown {
  switch (type) {
    case 'redis':
      return {
        type: 'redis',
        url: env['TORII_SESSION_REDIS_URL'],
        token: env['TORII_SESSION_REDIS_TOKEN'],
        maxAge: parseOptionalInt(env['TORII_SESSION_MAX_AGE']),
        keyPrefix: env['TORII_SESSION_REDIS_KEY_PREFIX'],
      };

    case 'upstash':
      return {
        type: 'upstash',
        url: env['TORII_SESSION_REDIS_URL'],
        token: env['TORII_SESSION_REDIS_TOKEN'],
        maxAge: parseOptionalInt(env['TORII_SESSION_MAX_AGE']),
        keyPrefix: env['TORII_SESSION_REDIS_KEY_PREFIX'],
      };

    case 'memory':
      return {
        type: 'memory',
        maxAge: parseOptionalInt(env['TORII_SESSION_MAX_AGE']),
      };

    case 'cookie':
    default:
      return {
        type: 'cookie',
        secret: env['TORII_SESSION_SECRET'],
        maxAge: parseOptionalInt(env['TORII_SESSION_MAX_AGE']),
      };
  }
}

function parseOptionalInt(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? undefined : parsed;
}
