/**
 * Environment Variable Loader Test Suite
 *
 * Tests the mapping of flat environment variables to ToriiConfig.
 * Validates integration with Valibot schema validation.
 */

import { describe, it, expect } from 'vitest';
import { loadConfigFromEnv, type Env } from './env';
import { ValiError } from 'valibot';

const BASE_ENV: Env = {
  TORII_OIDC_ISSUER: 'https://auth.torii.dev',
  TORII_OIDC_CLIENT_ID: 'client',
  TORII_OIDC_CLIENT_SECRET: 'secret',
  TORII_OIDC_REDIRECT_URI: 'https://app.torii.dev/auth/callback',
  TORII_UPSTREAM_URL: 'https://api.torii.dev',
  TORII_SESSION_SECRET: 'x'.repeat(32), // Required for cookie session (default type)
};

describe('loadConfigFromEnv — cookie session', () => {
  it('loads valid cookie session config from environment', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_SESSION_TYPE: 'cookie',
      TORII_SESSION_SECRET: 'a'.repeat(32),
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.oidc.issuer).toBe('https://auth.torii.dev');
    expect(config.oidc.clientId).toBe('client');
    expect(config.session.type).toBe('cookie');

    const session = config.session as Extract<typeof config.session, { type: 'cookie' }>;

    expect(session.secret).toBe('a'.repeat(32));
    expect(config.routing.upstreamUrl).toBe('https://api.torii.dev');
  });

  it('defaults to cookie session when TORII_SESSION_TYPE is unset', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_SESSION_SECRET: 'b'.repeat(32),
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.session.type).toBe('cookie');
  });
});

describe('loadConfigFromEnv — redis session', () => {
  it('loads redis session config with all fields', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_SESSION_TYPE: 'redis',
      TORII_SESSION_REDIS_URL: 'redis://localhost:6379',
      TORII_SESSION_REDIS_TOKEN: 'redis-token',
      TORII_SESSION_MAX_AGE: '1800',
      TORII_SESSION_REDIS_KEY_PREFIX: 'torii:session:',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.session.type).toBe('redis');

    // Type assertion after checking type
    const session = config.session as Extract<typeof config.session, { type: 'redis' }>;

    expect(session.url).toBe('redis://localhost:6379');
    expect(session.token).toBe('redis-token');
    expect(session.maxAge).toBe(1800);
    expect(session.keyPrefix).toBe('torii:session:');
  });

  it('loads redis session config without optional fields', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_SESSION_TYPE: 'redis',
      TORII_SESSION_REDIS_URL: 'redis://localhost:6379',
      TORII_SESSION_REDIS_TOKEN: 'redis-token',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.session.type).toBe('redis');

    const session = config.session as Extract<typeof config.session, { type: 'redis' }>;

    expect(session.maxAge).toBeDefined(); // Will use default from schema
  });
});

describe('loadConfigFromEnv — upstash session', () => {
  it('loads upstash session config', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_SESSION_TYPE: 'upstash',
      TORII_SESSION_REDIS_URL: 'https://upstash.redis.com',
      TORII_SESSION_REDIS_TOKEN: 'upstash-token',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.session.type).toBe('upstash');

    const session = config.session as Extract<typeof config.session, { type: 'upstash' }>;

    expect(session.url).toBe('https://upstash.redis.com');
    expect(session.token).toBe('upstash-token');
  });

  it('loads upstash with optional key prefix', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_SESSION_TYPE: 'upstash',
      TORII_SESSION_REDIS_URL: 'https://upstash.redis.com',
      TORII_SESSION_REDIS_TOKEN: 'upstash-token',
      TORII_SESSION_REDIS_KEY_PREFIX: 'custom:prefix:',
    };

    // Act
    const config = loadConfigFromEnv(env);

    const session = config.session as Extract<typeof config.session, { type: 'upstash' }>;

    // Assert
    expect(session.keyPrefix).toBe('custom:prefix:');
  });
});

describe('loadConfigFromEnv — memory session', () => {
  it('loads memory session config', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_SESSION_TYPE: 'memory',
      TORII_SESSION_MAX_AGE: '900',
    };

    // Act
    const config = loadConfigFromEnv(env);

    expect(config.session.type).toBe('memory');

    const session = config.session as Extract<typeof config.session, { type: 'memory' }>;

    expect(session.maxAge).toBe(900);
  });

  it('loads memory session with default maxAge', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_SESSION_TYPE: 'memory',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.session.type).toBe('memory');

    const session = config.session as Extract<typeof config.session, { type: 'memory' }>;

    expect(session.maxAge).toBeDefined();
  });
});

describe('loadConfigFromEnv — OIDC scopes', () => {
  it('splits comma-separated scopes', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_OIDC_SCOPES: 'openid,profile,email',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.oidc.scopes).toStrictEqual(['openid', 'profile', 'email']);
  });

  it('trims whitespace from scopes', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_OIDC_SCOPES: ' openid , profile , email ',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.oidc.scopes).toStrictEqual(['openid', 'profile', 'email']);
  });

  it('handles undefined scopes', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.oidc.scopes).toBeDefined(); // Will use default from schema
  });
});

// ─── Topology and security ────────────────────────────────────────────────────

describe('loadConfigFromEnv — topology and security', () => {
  it('defaults topology to same-domain', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.security.topology).toBe('same-domain');
  });

  it('loads subdomain topology with cookieDomain', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_TOPOLOGY: 'subdomain',
      TORII_COOKIE_DOMAIN: 'torii.dev',
      TORII_ALLOWED_ORIGINS: 'https://app.torii.dev',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.security.topology).toBe('subdomain');
    expect(config.security.cookieDomain).toBe('torii.dev');
  });

  it('omits cookieDomain when not provided', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.security.cookieDomain).toBeUndefined();
  });

  it('parses allowedOrigins as comma-separated list', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_ALLOWED_ORIGINS: 'https://app.torii.dev,https://admin.torii.dev',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.security.allowedOrigins).toStrictEqual(['https://app.torii.dev', 'https://admin.torii.dev']);
  });

  it('filters empty strings from allowedOrigins', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_ALLOWED_ORIGINS: 'https://app.torii.dev,,https://admin.torii.dev,',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.security.allowedOrigins).toStrictEqual(['https://app.torii.dev', 'https://admin.torii.dev']);
  });

  it('sets custom CSRF header', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_CSRF_HEADER: 'x-custom-csrf',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.security.csrfHeader).toBe('x-custom-csrf');
  });

  it('uses default CSRF header when not provided', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.security.csrfHeader).toBe('x-torii-request');
  });
});

describe('loadConfigFromEnv — routing defaults', () => {
  it('defaults agentPrefix to /auth', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
    };

    // Act
    const config = loadConfigFromEnv(env);

    expect(config.routing.agentPrefix).toBe('/auth');
  });

  it('defaults proxyPrefix to /api', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
    };

    // Act
    const config = loadConfigFromEnv(env);

    expect(config.routing.proxyPrefix).toBe('/api');
  });

  it('accepts custom routing prefixes', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_AGENT_PREFIX: '/custom-auth',
      TORII_PROXY_PREFIX: '/custom-api',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.routing.agentPrefix).toBe('/custom-auth');
    expect(config.routing.proxyPrefix).toBe('/custom-api');
  });
});

describe('loadConfigFromEnv — integer parsing', () => {
  it('parses valid integer strings for maxAge', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_SESSION_TYPE: 'memory',
      TORII_SESSION_MAX_AGE: '3600',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert
    expect(config.session.maxAge).toBe(3600);
  });

  it('handles empty string for optional integer', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_SESSION_TYPE: 'memory',
      TORII_SESSION_MAX_AGE: '',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert - Valibot will apply default for undefined
    expect(config.session.maxAge).toBeDefined();
  });

  it('handles NaN for optional integer', () => {
    // Arrange
    const env: Env = {
      ...BASE_ENV,
      TORII_SESSION_TYPE: 'memory',
      TORII_SESSION_MAX_AGE: 'not-a-number',
    };

    // Act
    const config = loadConfigFromEnv(env);

    // Assert - Valibot will apply default for undefined
    expect(config.session.maxAge).toBeDefined();
  });
});

describe('loadConfigFromEnv — Valibot validation', () => {
  it('throws when required OIDC issuer is missing', () => {
    // Arrange
    const env: Env = {
      TORII_OIDC_CLIENT_ID: 'client',
      TORII_OIDC_CLIENT_SECRET: 'secret',
      TORII_OIDC_REDIRECT_URI: 'https://app.torii.dev/auth/callback',
      TORII_UPSTREAM_URL: 'https://api.torii.dev',
    };

    // Act & Assert
    expect(() => loadConfigFromEnv(env)).toThrow(ValiError);
  });

  it('throws when required client_id is missing', () => {
    // Arrange
    const env: Env = {
      TORII_OIDC_ISSUER: 'https://auth.torii.dev',
      TORII_OIDC_CLIENT_SECRET: 'secret',
      TORII_OIDC_REDIRECT_URI: 'https://app.torii.dev/auth/callback',
      TORII_UPSTREAM_URL: 'https://api.torii.dev',
    };

    // Act & Assert
    expect(() => loadConfigFromEnv(env)).toThrow(ValiError);
  });

  it('throws for invalid issuer URL', () => {
    // Arrange
    const env: Env = {
      TORII_OIDC_ISSUER: 'not-a-url',
      TORII_OIDC_CLIENT_ID: 'client',
      TORII_OIDC_CLIENT_SECRET: 'secret',
      TORII_OIDC_REDIRECT_URI: 'https://app.torii.dev/auth/callback',
      TORII_UPSTREAM_URL: 'https://api.torii.dev',
    };

    // Act & Assert
    expect(() => loadConfigFromEnv(env)).toThrow(ValiError);
  });
});
