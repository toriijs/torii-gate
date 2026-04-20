/**
 * Config Schema Test Suite
 *
 * Validates that the Valibot schema enforces all required fields
 * and constraints at startup time — before any request is served.
 */

import { describe, it, expect } from 'vitest';
import { parse, ValiError } from 'valibot';
import { ToriiConfigSchema } from '../../src/config/schema';

const VALID_CONFIG = {
  oidc: {
    issuer: 'https://auth.torii.local/realms/test',
    clientId: 'my-client',
    clientSecret: 'my-secret',
    redirectUri: 'https://app.example.com/auth/callback',
  },
  session: {
    type: 'cookie' as const,
    secret: 'a'.repeat(32),
  },
  routing: {
    upstreamUrl: 'https://api.example.com',
  },
};

// ─── Happy path ───────────────────────────────────────────────────────────────

describe('toriiConfigSchema — valid config', () => {
  it('parses a minimal valid config', () => {
    expect(() => parse(ToriiConfigSchema, VALID_CONFIG)).not.toThrow();
  });

  it('applies default scopes when not specified', () => {
    const result = parse(ToriiConfigSchema, VALID_CONFIG);

    expect(result.oidc.scopes).toStrictEqual(['openid', 'profile', 'email']);
  });

  it('applies default agentPrefix /auth', () => {
    const result = parse(ToriiConfigSchema, VALID_CONFIG);

    expect(result.routing.agentPrefix).toBe('/auth');
  });

  it('applies default proxyPrefix /api', () => {
    const result = parse(ToriiConfigSchema, VALID_CONFIG);

    expect(result.routing.proxyPrefix).toBe('/api');
  });

  it('applies default cookie maxAge of 900', () => {
    const result = parse(ToriiConfigSchema, VALID_CONFIG);

    expect(result.session.type).toBe('cookie');

    // eslint-disable-next-line vitest/no-conditional-in-test
    if (result.session.type !== 'cookie') throw new Error('Expected cookie session type');

    expect(result.session.maxAge).toBe(900);
  });

  it('accepts Redis session config', () => {
    const config = {
      ...VALID_CONFIG,
      session: { type: 'redis' as const, url: 'redis://localhost:6379' },
    };

    expect(() => parse(ToriiConfigSchema, config)).not.toThrow();
  });

  it('accepts memory session config', () => {
    const config = {
      ...VALID_CONFIG,
      session: { type: 'memory' as const },
    };

    expect(() => parse(ToriiConfigSchema, config)).not.toThrow();
  });

  it('accepts Upstash session config with token', () => {
    const config = {
      ...VALID_CONFIG,
      session: {
        type: 'upstash' as const,
        url: 'https://us1-rare-shark-12345.upstash.io',
        token: 'AaBbCc...XxYyZz',
      },
    };

    expect(() => parse(ToriiConfigSchema, config)).not.toThrow();
  });

  it('accepts Upstash with redis:// protocol URL', () => {
    const config = {
      ...VALID_CONFIG,
      session: {
        type: 'upstash' as const,
        url: 'redis://upstash-host.upstash.io:6379',
        token: 'token123',
      },
    };

    expect(() => parse(ToriiConfigSchema, config)).not.toThrow();
  });

  it('applies default maxAge of 28800 for Upstash', () => {
    const result = parse(ToriiConfigSchema, {
      ...VALID_CONFIG,
      session: {
        type: 'upstash' as const,
        url: 'https://us1-rare-shark-12345.upstash.io',
        token: 'token123',
      },
    });

    expect(result.session.type).toBe('upstash');

    // eslint-disable-next-line vitest/no-conditional-in-test
    if (result.session.type !== 'upstash') throw new Error('Expected upstash session type');

    expect(result.session.maxAge).toBe(28800);
  });

  it('applies default keyPrefix for Upstash', () => {
    const result = parse(ToriiConfigSchema, {
      ...VALID_CONFIG,
      session: {
        type: 'upstash' as const,
        url: 'https://us1-rare-shark-12345.upstash.io',
        token: 'token123',
      },
    });

    expect(result.session.type).toBe('upstash');

    // eslint-disable-next-line vitest/no-conditional-in-test
    if (result.session.type !== 'upstash') throw new Error('Expected upstash session type');

    expect(result.session.keyPrefix).toBe('torii:session:');
  });
});

// ─── OIDC validation ──────────────────────────────────────────────────────────

describe('toriiConfigSchema — OIDC validation', () => {
  it('throws when issuer uses HTTP', () => {
    const config = {
      ...VALID_CONFIG,
      oidc: { ...VALID_CONFIG.oidc, issuer: 'http://auth.torii.local' },
    };

    expect(() => parse(ToriiConfigSchema, config)).toThrow(ValiError);
  });

  it('throws when clientId is empty', () => {
    const config = {
      ...VALID_CONFIG,
      oidc: { ...VALID_CONFIG.oidc, clientId: '' },
    };

    expect(() => parse(ToriiConfigSchema, config)).toThrow(ValiError);
  });

  it('throws when redirectUri uses HTTP', () => {
    const config = {
      ...VALID_CONFIG,
      oidc: { ...VALID_CONFIG.oidc, redirectUri: 'http://app.example.com/callback' },
    };

    expect(() => parse(ToriiConfigSchema, config)).toThrow(ValiError);
  });

  it('throws when issuer is missing', () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { issuer: _, ...noIssuer } = VALID_CONFIG.oidc;

    expect(() => parse(ToriiConfigSchema, { ...VALID_CONFIG, oidc: noIssuer })).toThrow(ValiError);
  });

  it('rejects HTTP URLs (HTTPS required)', () => {
    const httpIssuer = {
      ...VALID_CONFIG,
      oidc: { ...VALID_CONFIG.oidc, issuer: 'http://auth.torii.local' },
    };

    expect(() => parse(ToriiConfigSchema, httpIssuer)).toThrow(/must use HTTPS/);

    const httpRedirectUri = {
      ...VALID_CONFIG,
      oidc: { ...VALID_CONFIG.oidc, redirectUri: 'http://app.example.com/callback' },
    };

    expect(() => parse(ToriiConfigSchema, httpRedirectUri)).toThrow(/must use HTTPS/);
  });
});

// ─── Session validation ───────────────────────────────────────────────────────

describe('toriiConfigSchema — session validation', () => {
  it('throws when cookie secret is shorter than 32 characters', () => {
    const config = {
      ...VALID_CONFIG,
      session: { type: 'cookie' as const, secret: 'short' },
    };

    expect(() => parse(ToriiConfigSchema, config)).toThrow(ValiError);
  });

  it('throws when Redis URL is not a valid URL', () => {
    const config = {
      ...VALID_CONFIG,
      session: { type: 'redis' as const, url: 'not-a-url' },
    };

    expect(() => parse(ToriiConfigSchema, config)).toThrow(ValiError);
  });

  it('throws when session type is unknown', () => {
    const config = {
      ...VALID_CONFIG,
      session: { type: 'unknown' },
    };

    expect(() => parse(ToriiConfigSchema, config)).toThrow(ValiError);
  });

  it('throws when Upstash config is missing token', () => {
    const config = {
      ...VALID_CONFIG,
      session: {
        type: 'upstash' as const,
        url: 'https://us1-rare-shark-12345.upstash.io',
      },
    };

    expect(() => parse(ToriiConfigSchema, config)).toThrow(ValiError);
  });

  it('throws when Upstash URL is not a valid URL', () => {
    const config = {
      ...VALID_CONFIG,
      session: {
        type: 'upstash' as const,
        url: 'not-a-url',
        token: 'token123',
      },
    };

    expect(() => parse(ToriiConfigSchema, config)).toThrow(ValiError);
  });
});

// ─── Routing validation ───────────────────────────────────────────────────────

describe('toriiConfigSchema — routing validation', () => {
  it('throws when upstreamUrl is missing', () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { upstreamUrl: _, ...noUpstream } = VALID_CONFIG.routing as typeof VALID_CONFIG.routing & { upstreamUrl?: string };

    expect(() => parse(ToriiConfigSchema, { ...VALID_CONFIG, routing: noUpstream })).toThrow(ValiError);
  });

  it('throws when upstreamUrl is not a valid URL', () => {
    const config = {
      ...VALID_CONFIG,
      routing: { upstreamUrl: 'not-a-url' },
    };

    expect(() => parse(ToriiConfigSchema, config)).toThrow(ValiError);
  });
});

// ─── Topology config ──────────────────────────────────────────────────────────

describe('toriiConfigSchema — topology', () => {
  it('defaults to same-domain topology', () => {
    const config = parse(ToriiConfigSchema, VALID_CONFIG);

    expect(config.security.topology).toBe('same-domain');
  });

  it('defaults cookieName to __Host-session for same-domain', () => {
    const config = parse(ToriiConfigSchema, VALID_CONFIG);

    expect(config.security.cookieName).toBe('__Host-session');
  });

  it('defaults cookieName to __Secure-session for subdomain', () => {
    const config = parse(ToriiConfigSchema, {
      ...VALID_CONFIG,
      security: {
        topology: 'subdomain',
        cookieDomain: 'example.com',
        allowedOrigins: ['https://app.example.com'],
      },
    });

    expect(config.security.cookieName).toBe('__Secure-session');
  });

  it('preserves explicit cookieName over default', () => {
    const config = parse(ToriiConfigSchema, {
      ...VALID_CONFIG,
      security: { topology: 'same-domain', cookieName: '__Host-my-app' },
    });

    expect(config.security.cookieName).toBe('__Host-my-app');
  });

  it('accepts subdomain topology', () => {
    expect(() =>
      parse(ToriiConfigSchema, {
        ...VALID_CONFIG,
        security: {
          topology: 'subdomain',
          cookieDomain: 'example.com',
          allowedOrigins: ['https://app.example.com'],
        },
      }),
    ).not.toThrow();
  });

  it('rejects unknown topology values', () => {
    expect(() =>
      parse(ToriiConfigSchema, {
        ...VALID_CONFIG,
        security: { topology: 'cross-origin' },
      }),
    ).toThrow(ValiError);
  });

  it('throws when subdomain topology lacks cookieDomain', () => {
    expect(() =>
      parse(ToriiConfigSchema, {
        ...VALID_CONFIG,
        security: {
          topology: 'subdomain',
          allowedOrigins: ['https://app.example.com'],
        },
      }),
    ).toThrow(ValiError);
  });

  it('throws when same-domain topology has cookieDomain', () => {
    expect(() =>
      parse(ToriiConfigSchema, {
        ...VALID_CONFIG,
        security: {
          topology: 'same-domain',
          cookieDomain: 'example.com',
        },
      }),
    ).toThrow(ValiError);
  });
});
