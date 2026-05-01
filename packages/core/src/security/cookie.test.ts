/**
 * Cookie Security Test Suite
 *
 * RFC 6265bis — Cookies: HTTP State Management Mechanism
 * RFC 9700    — Section 7: Cookie security requirements for BFF
 * IETF BCP    — __Host- prefix requirements
 *
 * The __Host- prefix enforces four browser-level rules simultaneously:
 *   1. Secure flag (HTTPS only)
 *   2. No Domain attribute (exact origin only)
 *   3. Path=/ (whole origin)
 *   4. Cannot be set by subdomains
 *
 * References:
 *   https://datatracker.ietf.org/doc/html/rfc9700#section-7
 *   https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes
 */

import { describe, it, expect } from 'vitest';
import { buildSessionCookie, clearSessionCookie, parseSessionCookieName } from './cookie.js';

const DEFAULT_COOKIE_NAME = '__Host-session';

describe('cookie name', () => {
  it('uses the __Host- prefix by default', () => {
    // Act
    const header = buildSessionCookie('test-session-id', {});

    // Assert
    expect(header).toContain('__Host-');
  });

  it('default cookie name is __Host-session', () => {
    // Act
    const header = buildSessionCookie('test-session-id', {});

    // Assert
    expect(header).toContain(`${DEFAULT_COOKIE_NAME}=`);
  });

  it('rejects a cookie name without __Host- prefix', () => {
    // Act & Assert
    expect(() =>
      buildSessionCookie('test-session-id', {
        // @ts-expect-error — testing runtime validation for invalid cookie name
        cookieName: 'session',
      }),
    ).toThrow(Error);
  });

  it('rejects __Secure- prefix for same-domain topology', () => {
    // Act & Assert
    expect(() =>
      buildSessionCookie('test-session-id', {
        cookieName: '__Secure-session',
        topology: 'same-domain',
      } as never),
    ).toThrow(/__Secure-/);
  });

  it('accepts __Secure- prefix for subdomain topology', () => {
    // Act & Assert
    expect(() =>
      buildSessionCookie('test-session-id', {
        cookieName: '__Secure-session',
        topology: 'subdomain',
        cookieDomain: 'torii.dev',
      }),
    ).not.toThrow();
  });
});

describe('secure flag', () => {
  it('always includes Secure flag — required by __Host- prefix', () => {
    // Act
    const header = buildSessionCookie('test-session-id', {});

    // Assert
    expect(header).toMatch(/;\s*Secure/i);
  });

  it('secure flag is non-negotiable — cannot be disabled', () => {
    // Act
    // __Host- prefix makes Secure mandatory at the browser level.
    // This test documents that there is no option to disable it.
    const header = buildSessionCookie('test-session-id', {});

    // Assert
    expect(header).toMatch(/;\s*Secure/i);
  });
});

describe('httpOnly flag', () => {
  it('always includes HttpOnly flag — JavaScript cannot read the session cookie', () => {
    // Act
    // RFC 9700: tokens must never be accessible to JavaScript
    // HttpOnly prevents document.cookie access entirely
    const header = buildSessionCookie('test-session-id', {});

    // Assert
    expect(header).toMatch(/;\s*HttpOnly/i);
  });
});

describe('sameSite attribute', () => {
  it('sets SameSite=Strict for same-domain topology (default)', () => {
    // Act
    // same-domain topology: SPA and BFF share the same origin.
    // SameSite=Strict — cookie only sent on same-origin requests.
    const header = buildSessionCookie('test-session-id', {});

    // Assert
    expect(header).toMatch(/;\s*SameSite=Strict/i);
  });

  it('sets SameSite=Lax for subdomain topology', () => {
    // Act
    // subdomain topology: SPA at app.torii.dev, BFF at bff.torii.dev.
    // SameSite=Lax required — cross-subdomain requests are cross-site
    // in the Schemeful Same-Site model. Strict would block the cookie entirely.
    const header = buildSessionCookie('test-session-id', {
      cookieName: '__Secure-session',
      topology: 'subdomain',
      cookieDomain: 'torii.dev',
    });

    // Assert
    expect(header).toMatch(/;\s*SameSite=Lax/i);
  });

  it('sameSite is topology-driven — SameSite=None is never produced', () => {
    // Act
    // The topology drives SameSite automatically — consumers cannot set it
    // directly. This prevents accidental misconfiguration.
    // same-domain always produces Strict; subdomain always produces Lax.
    // SameSite=None is not supported — it weakens the CSRF posture.
    const sameDomain = buildSessionCookie('test-session-id', {});

    // Asset
    expect(sameDomain).not.toContain('SameSite=None');

    // Act
    const subdomain = buildSessionCookie('test-session-id', {
      cookieName: '__Secure-session',
      topology: 'subdomain',
      cookieDomain: 'torii.dev',
    });

    // Assert
    expect(subdomain).not.toContain('SameSite=None');
  });
});

describe('path attribute', () => {
  it('sets Path=/ — required by __Host- prefix', () => {
    // Act
    // __Host- prefix mandates Path=/ — browser rejects the cookie otherwise
    const header = buildSessionCookie('test-session-id', {});

    // Assert
    expect(header).toMatch(/;\s*Path=\//i);
  });

  it('does not allow narrower paths — __Host- requires Path=/', () => {
    // Act & Assert
    // A narrower path like Path=/auth would cause the browser to reject
    // the __Host- cookie entirely
    expect(() =>
      buildSessionCookie('test-session-id', {
        // @ts-expect-error — intentionally passing invalid path
        path: '/auth',
      }),
    ).toThrow(Error);
  });
});

describe('domain attribute', () => {
  it('does not include a Domain attribute — required by __Host- prefix', () => {
    // Act
    // __Host- prefix forbids Domain attribute entirely
    // Domain attribute would allow subdomains to receive the cookie
    const header = buildSessionCookie('test-session-id', {});

    // Assert
    expect(header).not.toMatch(/;\s*Domain=/i);
  });
});

describe('cookie expiry', () => {
  it('sets Max-Age matching the provided TTL in seconds', () => {
    // Act
    const header = buildSessionCookie('test-session-id', {
      maxAge: 900,
    });

    // Assert
    expect(header).toContain('Max-Age=900');
  });

  it('defaults to 900 seconds (15 minutes) — short-lived for security', () => {
    // Act
    const header = buildSessionCookie('test-session-id', {});

    // Assert
    expect(header).toContain('Max-Age=900');
  });

  it('does not set far-future expiry — prevents long-lived session fixation', () => {
    // Act
    const header = buildSessionCookie('test-session-id', {});

    // Should have a Max-Age attribute
    const match = new RegExp(/Max-Age=(\d+)/).exec(header);

    // Assert
    expect(match).toBeDefined();
    expect(match?.[1]).toBeDefined();

    const maxAge = Number.parseInt(match![1]!, 10);

    // 28 hours max — anything longer is a security risk without Redis revocation
    expect(maxAge).toBeLessThanOrEqual(28 * 60 * 60);
  });

  it('throws when maxAge exceeds 28-hour ceiling', () => {
    // Arrange
    const maxAge = 28 * 60 * 60 + 1; // 28 hours + 1 second

    // Act & Assert
    expect(() => buildSessionCookie('test-session-id', { maxAge })).toThrow(/28-hour ceiling/);
  });
});

describe(clearSessionCookie, () => {
  it('sets Max-Age=0 to immediately expire the cookie', () => {
    // Act
    const header = clearSessionCookie();

    // Assert
    expect(header).toContain('Max-Age=0');
  });

  it('sets an empty value', () => {
    // Act
    const header = clearSessionCookie();

    // Assert
    expect(header).toMatch(/__Host-session=;|__Host-session=""/);
  });

  it('retains all security flags on the clear cookie', () => {
    // Act
    // Browser only deletes a cookie if the clear matches the original attributes
    const header = clearSessionCookie();

    // Assert
    expect(header).toMatch(/;\s*Secure/i);
    expect(header).toMatch(/;\s*HttpOnly/i);
    expect(header).toMatch(/;\s*Path=\//i);
    expect(header).not.toMatch(/;\s*Domain=/i);
  });

  it('throws when cookie name is invalid for same-domain topology', () => {
    // Act & Assert
    expect(() => clearSessionCookie('__Secure-session', { topology: 'same-domain' })).toThrow(/Expected prefix: __Host-/);
  });

  it('throws when cookie name is invalid for subdomain topology', () => {
    // Act & Assert
    expect(() =>
      clearSessionCookie('plain-session', {
        topology: 'subdomain',
        cookieDomain: 'example.com',
      }),
    ).toThrow(/Expected prefix: __Secure-/);
  });
});

describe(parseSessionCookieName, () => {
  it('extracts the session ID from a valid __Host- cookie header', () => {
    // Arrange
    const cookieHeader = `${DEFAULT_COOKIE_NAME}=my-session-id-123; OtherCookie=value`;

    // Act
    const sessionId = parseSessionCookieName(cookieHeader, DEFAULT_COOKIE_NAME);

    // Assert
    expect(sessionId).toBe('my-session-id-123');
  });

  it('returns null when the session cookie is not present', () => {
    // Arrange
    const cookieHeader = 'OtherCookie=value; AnotherCookie=value2';

    // Act
    const sessionId = parseSessionCookieName(cookieHeader, DEFAULT_COOKIE_NAME);

    // Assert
    expect(sessionId).toBeNull();
  });

  it('returns null for an empty cookie header', () => {
    // Act
    const sessionId = parseSessionCookieName('', DEFAULT_COOKIE_NAME);

    // Assert
    expect(sessionId).toBeNull();
  });

  it('does not match a cookie with a similar but different name', () => {
    // Arrange - Ensure __Host-session does not match __Host-session-admin etc.
    const cookieHeader = `__Host-session-admin=evil-value`;

    // Act
    const sessionId = parseSessionCookieName(cookieHeader, DEFAULT_COOKIE_NAME);

    // Assert
    expect(sessionId).toBeNull();
  });
});

describe('subdomain topology', () => {
  const subdomainOpts = {
    cookieName: '__Secure-session' as const,
    topology: 'subdomain' as const,
    cookieDomain: 'torii.dev',
  };

  it('uses __Secure- prefix', () => {
    // Act
    const header = buildSessionCookie('sid', subdomainOpts);

    // Assert
    expect(header).toMatch(/^__Secure-session=/);
  });

  it('sets SameSite=Lax — required for cross-subdomain requests', () => {
    // Act
    const header = buildSessionCookie('sid', subdomainOpts);

    // Assert
    expect(header).toContain('SameSite=Lax');
  });

  it('does not set SameSite=Strict for subdomain', () => {
    // Act
    const header = buildSessionCookie('sid', subdomainOpts);

    // Assert
    expect(header).not.toContain('SameSite=Strict');
  });

  it('includes Domain=.torii.dev', () => {
    // Act
    const header = buildSessionCookie('sid', subdomainOpts);

    // Assert
    expect(header).toContain('Domain=.torii.dev');
  });

  it('still sets Secure and HttpOnly', () => {
    // Act
    const header = buildSessionCookie('sid', subdomainOpts);

    // Assert
    expect(header).toMatch(/Secure/);
    expect(header).toMatch(/HttpOnly/);
  });

  it('clearSessionCookie uses SameSite=Lax and Domain for subdomain', () => {
    // Act
    const header = clearSessionCookie('__Secure-session', {
      topology: 'subdomain',
      cookieDomain: 'torii.dev',
    });

    // Assert
    expect(header).toContain('SameSite=Lax');
    expect(header).toContain('Domain=.torii.dev');
    expect(header).toContain('Max-Age=0');
  });
});

describe('same-domain topology', () => {
  it('uses __Host- prefix by default', () => {
    // Act
    const header = buildSessionCookie('sid', {});

    // Assert
    expect(header).toMatch(/^__Host-session=/);
  });

  it('sets SameSite=Strict', () => {
    // Act
    const header = buildSessionCookie('sid', {});

    // Assert
    expect(header).toContain('SameSite=Strict');
  });

  it('does not include Domain attribute', () => {
    // Act
    const header = buildSessionCookie('sid', {});

    // Assert
    expect(header).not.toMatch(/Domain=/i);
  });

  it('clearSessionCookie uses SameSite=Strict for same-domain', () => {
    // Act
    const header = clearSessionCookie();

    // Assert
    expect(header).toContain('SameSite=Strict');
    expect(header).not.toMatch(/Domain=/i);
  });
});
