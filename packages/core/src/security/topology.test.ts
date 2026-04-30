/**
 * Topology Utilities Test Suite
 */

import { describe, it, expect } from 'vitest';
import {
  getCookiePrefix,
  getCookieSameSite,
  buildDomainAttribute,
  deriveCookieName,
  isCookieNameValid,
  validateTopologyConfig,
} from '../../src/security/topology';

describe(getCookiePrefix, () => {
  it('returns __Host- for same-domain', () => {
    // Act & Assert
    expect(getCookiePrefix('same-domain')).toBe('__Host-');
  });

  it('returns __Secure- for subdomain', () => {
    // Act & Assert
    expect(getCookiePrefix('subdomain')).toBe('__Secure-');
  });
});

describe(getCookieSameSite, () => {
  it('returns Strict for same-domain', () => {
    // Act & Assert
    expect(getCookieSameSite('same-domain')).toBe('Strict');
  });

  it('returns Lax for subdomain', () => {
    // Act & Assert
    expect(getCookieSameSite('subdomain')).toBe('Lax');
  });
});

describe(buildDomainAttribute, () => {
  it('returns empty string for same-domain', () => {
    // Act & Assert
    expect(buildDomainAttribute({ topology: 'same-domain' })).toBe('');
  });

  it('returns Domain=.example.com for subdomain', () => {
    // Act & Assert
    expect(
      buildDomainAttribute({
        topology: 'subdomain',
        cookieDomain: 'example.com',
      }),
    ).toBe('Domain=.example.com');
  });

  it('normalises a leading dot in cookieDomain', () => {
    // Act & Assert
    expect(
      buildDomainAttribute({
        topology: 'subdomain',
        cookieDomain: '.example.com',
      }),
    ).toBe('Domain=.example.com');
  });

  it('normalises a scheme in cookieDomain', () => {
    // Act & Assert
    expect(
      buildDomainAttribute({
        topology: 'subdomain',
        cookieDomain: 'https://example.com',
      }),
    ).toBe('Domain=.example.com');
  });

  it('throws when subdomain topology is used without cookieDomain', () => {
    // Act & Assert
    expect(() => buildDomainAttribute({ topology: 'subdomain' })).toThrow(/cookieDomain/);
  });
});

describe(isCookieNameValid, () => {
  it('accepts __Host- for same-domain', () => {
    // Act & Assert
    expect(isCookieNameValid('__Host-session', 'same-domain')).toBe(true);
  });

  it('rejects __Secure- for same-domain', () => {
    // Act & Assert
    expect(isCookieNameValid('__Secure-session', 'same-domain')).toBe(false);
  });

  it('rejects plain name for same-domain', () => {
    // Act & Assert
    expect(isCookieNameValid('session', 'same-domain')).toBe(false);
  });

  it('accepts __Secure- for subdomain', () => {
    // Act & Assert
    expect(isCookieNameValid('__Secure-session', 'subdomain')).toBe(true);
  });

  it('also accepts __Host- for subdomain (valid prefix, though Domain incompatible)', () => {
    // Act & Assert
    expect(isCookieNameValid('__Host-session', 'subdomain')).toBe(true);
  });

  it('rejects plain name for subdomain', () => {
    // Act & Assert
    expect(isCookieNameValid('session', 'subdomain')).toBe(false);
  });
});

describe(deriveCookieName, () => {
  it('keeps __Host- name unchanged for same-domain', () => {
    // Act & Assert
    expect(deriveCookieName('__Host-session', 'same-domain')).toBe('__Host-session');
  });

  it('replaces __Host- with __Secure- for subdomain', () => {
    // Act & Assert
    expect(deriveCookieName('__Host-session', 'subdomain')).toBe('__Secure-session');
  });

  it('replaces __Secure- with __Host- for same-domain', () => {
    // Act & Assert
    expect(deriveCookieName('__Secure-session', 'same-domain')).toBe('__Host-session');
  });

  it('keeps __Secure- unchanged for subdomain', () => {
    // Act & Assert
    expect(deriveCookieName('__Secure-session', 'subdomain')).toBe('__Secure-session');
  });

  it('adds correct prefix to a plain name', () => {
    // Act & Assert
    expect(deriveCookieName('session', 'same-domain')).toBe('__Host-session');
    expect(deriveCookieName('session', 'subdomain')).toBe('__Secure-session');
  });
});

describe('validateTopologyConfig — same-domain', () => {
  it('passes with minimal valid same-domain config', () => {
    // Act
    const errors = validateTopologyConfig('same-domain', undefined, [], '__Host-session');

    // Assert
    expect(errors).toHaveLength(0);
  });

  it('passes with allowedOrigins set (harmless for same-domain)', () => {
    // Act
    const errors = validateTopologyConfig('same-domain', undefined, ['https://app.example.com'], '__Host-session');

    // Assert
    expect(errors).toHaveLength(0);
  });

  it('errors when cookieDomain is set for same-domain', () => {
    // Act
    const errors = validateTopologyConfig('same-domain', 'example.com', [], '__Host-session');

    // Assert
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]?.field).toBe('security.cookieDomain');
  });

  it('errors when cookieName uses __Secure- for same-domain', () => {
    // Act
    const errors = validateTopologyConfig('same-domain', undefined, [], '__Secure-session');

    // Assert
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]?.field).toBe('security.cookieName');
  });
});

describe('validateTopologyConfig — subdomain', () => {
  it('passes with valid subdomain config', () => {
    // Act
    const errors = validateTopologyConfig('subdomain', 'example.com', ['https://app.example.com'], '__Secure-session');

    // Assert
    expect(errors).toHaveLength(0);
  });

  it('errors when cookieDomain is missing for subdomain', () => {
    // Act
    const errors = validateTopologyConfig('subdomain', undefined, ['https://app.example.com'], '__Secure-session');
    const fieldNames = errors.map((e) => e.field);

    // Assert
    expect(fieldNames).toContain('security.cookieDomain');
  });

  it('errors when allowedOrigins is empty for subdomain', () => {
    // Act
    const errors = validateTopologyConfig('subdomain', 'example.com', [], '__Secure-session');
    const fieldNames = errors.map((e) => e.field);

    // Assert
    expect(fieldNames).toContain('security.allowedOrigins');
  });

  it('errors when cookieName uses __Host- for subdomain', () => {
    // Act
    const errors = validateTopologyConfig('subdomain', 'example.com', ['https://app.example.com'], '__Host-session');
    const fieldNames = errors.map((e) => e.field);

    // Assert
    expect(fieldNames).toContain('security.cookieName');
  });

  it('reports all errors at once — not fail-fast', () => {
    // Act
    // Missing cookieDomain + empty origins + wrong cookie name
    const errors = validateTopologyConfig('subdomain', undefined, [], '__Host-session');

    // Assert
    expect(errors).toHaveLength(3);
  });
});
