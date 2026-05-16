/**
 * Redirect URI validation tests — RFC 9700 §2.1, §4.11.
 *
 * Covers:
 *   - Exact redirect_uri match (origin + path, trailing slash normalized)
 *   - Query/fragment ignored (callback adds code/state)
 *   - Post-logout redirect allowlist (no wildcards, exact match)
 */

import { describe, it, expect } from 'vitest';
import { assertExactRedirectUri, validatePostLogoutRedirectUri } from './redirect.js';

describe('redirect — RFC 9700 §2.1 exact match', () => {
  describe(assertExactRedirectUri, () => {
    it('accepts exact match', () => {
      const requestUrl = new URL('https://example.com/auth/callback');
      const configured = 'https://example.com/auth/callback';

      expect(() => {
        assertExactRedirectUri(requestUrl, configured);
      }).not.toThrow();
    });

    it('accepts match with trailing slash normalization', () => {
      const requestUrl1 = new URL('https://example.com/auth/callback/');
      const configured1 = 'https://example.com/auth/callback';

      expect(() => {
        assertExactRedirectUri(requestUrl1, configured1);
      }).not.toThrow();

      const requestUrl2 = new URL('https://example.com/auth/callback');
      const configured2 = 'https://example.com/auth/callback/';

      expect(() => {
        assertExactRedirectUri(requestUrl2, configured2);
      }).not.toThrow();
    });

    it('accepts extra query string (callback adds code/state/iss)', () => {
      const requestUrl = new URL('https://example.com/auth/callback?code=abc&state=xyz&iss=https://issuer');
      const configured = 'https://example.com/auth/callback';

      expect(() => {
        assertExactRedirectUri(requestUrl, configured);
      }).not.toThrow();
    });

    it('rejects origin mismatch — scheme', () => {
      const requestUrl = new URL('http://example.com/auth/callback');
      const configured = 'https://example.com/auth/callback';

      expect(() => {
        assertExactRedirectUri(requestUrl, configured);
      }).toThrow(/redirect_uri mismatch.*origin/i);
    });

    it('rejects origin mismatch — host', () => {
      const requestUrl = new URL('https://attacker.com/auth/callback');
      const configured = 'https://example.com/auth/callback';

      expect(() => {
        assertExactRedirectUri(requestUrl, configured);
      }).toThrow(/redirect_uri mismatch.*origin/i);
    });

    it('rejects origin mismatch — port', () => {
      const requestUrl = new URL('https://example.com:8080/auth/callback');
      const configured = 'https://example.com/auth/callback';

      expect(() => {
        assertExactRedirectUri(requestUrl, configured);
      }).toThrow(/redirect_uri mismatch.*origin/i);
    });

    it('rejects path mismatch', () => {
      const requestUrl = new URL('https://example.com/auth/other');
      const configured = 'https://example.com/auth/callback';

      expect(() => {
        assertExactRedirectUri(requestUrl, configured);
      }).toThrow(/redirect_uri mismatch.*path/i);
    });

    it('rejects path prefix attack', () => {
      const requestUrl = new URL('https://example.com/auth/callback-evil');
      const configured = 'https://example.com/auth/callback';

      expect(() => {
        assertExactRedirectUri(requestUrl, configured);
      }).toThrow(/redirect_uri mismatch.*path/i);
    });

    it('throws when configured value is invalid URL', () => {
      const requestUrl = new URL('https://example.com/auth/callback');
      const configured = 'not a url';

      expect(() => {
        assertExactRedirectUri(requestUrl, configured);
      }).toThrow(/configured value is not a valid URL/i);
    });
  });

  describe('validatePostLogoutRedirectUri — RFC 9700 §4.11 open-redirect guard', () => {
    const allowlist = ['https://example.com/app', 'https://example.com/admin/', 'https://trusted.org/'];

    it('accepts candidate in allowlist', () => {
      expect(validatePostLogoutRedirectUri('https://example.com/app', allowlist)).toBe('https://example.com/app');
      expect(validatePostLogoutRedirectUri('https://example.com/admin', allowlist)).toBe('https://example.com/admin');
      expect(validatePostLogoutRedirectUri('https://example.com/admin/', allowlist)).toBe('https://example.com/admin/');
      expect(validatePostLogoutRedirectUri('https://trusted.org', allowlist)).toBe('https://trusted.org');
      expect(validatePostLogoutRedirectUri('https://trusted.org/', allowlist)).toBe('https://trusted.org/');
    });

    it('ignores query/fragment when matching', () => {
      expect(validatePostLogoutRedirectUri('https://example.com/app?foo=bar#baz', allowlist)).toBe('https://example.com/app?foo=bar#baz');
    });

    it('rejects candidate not in allowlist', () => {
      expect(() => validatePostLogoutRedirectUri('https://attacker.com/', allowlist)).toThrow(/not in the allowlist/i);
      expect(() => validatePostLogoutRedirectUri('https://example.com/other', allowlist)).toThrow(/not in the allowlist/i);
    });

    it('rejects candidate with origin mismatch', () => {
      expect(() => validatePostLogoutRedirectUri('https://evil.com/app', allowlist)).toThrow(/not in the allowlist/i);
    });

    it('rejects candidate with path prefix attack', () => {
      expect(() => validatePostLogoutRedirectUri('https://example.com/app-evil', allowlist)).toThrow(/not in the allowlist/i);
    });

    it('throws when allowlist is empty', () => {
      expect(() => validatePostLogoutRedirectUri('https://example.com/app', [])).toThrow(/no allowlist configured/i);
    });

    it('throws when candidate is not a valid URL', () => {
      expect(() => validatePostLogoutRedirectUri('not a url', allowlist)).toThrow(/not a valid URL/i);
    });

    it('ignores malformed allowlist entries', () => {
      const allowlistWithInvalid = ['not a url', 'https://valid.com/path'];

      // Assert
      expect(validatePostLogoutRedirectUri('https://valid.com/path', allowlistWithInvalid)).toBe('https://valid.com/path');
      expect(() => validatePostLogoutRedirectUri('https://other.com/', allowlistWithInvalid)).toThrow(/not in the allowlist/i);
    });
  });
});
