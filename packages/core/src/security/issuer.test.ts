/**
 * Mix-Up Attack Defence Test Suite
 *
 * RFC 9207  — OAuth 2.0 Authorization Server Issuer Identification
 * RFC 9700  — Section 4.4: Mix-up attack prevention
 *
 * A mix-up attack tricks a client into sending an authorization code
 * intended for one authorization server to a different (attacker-controlled)
 * server. The `iss` parameter in the authorization response binds the
 * response to the specific authorization server that issued it.
 *
 * Attack scenario:
 *   1. Attacker controls AS-Evil and AS-Legitimate
 *   2. Client initiates flow with AS-Legitimate
 *   3. Attacker redirects the callback to point at AS-Evil's token endpoint
 *   4. Client sends code to AS-Evil → token endpoint → code theft
 *
 * Defence: validate `iss` in the authorization response before token exchange.
 *
 * References:
 *   https://datatracker.ietf.org/doc/html/rfc9207
 *   https://datatracker.ietf.org/doc/html/rfc9700#section-4.4
 */

import { describe, it, expect } from 'vitest';
import { validateIssuer } from './issuer.js';

const EXPECTED_ISSUER = 'https://auth.torri.dev/realms/myrealm';

// ─── iss parameter validation ─────────────────────────────────────────────────

describe('validateIssuer — RFC 9207 mix-up attack defence', () => {
  it('returns true when iss matches the expected issuer exactly', () => {
    // Act
    const result = validateIssuer(EXPECTED_ISSUER, EXPECTED_ISSUER);

    // Assert
    expect(result).toBe(true);
  });

  it('returns false when iss does not match the expected issuer', () => {
    // Act
    const result = validateIssuer('https://evil.attacker.com/realms/myrealm', EXPECTED_ISSUER);

    // Assert
    expect(result).toBe(false);
  });

  it('returns false when iss is missing from the authorization response', () => {
    // Act
    // RFC 9207: if server advertises iss support, client MUST validate
    // Missing iss is treated as a potential attack
    const result = validateIssuer(undefined, EXPECTED_ISSUER);

    // Assert
    expect(result).toBe(false);
  });

  it('returns false when iss is an empty string', () => {
    // Act
    const result = validateIssuer('', EXPECTED_ISSUER);

    expect(result).toBe(false);
  });

  it('returns false when iss is null', () => {
    // Act
    const result = validateIssuer(null, EXPECTED_ISSUER);

    expect(result).toBe(false);
  });

  it('performs exact string matching — no prefix/suffix tricks', () => {
    // Act & Assert
    // Attacker: https://auth.torri.dev/realms/myrealm.evil.com
    expect(validateIssuer(`${EXPECTED_ISSUER}.evil.com`, EXPECTED_ISSUER)).toBe(false);
  });

  it('is case-sensitive — uppercase issuer does not match', () => {
    // Act & Assert
    expect(validateIssuer(EXPECTED_ISSUER.toUpperCase(), EXPECTED_ISSUER)).toBe(false);
  });

  it('treats trailing slash as a different issuer — exact match required', () => {
    // Arrange - https://auth.torri.dev vs https://auth.torri.dev/ are different
    const withTrailingSlash = EXPECTED_ISSUER + '/';

    // Act
    const result = validateIssuer(withTrailingSlash, EXPECTED_ISSUER);

    // Assert
    expect(result).toBe(false);
  });

  it('rejects HTTP iss in the authorization response — HTTPS required', () => {
    // Arrange
    // Attack scenario: config is correctly HTTPS, but the authorization
    // response iss parameter comes back as HTTP (downgrade attempt).
    // The HTTPS expectedIssuer is correct — only the received iss is HTTP.
    const httpIss = EXPECTED_ISSUER.replace('https://', 'http://');

    // Act & Assert
    expect(validateIssuer(httpIss, EXPECTED_ISSUER)).toBe(false);
  });

  it('throws when expectedIssuer itself is HTTP — configuration error', () => {
    // Arrange - This is a misconfiguration, not an attack — fail loudly at startup
    const httpExpected = EXPECTED_ISSUER.replace('https://', 'http://');

    // Act & Assert
    expect(() => validateIssuer(EXPECTED_ISSUER, httpExpected)).toThrow(Error);
  });
});

describe('validateIssuer — authorization response parameter', () => {
  it('extracts and validates iss from URLSearchParams', () => {
    // Arrange - Real authorization response callback URL
    const callbackUrl = new URL(`https://app.torii.dev/auth/callback?code=abc123&state=xyz&iss=${encodeURIComponent(EXPECTED_ISSUER)}`);
    const iss = callbackUrl.searchParams.get('iss');

    // Act
    const result = validateIssuer(iss, EXPECTED_ISSUER);

    // Assert
    expect(result).toBe(true);
  });

  it('fails when iss is absent from callback URL params', () => {
    // Arrange
    const callbackUrl = new URL(
      'https://app.torii.dev/auth/callback?code=abc123&state=xyz',
      // No iss parameter
    );
    const iss = callbackUrl.searchParams.get('iss');

    // Act
    const result = validateIssuer(iss, EXPECTED_ISSUER);

    // Assert
    expect(result).toBe(false);
  });

  it('fails when iss in callback is a different valid HTTPS URL', () => {
    // Arrange
    // Both are valid HTTPS URLs but they are different issuers
    const callbackUrl = new URL(
      `https://app.torii.dev/auth/callback?code=abc123&state=xyz&iss=${encodeURIComponent('https://different-auth.torri.dev/realms/other')}`,
    );
    const iss = callbackUrl.searchParams.get('iss');

    // Act
    const result = validateIssuer(iss, EXPECTED_ISSUER);

    // Assert
    expect(result).toBe(false);
  });
});
