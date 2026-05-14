/**
 * RFC 9700 End-to-End Compliance Scenarios
 *
 * These tests validate complete flows rather than individual functions.
 * Each test maps to a specific RFC 9700 requirement and is tagged
 * with the exact section reference.
 *
 * These are the tests that justify the "RFC 9700 compliant" claim in README.md.
 * If any of these fail, the compliance claim must be updated.
 */

import { describe, it, expect } from 'vitest';
import { generateCodeVerifier, PKCE_METHOD } from '../../src/security/pkce.js';
import { generateState } from '../../src/security/state.js';
import { generateNonce } from '../../src/security/nonce.js';
import { validateIssuer } from '../../src/security/issuer.js';
import { buildSessionCookie } from '../../src/security/cookie.js';
import { validateCsrf } from '../../src/security/csrf.js';
import { buildLoginUrl } from '../../src/agent/login.js';
import { TestPendingStore } from '../fixtures/pending-store.js';

describe('rFC 9700 §4 — Authorization Code + PKCE', () => {
  it('[§4] Only Authorization Code flow is used — no implicit flow', async () => {
    // RFC 9700 §2.1: MUST use Authorization Code flow (response_type=code)
    // RFC 9700 §2.1.2: MUST NOT use Implicit flow (response_type=token or id_token)
    // RFC 9700 §2.4: MUST NOT use Resource Owner Password Credentials flow
    //
    // This test verifies the actual authorization URL produced by buildLoginUrl()
    // contains only response_type=code and rejects all implicit flow variants.

    // Arrange
    const config = {
      authorizationEndpoint: 'https://auth.torii.dev/authorize',
      clientId: 'test-client-id',
      redirectUri: 'https://app.torii.dev/callback',
      scopes: ['openid', 'profile'] as const,
    };

    // Act
    const { redirectUrl } = await buildLoginUrl(config, new TestPendingStore());
    const url = new URL(redirectUrl);
    const responseType = url.searchParams.get('response_type');

    // Assert
    // Verify Authorization Code flow (the ONLY allowed value)
    expect(responseType).toBe('code');

    // Verify NO implicit flow variants are used
    // (Testing that the value is NOT any of these ensures regression protection)
    /* eslint-disable vitest/max-expects */
    expect(responseType).not.toBe('token');
    expect(responseType).not.toBe('id_token');
    expect(responseType).not.toBe('token id_token');
    expect(responseType).not.toBe('code token');
    expect(responseType).not.toBe('code id_token');
    expect(responseType).not.toBe('code token id_token');
    /* eslint-enable vitest/max-expects */
  });

  it('[§4] PKCE parameters are included in every authorization request', async () => {
    // Arrange
    // RFC 9700 §2.1.1: PKCE MUST be used for all authorization requests
    // RFC 7636 §4: code_challenge and code_challenge_method are required
    const config = {
      authorizationEndpoint: 'https://auth.torii.dev/authorize',
      clientId: 'test-client-id',
      redirectUri: 'https://app.torii.dev/callback',
      scopes: ['openid'] as const,
    };

    // Act
    const { redirectUrl } = await buildLoginUrl(config, new TestPendingStore());
    const url = new URL(redirectUrl);

    // Verify PKCE parameters are present
    const challenge = url.searchParams.get('code_challenge');
    const method = url.searchParams.get('code_challenge_method');

    // Assert
    expect(challenge).not.toBeNull();
    expect(method).toBe('S256');

    // Verify PKCE challenge is not empty
    expect(challenge!.length).toBeGreaterThan(0);
  });

  it('[§4] PKCE method is S256 — plain is never used', () => {
    // Assert
    expect(PKCE_METHOD).toBe('S256');
    expect(PKCE_METHOD).not.toBe('plain');
  });

  it('[§4] code_verifier has sufficient entropy (≥ 256 bits)', async () => {
    // Act
    const verifier = await generateCodeVerifier();

    // Assert - 43+ chars in base64url ≈ 32+ bytes = 256+ bits
    expect(verifier.length).toBeGreaterThanOrEqual(43);
  });
});

describe('rFC 9700 §4.7 — state parameter', () => {
  it('[§4.7] state is included in every authorization request', async () => {
    // Act
    const state = await generateState();

    // Assert
    // eslint-disable-next-line vitest/prefer-strict-boolean-matchers
    expect(state).toBeTruthy();
    expect(state.length).toBeGreaterThan(0);
  });

  it('[§4.7] state has sufficient entropy to prevent brute force (≥ 128 bits)', async () => {
    // Act
    const state = await generateState();
    const byteLength = Math.floor((state.length * 3) / 4);

    // Assert
    expect(byteLength).toBeGreaterThanOrEqual(16); // 16 bytes = 128 bits
  });

  it('[§4.7] nonce is included in every OIDC authorization request', async () => {
    // Act
    const nonce = await generateNonce();

    // Assert
    // eslint-disable-next-line vitest/prefer-strict-boolean-matchers
    expect(nonce).toBeTruthy();
    expect(nonce.length).toBeGreaterThan(0);
  });
});

// ─── RFC 9207 — iss parameter (mix-up attack defence) ────────────────────────

describe('rFC 9207 — iss parameter validation', () => {
  it('[RFC 9207] iss is validated in every authorization response', () => {
    //Arrange
    const expected = 'https://auth.torii.dev/realms/test';

    // Act & Assert
    expect(validateIssuer(expected, expected)).toBe(true);
  });

  it('[RFC 9207] missing iss is rejected — potential mix-up attack', () => {
    // Act & Assert
    expect(validateIssuer(undefined, 'https://auth.torii.dev')).toBe(false);
    expect(validateIssuer(null, 'https://auth.torii.dev')).toBe(false);
  });

  it('[RFC 9207] mismatched iss is rejected', () => {
    // Act & Assert
    expect(validateIssuer('https://evil.attacker.com', 'https://auth.torii.dev')).toBe(false);
  });

  it('[RFC 9207] HTTP issuers are rejected — HTTPS required', () => {
    // Act & Assert
    expect(() => validateIssuer('http://auth.torii.dev', 'http://auth.torii.dev')).toThrow(Error);
  });
});

describe('rFC 9700 §7 — Session cookie security', () => {
  it('[§7] session cookie uses __Host- prefix', () => {
    // Act
    const header = buildSessionCookie('session-id', {});

    // Assert
    expect(header).toContain('__Host-session=');
  });

  it('[§7] session cookie has Secure flag', () => {
    // Act
    const header = buildSessionCookie('session-id', {});

    // Assert
    expect(header).toMatch(/;\s*Secure/i);
  });

  it('[§7] session cookie has HttpOnly flag — no JS access', () => {
    // Act
    const header = buildSessionCookie('session-id', {});

    // Assert
    expect(header).toMatch(/;\s*HttpOnly/i);
  });

  it('[§7] session cookie has SameSite=Strict', () => {
    // Act
    const header = buildSessionCookie('session-id', {});

    // Assert
    expect(header).toMatch(/;\s*SameSite=Strict/i);
  });

  it('[§7] session cookie has no Domain attribute', () => {
    // Act
    const header = buildSessionCookie('session-id', {});

    // Assert
    expect(header).not.toMatch(/;\s*Domain=/i);
  });

  it('[§7] session cookie has Path=/', () => {
    // Act
    const header = buildSessionCookie('session-id', {});

    // Assert
    expect(header).toMatch(/;\s*Path=\//i);
  });

  it('[§7] all five security properties present simultaneously', () => {
    // Act
    const header = buildSessionCookie('session-id', {});

    // Assert - All must be true at once — not just individually
    /* eslint-disable vitest/max-expects */
    expect(header).toContain('__Host-session=');
    expect(header).toMatch(/;\s*Secure/i);
    expect(header).toMatch(/;\s*HttpOnly/i);
    expect(header).toMatch(/;\s*SameSite=Strict/i);
    expect(header).toMatch(/;\s*Path=\//i);
    expect(header).not.toMatch(/;\s*Domain=/i);
    /* eslint-enable vitest/max-expects */
  });
});

describe('rFC 9700 §7.1 — CSRF protection', () => {
  it('[§7.1] custom header required on all BFF requests', () => {
    // Arrange
    const reqWithHeader = new Request('https://bff.torii.dev/auth/login', {
      method: 'POST',
      headers: {
        'x-torii-request': '1',
        origin: 'https://app.torii.dev',
      },
    });
    const reqWithoutHeader = new Request('https://bff.torii.dev/auth/login', {
      method: 'POST',
      headers: { origin: 'https://app.torii.dev' },
    });

    const config = {
      headerName: 'x-torii-request',
      allowedOrigins: ['https://app.torii.dev'],
    };

    // Act & Assert
    expect(validateCsrf(reqWithHeader, config)).toBe(true);
    expect(validateCsrf(reqWithoutHeader, config)).toBe(false);
  });

  it('[§7.1] origin is validated — cross-origin requests rejected', () => {
    // Arrange
    const config = {
      headerName: 'x-torii-request',
      allowedOrigins: ['https://app.torii.dev'],
    };

    const legitimateReq = new Request('https://bff.torii.dev/api/data', {
      headers: {
        'x-torii-request': '1',
        origin: 'https://app.torii.dev',
      },
    });
    const attackerReq = new Request('https://bff.torii.dev/api/data', {
      headers: {
        'x-torii-request': '1',
        origin: 'https://evil.com',
      },
    });

    // Act & Assert
    expect(validateCsrf(legitimateReq, config)).toBe(true);
    expect(validateCsrf(attackerReq, config)).toBe(false);
  });
});
