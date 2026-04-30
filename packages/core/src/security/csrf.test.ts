/**
 * CSRF Protection Test Suite
 *
 * RFC 9700  — Section 7.1: CSRF protection for BFF endpoints
 * OWASP     — Cross-Site Request Forgery Prevention Cheat Sheet
 *
 * Torii uses the custom request header pattern:
 *   - All BFF endpoints require a custom header (e.g. X-Torii-Request: 1)
 *   - Custom headers trigger CORS preflight on cross-origin requests
 *   - Preflight is blocked by CORS policy → CSRF impossible from other origins
 *   - No CSRF token needed — the header IS the proof of same-origin intent
 *
 * References:
 *   https://datatracker.ietf.org/doc/html/rfc9700#section-7.1
 *   https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
 */

import { describe, it, expect } from 'vitest';
import { validateCsrf, type CsrfConfig } from '../../src/security/csrf';

const DEFAULT_CONFIG: CsrfConfig = {
  headerName: 'x-torii-request',
  allowedOrigins: ['https://app.torii.dev'],
};

// ─── Custom header validation ─────────────────────────────────────────────────

describe('validateCsrf — custom header requirement', () => {
  it('returns true when the required custom header is present', () => {
    // Arrange
    const req = new Request('https://bff.torii.dev/auth/login', {
      method: 'POST',
      headers: {
        'x-torii-request': '1',
        origin: 'https://app.torii.dev',
      },
    });

    // Act & Assert
    expect(validateCsrf(req, DEFAULT_CONFIG)).toBe(true);
  });

  it('returns false when the custom header is missing', () => {
    // Arrange
    // A cross-site form POST cannot set custom headers — this is the protection
    const req = new Request('https://bff.torii.dev/auth/login', {
      method: 'POST',
      headers: {
        origin: 'https://app.torii.dev',
      },
    });

    // Act & Assert
    expect(validateCsrf(req, DEFAULT_CONFIG)).toBe(false);
  });

  it('is case-insensitive for the header name', () => {
    // Arrange
    const req = new Request('https://bff.torii.dev/auth/login', {
      method: 'POST',
      headers: {
        'X-Torii-Request': '1', // capitalized
        origin: 'https://app.torii.dev',
      },
    });

    expect(validateCsrf(req, DEFAULT_CONFIG)).toBe(true);
  });

  it('accepts any non-empty header value — value does not matter', () => {
    // Arrange
    // The presence of the header is the signal — not its value
    const req = new Request('https://bff.torii.dev/auth/login', {
      method: 'POST',
      headers: {
        'x-torii-request': 'true',
        origin: 'https://app.torii.dev',
      },
    });

    // Act & Assert
    expect(validateCsrf(req, DEFAULT_CONFIG)).toBe(true);
  });
});

describe('validateCsrf — Origin header validation', () => {
  it('returns true when Origin matches an allowed origin', () => {
    // Arrange
    const req = new Request('https://bff.torii.dev/api/data', {
      headers: {
        'x-torii-request': '1',
        origin: 'https://app.torii.dev',
      },
    });

    // Act & Assert
    expect(validateCsrf(req, DEFAULT_CONFIG)).toBe(true);
  });

  it('returns false when Origin does not match any allowed origin', () => {
    // Arrange
    const req = new Request('https://bff.torii.dev/api/data', {
      headers: {
        'x-torii-request': '1',
        origin: 'https://evil.attacker.com',
      },
    });

    // Act & Assert
    expect(validateCsrf(req, DEFAULT_CONFIG)).toBe(false);
  });

  it('returns false for a subdomain of an allowed origin — no wildcard matching', () => {
    // Arrange
    // https://sub.app.torii.dev must NOT match https://app.torii.dev
    const req = new Request('https://bff.torii.dev/api/data', {
      headers: {
        'x-torii-request': '1',
        origin: 'https://sub.app.torii.dev',
      },
    });

    // Act & Assert
    expect(validateCsrf(req, DEFAULT_CONFIG)).toBe(false);
  });

  it('returns false when Origin header is missing on a cross-origin request', () => {
    // Arrange
    const req = new Request('https://bff.torii.dev/api/data', {
      headers: {
        'x-torii-request': '1',
        // No Origin header
      },
    });

    // Act & Assert
    expect(validateCsrf(req, DEFAULT_CONFIG)).toBe(false);
  });

  it('handles multiple allowed origins correctly', () => {
    // Arrange
    const config: CsrfConfig = {
      headerName: 'x-torii-request',
      allowedOrigins: ['https://app.torii.dev', 'https://admin.torii.dev'],
    };

    const req1 = new Request('https://bff.torii.dev/api/data', {
      headers: { 'x-torii-request': '1', origin: 'https://app.torii.dev' },
    });
    const req2 = new Request('https://bff.torii.dev/api/data', {
      headers: { 'x-torii-request': '1', origin: 'https://admin.torii.dev' },
    });
    const req3 = new Request('https://bff.torii.dev/api/data', {
      headers: { 'x-torii-request': '1', origin: 'https://other.torii.dev' },
    });

    // Act & Assert
    expect(validateCsrf(req1, config)).toBe(true);
    expect(validateCsrf(req2, config)).toBe(true);
    expect(validateCsrf(req3, config)).toBe(false);
  });

  it('rejects wildcard allowed origins — must be explicit', () => {
    // Arrange
    const config: CsrfConfig = {
      headerName: 'x-torii-request',
      allowedOrigins: ['*'],
    };
    const req = new Request('https://bff.torii.dev/api/data', {
      headers: { 'x-torii-request': '1', origin: 'https://anything.com' },
    });

    // Act & Assert
    expect(() => {
      validateCsrf(req, config);
    }).toThrow(Error);
  });
});

describe('validateCsrf — both header AND origin required', () => {
  it('returns false when header present but Origin invalid', () => {
    // Arrange
    const req = new Request('https://bff.torii.dev/api/data', {
      headers: {
        'x-torii-request': '1',
        origin: 'https://evil.com', // ← invalid origin
      },
    });

    // Act & Assert
    expect(validateCsrf(req, DEFAULT_CONFIG)).toBe(false);
  });

  it('returns false when Origin valid but custom header missing', () => {
    // Arrange
    const req = new Request('https://bff.torii.dev/api/data', {
      headers: {
        origin: 'https://app.torii.dev', // ← valid origin
        // ← missing custom header
      },
    });

    // Act & Assert
    expect(validateCsrf(req, DEFAULT_CONFIG)).toBe(false);
  });
});
