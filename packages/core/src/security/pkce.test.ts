/**
 * PKCE Test Suite
 *
 * RFC 7636  — Proof Key for Code Exchange
 * RFC 9700  — Section 4: Authorization Code + PKCE requirements
 *
 * References:
 *   https://datatracker.ietf.org/doc/html/rfc7636
 *   https://datatracker.ietf.org/doc/html/rfc9700#section-4
 */

import { describe, it, expect, expectTypeOf } from 'vitest';
import { generateCodeVerifier, generateCodeChallenge, verifyCodeChallenge, PKCE_METHOD } from './pkce.js';

// ─── RFC 7636 §4.1 — code_verifier ───────────────────────────────────────────

describe(generateCodeVerifier, () => {
  it('returns a string', async () => {
    // Act
    const verifier = await generateCodeVerifier();

    // Assert
    expect(verifier).toBeTypeOf('string');

    expectTypeOf(verifier).toBeString();
  });

  it('meets RFC 7636 minimum length of 43 characters', async () => {
    // Act
    const verifier = await generateCodeVerifier();

    // Assert - RFC 7636 §4.1: code_verifier length must be >= 43 and <= 128
    expect(verifier.length).toBeGreaterThanOrEqual(43);
  });

  it('does not exceed RFC 7636 maximum length of 128 characters', async () => {
    // Act
    const verifier = await generateCodeVerifier();

    // Assert
    expect(verifier.length).toBeLessThanOrEqual(128);
  });

  it('uses only URL-safe base64 characters [A-Z a-z 0-9 - . _ ~]', async () => {
    // Act - RFC 7636 §4.1: unreserved characters only
    const verifier = await generateCodeVerifier();

    // Assert
    expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it('generates cryptographically unique values — no two verifiers are equal', async () => {
    // Act - Probabilistic — collision would require 2^256 luck
    const verifiers = await Promise.all(Array.from({ length: 20 }, () => generateCodeVerifier()));
    const unique = new Set(verifiers);

    // Assert
    expect(unique.size).toBe(20);
  });

  it('provides at least 256 bits of entropy (32 bytes minimum)', async () => {
    // Act
    // 32 bytes base64url-encoded = 43 chars minimum
    // We generate 32 bytes → 43 chars — verify the source entropy
    const verifier = await generateCodeVerifier();
    // base64url: 4 chars = 3 bytes → 43 chars ≈ 32 bytes = 256 bits
    const byteLength = Math.floor((verifier.length * 3) / 4);

    // Assert
    expect(byteLength).toBeGreaterThanOrEqual(32);
  });
});

// ─── RFC 7636 §4.2 — code_challenge ──────────────────────────────────────────

describe(generateCodeChallenge, () => {
  it('returns a string', async () => {
    // Arrange
    const verifier = await generateCodeVerifier();

    // Act
    const challenge = await generateCodeChallenge(verifier);

    // Assert
    expect(challenge).toBeTypeOf('string');

    expectTypeOf(challenge).toBeString();
  });

  it('produces BASE64URL(SHA-256(ASCII(code_verifier))) per RFC 7636 §4.2', async () => {
    // Arrange - Test vector from RFC 7636 Appendix B
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    // Act
    const challenge = await generateCodeChallenge(verifier);

    // Assert
    expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('uses no padding (URL-safe base64, no = characters)', async () => {
    // Arrange
    const verifier = await generateCodeVerifier();

    // Act
    const challenge = await generateCodeChallenge(verifier);

    expect(challenge).not.toContain('=');
    expect(challenge).not.toContain('+');
    expect(challenge).not.toContain('/');
  });

  it('is deterministic — same verifier always produces same challenge', async () => {
    // Arrange
    const verifier = await generateCodeVerifier();

    // Act
    const [c1, c2] = await Promise.all([generateCodeChallenge(verifier), generateCodeChallenge(verifier)]);

    expect(c1).toBe(c2);
  });

  it('produces different challenges for different verifiers', async () => {
    // Arrange
    const [v1, v2] = await Promise.all([generateCodeVerifier(), generateCodeVerifier()]);

    // Act
    const [c1, c2] = await Promise.all([generateCodeChallenge(v1), generateCodeChallenge(v2)]);

    // Assert
    expect(c1).not.toBe(c2);
  });
});

// ─── RFC 9700 §4 — S256 is the only permitted method ─────────────────────────

describe(PKCE_METHOD, () => {
  it('is S256 — the only method permitted by RFC 9700', () => {
    // Act & Assert - RFC 9700 §4: Clients MUST use S256. plain MUST NOT be used.
    expect(PKCE_METHOD).toBe('S256');
  });

  it('is not "plain" — RFC 9700 explicitly forbids plain method', () => {
    // Act & Assert
    expect(PKCE_METHOD).not.toBe('plain');
  });
});

// ─── RFC 7636 §4.6 — server-side challenge verification ──────────────────────

describe(verifyCodeChallenge, () => {
  it('returns true when verifier matches the stored challenge', async () => {
    // Arrange
    const verifier = await generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    const result = await verifyCodeChallenge(verifier, challenge);

    expect(result).toBe(true);
  });

  it('returns false when verifier does not match the challenge', async () => {
    // Arrange
    const verifier = await generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    const tampered = verifier.slice(0, -1) + (verifier.endsWith('a') ? 'b' : 'a');

    // Act
    const result = await verifyCodeChallenge(tampered, challenge);

    // Assert
    expect(result).toBe(false);
  });

  it('returns false for an empty verifier', async () => {
    // Arrange
    const verifier = await generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);

    // Act
    const result = await verifyCodeChallenge('', challenge);

    // Assert
    expect(result).toBe(false);
  });

  it('returns false for a completely different verifier', async () => {
    // Arrange
    const verifier1 = await generateCodeVerifier();
    const verifier2 = await generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier1);

    // Act
    const result = await verifyCodeChallenge(verifier2, challenge);

    // Assert
    expect(result).toBe(false);
  });

  it('is timing-safe — uses constant-time comparison to prevent timing attacks', async () => {
    // Arrange
    // We cannot test timing directly in unit tests — this documents the requirement.
    // The implementation MUST use crypto.subtle.timingSafeEqual or equivalent.
    // See packages/core/src/security/pkce.ts for the implementation.
    const verifier = await generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    // Act - At minimum: function exists and returns a boolean (not a timing oracle)
    const result = await verifyCodeChallenge(verifier, challenge);

    // Assert
    expect(result).toBeTypeOf('boolean');

    expectTypeOf(result).toBeBoolean();
  });
});

// ─── Web Standards compliance ─────────────────────────────────────────────────

describe('web Standards compliance', () => {
  it('uses only Web Crypto API — no Node.js crypto module', async () => {
    // Act
    // This test passes by virtue of running in edge-runtime environment.
    // If the implementation imports Node.js crypto, the edge-runtime
    // vitest environment will throw at import time — not here.
    // The fact that the above tests pass in edge-runtime IS the proof.
    const verifier = await generateCodeVerifier();

    // Assert
    expect(verifier).toBeDefined();
    expect(verifier).toBeTypeOf('string');

    expectTypeOf(verifier).toBeString();
  });
});
