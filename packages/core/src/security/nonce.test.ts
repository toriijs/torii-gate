/**
 * Nonce Test Suite
 *
 * OpenID Connect Core 1.0 — Section 3.1.2.1, 3.1.3.7
 * RFC 9700  — Section 4.7: replay attack prevention
 *
 * The nonce binds the ID token to a specific authorization request,
 * preventing ID token replay attacks across sessions.
 *
 * References:
 *   https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 *   https://datatracker.ietf.org/doc/html/rfc9700#section-4.7
 */

import { describe, it, expect, expectTypeOf } from 'vitest';
import { generateNonce, hashNonce } from './nonce.js';
import { generateState } from './state.js';
import { createPendingAuthFixture } from '../../tests/fixtures/pending-store.js';

describe(generateNonce, () => {
  it('returns a non-empty string', async () => {
    // Act
    const nonce = await generateNonce();

    // Assert
    expect(nonce.length).toBeGreaterThan(0);
    expect(nonce).toBeTypeOf('string');

    expectTypeOf(nonce).toBeString();
  });

  it('provides at least 128 bits of entropy', async () => {
    // Act
    const nonce = await generateNonce();
    const byteLength = Math.floor((nonce.length * 3) / 4);

    // Assert
    expect(byteLength).toBeGreaterThanOrEqual(16);
  });

  it('generates unique values — no two nonces are equal', async () => {
    // Act
    const nonces = await Promise.all(Array.from({ length: 50 }, () => generateNonce()));
    const unique = new Set(nonces);

    // Assert
    expect(unique.size).toBe(50);
  });

  it('uses only URL-safe characters', async () => {
    // Act
    const nonce = await generateNonce();

    // Assert
    expect(nonce).toMatch(/^[A-Za-z0-9\-_]+$/);
  });
});

describe(hashNonce, () => {
  it('returns a string', async () => {
    // Act
    const nonce = await generateNonce();
    const hash = await hashNonce(nonce);

    // Assert
    expect(hash).toBeTypeOf('string');

    expectTypeOf(hash).toBeString();
  });

  it('is deterministic — same nonce always produces same hash', async () => {
    // Act
    const nonce = await generateNonce();
    const [h1, h2] = await Promise.all([hashNonce(nonce), hashNonce(nonce)]);

    // Assert
    expect(h1).toBe(h2);
  });

  it('produces different hashes for different nonces', async () => {
    // Act
    const [n1, n2] = await Promise.all([generateNonce(), generateNonce()]);
    const [h1, h2] = await Promise.all([hashNonce(n1), hashNonce(n2)]);

    // Assert
    expect(h1).not.toBe(h2);
  });

  it('hash cannot be reversed to original nonce — one-way function', async () => {
    // Act
    // This is a property of SHA-256 — documented here as a requirement,
    // not a runtime assertion. The implementation must use SHA-256.
    const nonce = await generateNonce();
    const hash = await hashNonce(nonce);

    // Assert - Hash must not equal the original nonce
    expect(hash).not.toBe(nonce);
  });
});

describe('nonce validation via TestPendingStore', () => {
  it('returns pending auth with correct nonce', async () => {
    // Arrange
    const { store, pendingAuth, state, nonce } = await createPendingAuthFixture();

    await store.set(pendingAuth);

    // Act
    const result = await store.get(state);

    // Assert
    expect(result?.nonce).toBe(nonce);
  });

  it('nonce is removed after first retrieval — single use', async () => {
    // Arrange - OpenID Connect Core: nonce MUST be used only once
    const { store, pendingAuth, state } = await createPendingAuthFixture();

    await store.set(pendingAuth);

    // Act
    await store.get(state); // first use — removes from store
    const result = await store.get(state); // second use

    expect(result).toBeNull();
  });

  it('returns null on second use — ID token replay attack prevention', async () => {
    // Arrange
    const { store, pendingAuth, state } = await createPendingAuthFixture();

    await store.set(pendingAuth);

    // Act
    const first = await store.get(state); // first — valid
    const second = await store.get(state); // replay — rejected

    // Assert
    expect(first).toStrictEqual(pendingAuth);
    expect(second).toBeNull();
  });

  it('returns null for unknown nonce — forged or unknown', async () => {
    // Arrange
    const { store } = await createPendingAuthFixture();

    // Act
    const unknownState = await generateState();
    const result = await store.get(unknownState);

    // Assert
    expect(result).toBeNull();
  });

  it('returns null for expired nonce', async () => {
    // Arrange
    const { store, pendingAuth, state } = await createPendingAuthFixture({
      expiresAt: Date.now() - 1, // already expired
    });

    await store.set(pendingAuth);
    const result = await store.get(state);

    // Assert
    expect(result).toBeNull();
  });
});
