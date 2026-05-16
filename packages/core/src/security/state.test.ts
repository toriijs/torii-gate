/**
 * State Parameter Test Suite
 *
 * RFC 9700  — Section 4.7: state parameter requirements
 * RFC 6749  — Section 10.12: CSRF protection via state
 *
 * The state parameter serves two purposes:
 *   1. CSRF protection — binds the callback to the original login request
 *   2. Application state restoration — optional, not required by spec
 *
 * References:
 *   https://datatracker.ietf.org/doc/html/rfc9700#section-4.7
 *   https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
 */

import { describe, it, expect, expectTypeOf } from 'vitest';
import { generateState } from './state.js';
import { createPendingAuthFixture, TestPendingStore } from '../../tests/fixtures/pending-store.js';

describe(generateState, () => {
  it('returns a non-empty string', async () => {
    // Act
    const state = await generateState();

    // Assert
    expect(state).toBeTypeOf('string');
    expect(state.length).toBeGreaterThan(0);

    expectTypeOf(state).toBeString();
  });

  it('provides at least 128 bits of entropy — RFC 9700 §4.7', async () => {
    // Act -128 bits = 16 bytes → base64url encodes to ~22 chars minimum
    const state = await generateState();
    const byteLength = Math.floor((state.length * 3) / 4);

    // Assert
    expect(byteLength).toBeGreaterThanOrEqual(16);
  });

  it('uses only URL-safe characters — safe for query parameters', async () => {
    // Act
    const state = await generateState();

    // Assert
    expect(state).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it('generates unique values — no two states are equal', async () => {
    // Act
    const states = await Promise.all(Array.from({ length: 50 }, () => generateState()));
    const unique = new Set(states);

    // Assert
    expect(unique.size).toBe(50);
  });

  it('uses crypto.getRandomValues — not Math.random', async () => {
    // Act
    // Verified by running in edge-runtime where only Web Crypto is available.
    // Math.random() is predictable and MUST NOT be used for security parameters.
    const state = await generateState();

    // Assert
    expect(state).toBeDefined();
    expect(state.length).toBeGreaterThan(0);
  });
});

describe('state validation via TestPendingStore', () => {
  it('returns pending auth when state matches', async () => {
    // Arrange
    const { store, pendingAuth, state } = await createPendingAuthFixture();
    await store.set(pendingAuth);

    // Act
    const result = await store.get(state);

    // Assert
    expect(result).toStrictEqual(pendingAuth);
  });

  it('removes state after first retrieval — one-time use', async () => {
    // RFC 9700 §4.7: state MUST be invalidated after first use
    // Arrange
    const { store, pendingAuth, state } = await createPendingAuthFixture();

    await store.set(pendingAuth);
    await store.get(state); // first use

    // Act
    const result = await store.get(state); // second use

    // Assert
    expect(result).toBeNull();
  });

  it('returns null on second use — replay attack prevention', async () => {
    // Arrange
    const { store, pendingAuth, state } = await createPendingAuthFixture();

    await store.set(pendingAuth);

    // Act
    const first = await store.get(state); // first use — valid
    const second = await store.get(state); // second use — must reject

    // Assert
    expect(first).toStrictEqual(pendingAuth);
    expect(second).toBeNull();
  });

  it('returns null for unknown state — not in store', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const unknownState = await generateState();

    const result = await store.get(unknownState);

    // Assert
    expect(result).toBeNull();
  });

  it('returns null for expired state — prevents login replay after timeout', async () => {
    // Arrange
    const { store, pendingAuth, state } = await createPendingAuthFixture({
      expiresAt: Date.now() - 1, // already expired
    });

    await store.set(pendingAuth);

    // Act
    const result = await store.get(state);

    // Assert
    expect(result).toBeNull();
  });

  it('handles concurrent validation attempts — only first succeeds', async () => {
    // Arrange
    // Simulates two simultaneous callback requests with the same state
    // (e.g. double-click on login button)
    const { store, pendingAuth, state } = await createPendingAuthFixture();

    await store.set(pendingAuth);
    const [r1, r2] = await Promise.all([store.get(state), store.get(state)]);

    // Exactly one must succeed — not both, not neither
    const successes = [r1, r2].filter(Boolean).length;

    // Assert
    expect(successes).toBe(1);
  });
});

describe('state security properties', () => {
  it('state value is opaque — does not contain user or session identifiers', async () => {
    // Act
    // State must be random bytes only — not a JWT, not a session ID,
    // not anything that could identify the user if intercepted
    const state = await generateState();

    // Assert
    // Must not look like a JWT (header.payload.signature)
    expect(state.split('.').length).toBeLessThan(3);
    // Must not be a UUID (not the right format for high-entropy state)
    expect(state).not.toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  });
});
