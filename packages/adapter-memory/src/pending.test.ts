/**
 * Memory Pending Store Test Suite
 *
 * Runs the full PendingAuthStore contract suite from @torii-gate/test-contracts
 * plus memory-specific behavior (in-memory state, no cookies).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryPendingStore } from './pending';
import { runPendingStoreContractTests, VALID_PENDING_AUTH, EXPIRED_PENDING_AUTH } from '@torii-gate/test-contracts';

// ─── Contract tests — every pending store must pass these ────────────────────

// eslint-disable-next-line vitest/require-hook -- runPendingStoreContractTests is a test suite generator, not setup
runPendingStoreContractTests(() => new MemoryPendingStore(), { type: 'server-side' });

describe('memoryPendingStore — headers', () => {
  let store: MemoryPendingStore;

  beforeEach(() => {
    store = new MemoryPendingStore();
  });

  it('set() returns empty headers object (stateless)', async () => {
    // Arrange
    const headers = await store.set(VALID_PENDING_AUTH);

    // Assert
    expect(headers).toStrictEqual({});
  });

  it('clear() returns empty headers object', () => {
    // Act
    const headers = store.clear();

    // Assert
    expect(headers).toStrictEqual({});
  });
});

// ─── Memory-specific: request parameter not used ──────────────────────────────

describe('memoryPendingStore — request handling', () => {
  let store: MemoryPendingStore;

  beforeEach(() => {
    store = new MemoryPendingStore();
  });

  it('get() works without request parameter', async () => {
    // Arrange
    await store.set(VALID_PENDING_AUTH);

    // Act
    const result = await store.get(VALID_PENDING_AUTH.state);

    // Assert
    expect(result).toStrictEqual(VALID_PENDING_AUTH);
  });

  it('get() ignores request parameter if provided', async () => {
    // Arrange
    await store.set(VALID_PENDING_AUTH);
    const request = new Request('https://example.com');

    // Act
    const result = await store.get(VALID_PENDING_AUTH.state, request);

    // Assert
    expect(result).toStrictEqual(VALID_PENDING_AUTH);
  });
});

describe('memoryPendingStore — TTL enforcement', () => {
  let store: MemoryPendingStore;

  beforeEach(() => {
    store = new MemoryPendingStore();
  });

  it('expired entries are removed from store on get()', async () => {
    // Arrange
    await store.set(EXPIRED_PENDING_AUTH);

    // Act
    const result = await store.get(EXPIRED_PENDING_AUTH.state);

    // Assert
    expect(result).toBeNull();

    // Second get should also return null (entry was deleted)
    const second = await store.get(EXPIRED_PENDING_AUTH.state);

    expect(second).toBeNull();
  });

  it('cleans up expired entry even if TTL check is after deletion', async () => {
    // Arrange
    const almostExpired = {
      ...VALID_PENDING_AUTH,
      state: 'almost-expired-state',
      expiresAt: Date.now() + 50, // 50ms TTL
    };
    await store.set(almostExpired);

    // Act - Wait for expiry
    await new Promise((resolve) => setTimeout(resolve, 100));
    const result = await store.get(almostExpired.state);

    // Assert
    expect(result).toBeNull();
  });
});

describe('memoryPendingStore — in-memory state', () => {
  let store: MemoryPendingStore;

  beforeEach(() => {
    store = new MemoryPendingStore();
  });

  it('state persists between multiple sets', async () => {
    // Arrange
    const entry1 = { ...VALID_PENDING_AUTH, state: 'state-1' };
    const entry2 = { ...VALID_PENDING_AUTH, state: 'state-2' };

    // Act
    await store.set(entry1);
    await store.set(entry2);

    // Assert - Both should be retrievable
    const result1 = await store.get('state-1');
    const result2 = await store.get('state-2');

    expect(result1).toStrictEqual(entry1);
    expect(result2).toStrictEqual(entry2);
  });

  it('overwriting same state replaces the entry', async () => {
    // Arrange
    const entry1 = { ...VALID_PENDING_AUTH, codeVerifier: 'verifier-1' };
    const entry2 = { ...VALID_PENDING_AUTH, codeVerifier: 'verifier-2' };

    // Act
    await store.set(entry1);
    await store.set(entry2); // Same state, different verifier
    const result = await store.get(VALID_PENDING_AUTH.state);

    // Assert
    expect(result?.codeVerifier).toBe('verifier-2');
  });

  it('isolated instances do not share state', async () => {
    // Arrange
    const store1 = new MemoryPendingStore();
    const store2 = new MemoryPendingStore();

    // Act
    await store1.set(VALID_PENDING_AUTH);
    const result = await store2.get(VALID_PENDING_AUTH.state);

    // Assert
    expect(result).toBeNull();
  });
});
