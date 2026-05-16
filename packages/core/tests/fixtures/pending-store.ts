import type { PendingAuth, PendingAuthStore } from '../../src/adapters/index.js';
import { generateNonce } from '../../src/security/nonce.js';
import { generateCodeVerifier } from '../../src/security/pkce.js';
import { generateState } from '../../src/security/state.js';

/**
 * Simple in-memory pending store for testing.
 * Avoids circular dependency with adapter-memory package.
 *
 * Features:
 * - Single-use state (deleted after first get)
 * - TTL enforcement (respects expiresAt)
 * - In-memory Map storage
 */
export class TestPendingStore implements PendingAuthStore {
  private readonly store = new Map<string, PendingAuth>();

  set(data: PendingAuth): Promise<Record<string, string>> {
    this.store.set(data.state, data);
    return Promise.resolve({});
  }

  get(state: string): Promise<PendingAuth | null> {
    const data = this.store.get(state);
    if (!data) return Promise.resolve(null);
    this.store.delete(state);
    if (Date.now() > data.expiresAt) return Promise.resolve(null);
    return Promise.resolve(data);
  }

  clear(): Record<string, string> {
    return {};
  }
}

/**
 * Creates a complete PendingAuth fixture with store and generated security parameters
 *
 * @param overrides - Optional field overrides for PendingAuth
 * @returns Object containing store, pendingAuth, and individual security parameters
 *
 * @example
 * const { store, pendingAuth, state } = await createPendingAuthFixture();
 * await store.set(pendingAuth);
 * const result = await store.get(state);
 */
export async function createPendingAuthFixture(overrides?: Partial<PendingAuth>): Promise<{
  store: TestPendingStore;
  pendingAuth: PendingAuth;
  state: string;
  nonce: string;
  codeVerifier: string;
}> {
  const state = await generateState();
  const nonce = await generateNonce();
  const codeVerifier = await generateCodeVerifier();

  const pendingAuth: PendingAuth = {
    state,
    nonce,
    codeVerifier,
    expiresAt: Date.now() + 10_000,
    ...overrides,
  };

  return {
    store: new TestPendingStore(),
    pendingAuth,
    state,
    nonce,
    codeVerifier,
  };
}
