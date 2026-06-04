/**
 * In-memory Pending Auth Store
 *
 * For single-instance deployments and testing only.
 *
 * WARNING: breaks on scale-to-zero and multi-instance deployments.
 * Use CookiePendingStore (default) or a Redis/KV implementation for production.
 */

import type { PendingAuthStore, PendingAuth } from '@torii-gate/core/adapters/pending';

export class MemoryPendingStore implements PendingAuthStore {
  readonly #store = new Map<string, PendingAuth>();

  set(data: PendingAuth): Promise<Record<string, string>> {
    this.#store.set(data.state, data);
    return Promise.resolve({});
  }

  get(state: string, _request?: Request): Promise<PendingAuth | null> {
    const data = this.#store.get(state);
    if (!data) return Promise.resolve(null);

    // Single-use: remove immediately
    this.#store.delete(state);

    if (Date.now() > data.expiresAt) return Promise.resolve(null);

    return Promise.resolve(data);
  }

  clear(): Record<string, string> {
    return {};
  }
}
