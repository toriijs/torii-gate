import type { PendingAuth, PendingAuthStore } from '../../src/adapters';

// Simple in-memory test implementation (avoids circular dependency with adapter-memory)
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
