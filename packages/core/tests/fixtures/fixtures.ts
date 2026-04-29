import type { SessionAdapter, SessionData } from '../../src/adapters/index.js';
import { vi } from 'vitest';

export function createMockAdapter(session: SessionData | null): SessionAdapter {
  return {
    get: vi.fn().mockResolvedValue(session),
    set: vi.fn().mockResolvedValue([]),
    delete: vi.fn().mockResolvedValue([]),
  };
}
