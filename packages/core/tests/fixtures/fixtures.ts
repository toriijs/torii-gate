import type { SessionAdapter, SessionData } from '../../src/adapters/index.js';
import { vi } from 'vitest';

/**
 * Creates a mock SessionAdapter with Vitest spies.
 *
 * @param session - Session data to return from get(), or null for no session
 * @param options - Optional return values for set() and delete()
 * @returns SessionAdapter with mocked methods
 */
export function createMockAdapter(
  session: SessionData | null,
  options?: {
    setHeaders?: string[];
    deleteHeaders?: string[];
  },
): SessionAdapter {
  return {
    get: vi.fn().mockResolvedValue(session),
    set: vi.fn().mockResolvedValue(options?.setHeaders ?? []),
    delete: vi.fn().mockResolvedValue(options?.deleteHeaders ?? []),
  };
}

/**
 * Creates a mock fetch function that returns a JSON response.
 *
 * @param response - Response body (will be JSON stringified)
 * @param status - HTTP status code (default: 200)
 * @returns Mocked fetch function
 */
export function createMockFetch(response: Record<string, unknown> = {}, status = 200): ReturnType<typeof vi.fn<typeof fetch>> {
  return vi.fn<typeof fetch>().mockResolvedValue(
    new Response(JSON.stringify(response), {
      status,
      headers: { 'content-type': 'application/json' },
    }),
  );
}
