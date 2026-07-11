/**
 * Optional Security Audit Test Suite
 *
 * These tests validate timing-safe operations and other security properties
 * that are difficult to test deterministically. Run separately from main
 * contract tests.
 *
 * Usage:
 * ```typescript
 * import { runSecurityAuditTests } from '@torii-gate/test-contracts/security-audit';
 *
 * describe('Security Audit', () => {
 *   runSecurityAuditTests(() => new MyCookiePendingStore(), { type: 'cookie-based' });
 * });
 * ```
 */

import { describe, it, expect } from 'vitest';
import type { PendingAuthStore } from '@torii-gate/core/adapters/pending';
import { VALID_PENDING_AUTH } from './fixtures';
import { mockRequest } from './contract';
import type { SecurityAuditOptions } from './types.js';

/**
 * Maximum timing variance ratio for constant-time comparison heuristic.
 * Allows 2x variance to account for JIT, GC, scheduler noise.
 * RFC 8725 recommends constant-time for all cryptographic operations.
 */
const TIMING_SAFE_MAX_RATIO = 2;

export function runSecurityAuditTests(createStore: () => PendingAuthStore, options: SecurityAuditOptions): void {
  const isCookieBased = options.type === 'cookie-based';

  describe('Security Audit - Timing-Safe Operations', () => {
    it.skipIf(!isCookieBased)('state validation uses timing-safe comparison (heuristic)', async () => {
      const store = createStore();
      const headers = await store.set(VALID_PENDING_AUTH);
      const request = mockRequest(headers['set-cookie']!);

      // Measure timing for short wrong state
      const shortTimes: number[] = [];
      for (let i = 0; i < 20; i++) {
        const start = performance.now();
        await store.get('x', request);
        shortTimes.push(performance.now() - start);
      }

      // Re-create entry (consumed by gets above)
      const headers2 = await store.set({ ...VALID_PENDING_AUTH, state: 'timing-test-state-2' });
      const request2 = headers2['set-cookie'] ? mockRequest(headers2['set-cookie']) : undefined;

      // Measure timing for long wrong state
      const longTimes: number[] = [];
      for (let i = 0; i < 20; i++) {
        const start = performance.now();
        await store.get('x'.repeat(50), request2);
        longTimes.push(performance.now() - start);
      }

      // Calculate median times (more robust than mean)
      const median = (arr: number[]) => {
        const sorted = arr.slice().sort((a, b) => a - b);
        return sorted.at(Math.floor(sorted.length / 2)) ?? 0;
      };

      const shortMedian = median(shortTimes);
      const longMedian = median(longTimes);

      // Timing difference should be minimal for constant-time comparison
      const ratio = Math.max(shortMedian, longMedian) / Math.min(shortMedian, longMedian);

      // Note: This is a heuristic test, not proof of constant-time
      expect(ratio).toBeLessThan(TIMING_SAFE_MAX_RATIO);
    });
  });
}
