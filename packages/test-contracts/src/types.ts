/**
 * Shared type definitions for test contracts
 */

/**
 * Adapter type for SessionAdapter implementations
 */
export type AdapterType = 'stateful' | 'stateless';

/**
 * Store type for PendingAuthStore implementations
 */
export type PendingStoreType = 'server-side' | 'cookie-based';

/**
 * Options for runAdapterContractTests
 */
export interface AdapterContractOptions {
  /**
   * The type of adapter being tested.
   * - 'stateful': Session ID in cookie, data in database (Redis, Memory, SQL)
   * - 'stateless': Encrypted session data in cookie
   */
  type: AdapterType;
}

/**
 * Options for runPendingStoreContractTests
 */
export interface PendingStoreContractOptions {
  /**
   * The type of pending auth store being tested.
   * - 'server-side': Data stored on server (Redis, Memory, SQL)
   * - 'cookie-based': Encrypted data in cookie
   */
  type: PendingStoreType;
}

/**
 * Options for runSecurityAuditTests
 */
export interface SecurityAuditOptions {
  /**
   * The type of pending auth store being tested.
   * Only 'cookie-based' stores are tested for timing-safe comparison.
   */
  type: PendingStoreType;
}
