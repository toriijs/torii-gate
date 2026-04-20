/**
 * Adapter Interfaces
 *
 * All external storage adapter interfaces are defined here.
 * Implementations live in separate @torii-gate/adapter-* packages.
 */

export type { SessionAdapter, SessionData, CookieOptions } from './interface.js';

export type { PendingAuthStore, PendingAuth } from './pending.js';
