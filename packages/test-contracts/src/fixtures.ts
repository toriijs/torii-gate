/**
 * Test Fixtures for SessionAdapter and PendingAuthStore Testing
 *
 * Predefined SessionData and PendingAuth objects for use in adapter tests.
 * These fixtures cover common test scenarios.
 */

import type { SessionData } from '@torii-gate/core/adapters/interface';
import type { PendingAuth } from '@torii-gate/core/adapters/pending';

/** Valid session with all fields populated (expires in 1 hour) */
export const VALID_SESSION: SessionData = {
  accessToken: 'access-token-value',
  refreshToken: 'refresh-token-value',
  expiresAt: Date.now() + 3_600_000,
  idToken: 'id-token-value',
  refreshGeneration: 0,
};

/** Session without optional fields */
export const MINIMAL_SESSION: SessionData = {
  accessToken: 'minimal-access-token',
  expiresAt: Date.now() + 1_800_000,
  refreshGeneration: 0,
};

/** Expired session (expiresAt in the past) */
export const EXPIRED_SESSION: SessionData = {
  accessToken: 'expired-token',
  expiresAt: Date.now() - 1_000,
  refreshGeneration: 0,
};

/** Session with userInfo claims */
export const SESSION_WITH_USERINFO: SessionData = {
  accessToken: 'token-with-userinfo',
  expiresAt: Date.now() + 3_600_000,
  idToken: 'id-token',
  userInfo: {
    sub: 'user-123',
    email: 'user@example.com',
    name: 'Test User',
  },
  refreshGeneration: 0,
};

// ─── PendingAuth Fixtures ─────────────────────────────────────────────────────

/** Valid pending auth with all fields populated (expires in 10 minutes) */
export const VALID_PENDING_AUTH: PendingAuth = {
  codeVerifier: 'test-code-verifier-abcdefghijklmnopqrstuvwxyz0123456789-_',
  nonce: 'test-nonce-value',
  state: 'test-state-value',
  expiresAt: Date.now() + 600_000, // 10 minutes
};

/** Pending auth with minimal TTL (expires in 1 second) */
export const SHORT_TTL_PENDING_AUTH: PendingAuth = {
  codeVerifier: 'short-ttl-verifier',
  nonce: 'short-ttl-nonce',
  state: 'short-ttl-state',
  expiresAt: Date.now() + 1_000,
};

/** Expired pending auth (expiresAt in the past) */
export const EXPIRED_PENDING_AUTH: PendingAuth = {
  codeVerifier: 'expired-verifier',
  nonce: 'expired-nonce',
  state: 'expired-state',
  expiresAt: Date.now() - 1_000,
};

// ─── Invalid SessionData Fixtures ─────────────────────────────────────────────

/** Session with negative expiresAt (invalid timestamp) */
export const INVALID_EXPIRES_AT_SESSION: SessionData = {
  accessToken: 'valid-token',
  expiresAt: -1000,
  refreshGeneration: 0,
};

/** Session with NaN expiresAt */
export const NAN_EXPIRES_AT_SESSION: SessionData = {
  accessToken: 'valid-token',
  expiresAt: Number.NaN,
  refreshGeneration: 0,
};

/** Session with negative refreshGeneration */
export const NEGATIVE_GENERATION_SESSION: SessionData = {
  accessToken: 'valid-token',
  expiresAt: Date.now() + 3_600_000,
  refreshGeneration: -1,
};

/** Session with empty accessToken */
export const EMPTY_TOKEN_SESSION: SessionData = {
  accessToken: '',
  expiresAt: Date.now() + 3_600_000,
  refreshGeneration: 0,
};

/** Session with extremely long token (10KB) */
export const LARGE_TOKEN_SESSION: SessionData = {
  accessToken: 'x'.repeat(10_000),
  expiresAt: Date.now() + 3_600_000,
  refreshGeneration: 0,
};

/** Session with special characters in token */
export const SPECIAL_CHARS_SESSION: SessionData = {
  accessToken: 'token-with-émojis-🔐-and-控制字符',
  expiresAt: Date.now() + 3_600_000,
  refreshGeneration: 0,
};

// ─── Edge Case PendingAuth Fixtures ───────────────────────────────────────────

/** Pending auth with empty state (invalid) */
export const EMPTY_STATE_PENDING_AUTH: PendingAuth = {
  codeVerifier: 'valid-verifier',
  nonce: 'valid-nonce',
  state: '',
  expiresAt: Date.now() + 600_000,
};

/** Pending auth with very long state (DoS test) */
export const LONG_STATE_PENDING_AUTH: PendingAuth = {
  codeVerifier: 'valid-verifier',
  nonce: 'valid-nonce',
  state: 'x'.repeat(10_000),
  expiresAt: Date.now() + 600_000,
};
