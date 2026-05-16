/**
 * State Parameter
 *
 * RFC 9700  — §4.7: state MUST be unpredictable and single-use
 * RFC 6749  — §10.12: CSRF protection
 *
 * The state value is stored server-side (in the session adapter or a
 * short-lived in-process Map) and validated exactly once on callback.
 * After validation — whether it passes or fails — the entry is removed.
 */

import { base64urlEncode } from './utils';
import { STATE_BYTES } from './constants';

/**
 * Generates a cryptographically random state value.
 *
 * RFC 9700 §4.7: must be unguessable, URL-safe, minimum 128 bits.
 * 16 random bytes → ~22 chars base64url → 128 bits entropy.
 *
 * This primitive is used internally by PendingAuthStore implementations.
 */
export function generateState(): Promise<string> {
  const bytes = new Uint8Array(STATE_BYTES);
  crypto.getRandomValues(bytes);
  return Promise.resolve(base64urlEncode(bytes));
}
