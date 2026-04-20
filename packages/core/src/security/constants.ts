/**
 * Security-related constants
 * All byte lengths follow RFC requirements
 */

/** PKCE code verifier length — RFC 7636 §4.1: 43-128 chars, we use 256 bits */
export const PKCE_CODE_VERIFIER_BYTES = 32;

/** OAuth state parameter length — 128 bits entropy recommended */
export const STATE_BYTES = 16;

/** OpenID nonce parameter length — 128 bits entropy recommended */
export const NONCE_BYTES = 16;

/** Session ID length — 256 bits for session identifier */
export const SESSION_ID_BYTES = 32;

/** AES-GCM IV/nonce length — MUST be 12 bytes for GCM mode */
export const AES_GCM_IV_BYTES = 12;

/** Default session TTL in seconds — 15 minutes */
export const DEFAULT_SESSION_TTL_SECONDS = 900;

/** PKCE pending auth TTL in seconds — 10 minutes */
export const PKCE_PENDING_TTL_SECONDS = 600;

/** OIDC discovery HTTP timeout in milliseconds */
export const OIDC_DISCOVERY_TIMEOUT_MS = 5000;
