/**
 * HTTPS Validation Utility
 *
 * Centralized HTTPS enforcement.
 * Used by: config validation, OIDC discovery, and issuer validation.
 *
 * RFC 9700 — OAuth 2.0 Token Handler Pattern requires HTTPS
 */

/**
 * Validates that a URL uses HTTPS.
 *
 * @param url - The URL to validate
 * @returns true if URL uses HTTPS, false otherwise
 */
export function isValidHttpsUrl(url: string): boolean {
  return url.startsWith('https://');
}
