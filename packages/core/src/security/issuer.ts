/**
 * Issuer Validation
 *
 * RFC 9207  — OAuth 2.0 Authorization Server Issuer Identification
 * RFC 9700  — §4.4: mix-up attack prevention
 *
 * Validates the `iss` parameter in the authorization response before
 * attempting token exchange. A missing or mismatched issuer is treated
 * as a potential mix-up attack and causes an immediate failure.
 */

import { isValidHttpsUrl } from './https.js';

/**
 * Validates the issuer from an authorization response.
 *
 * Rules:
 *   - `iss` must be present and non-empty
 *   - `iss` must exactly match `expectedIssuer` (case-sensitive)
 *   - Both values must use HTTPS
 *
 * @param iss - The issuer value from the authorization response
 * @param expectedIssuer - The expected issuer URL from configuration
 * @throws if `expectedIssuer` does not use HTTPS
 */
export function validateIssuer(iss: string | null | undefined, expectedIssuer: string): boolean {
  // Configuration guard: expected issuer must use HTTPS
  if (!isValidHttpsUrl(expectedIssuer)) {
    throw new Error(`expectedIssuer must use HTTPS (got "${expectedIssuer}"). HTTP authorization servers are not permitted.`);
  }

  // Missing or empty iss — potential mix-up attack
  if (!iss) return false;

  // Issuer in response must use HTTPS
  if (!isValidHttpsUrl(iss)) return false;

  // Exact match required — no prefix matching, no trailing-slash tolerance
  return iss === expectedIssuer;
}
