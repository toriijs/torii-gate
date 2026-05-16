/**
 * CSRF Protection
 *
 * RFC 9700  — §7.1: CSRF protection for BFF endpoints
 *
 * Strategy: require a custom request header on all BFF endpoints.
 * A custom header triggers a CORS preflight on any cross-origin request.
 * The preflight fails if the origin is not in the allowlist — cross-site
 * form submissions and script-driven requests cannot set custom headers,
 * so they are blocked before reaching the handler.
 *
 * Defence-in-depth: SameSite=Strict on the session cookie provides a
 * second layer — the cookie is not sent on cross-site navigations at all.
 */

export interface CsrfConfig {
  /** Name of the required custom header (case-insensitive) */
  headerName: string;
  /**
   * Exact origin strings that are permitted.
   * Wildcards are not allowed — each entry must be an explicit HTTPS origin.
   * Example: ['https://app.torii.dev', 'https://admin.torii.dev']
   */
  allowedOrigins: readonly string[];
}

/**
 * Validates CSRF protection for an incoming request.
 *
 * Returns true only if:
 *   1. The required custom header is present (any non-empty value)
 *   2. The Origin header exactly matches one of the allowed origins
 *
 * Both conditions must be satisfied — either alone is insufficient.
 */
export function validateCsrf(request: Request, config: CsrfConfig): boolean {
  // Guard: reject wildcard origins at call time
  if (config.allowedOrigins.includes('*')) {
    throw new Error(`Wildcard (*) is not a valid allowed origin. ` + `Specify explicit HTTPS origins in allowedOrigins.`);
  }

  // Condition 1: custom header must be present with a non-empty value
  const headerValue = request.headers.get(config.headerName);
  if (!headerValue) return false;

  // Condition 2: Origin header must match an allowed origin exactly
  const origin = request.headers.get('origin');
  if (!origin) return false;

  return config.allowedOrigins.includes(origin);
}
