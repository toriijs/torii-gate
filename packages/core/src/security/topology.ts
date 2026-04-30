/**
 * Topology Utilities
 *
 * Torii supports two deployment topologies that affect cookie security
 * attributes, CORS requirements, and the allowed cookie name prefix.
 *
 * ── same-domain ────────────────────────────────────────────────────────────
 * SPA and BFF share the same origin.
 *
 *   https://app.torii.dev/          → SPA (static files, CDN)
 *   https://app.torii.dev/auth/*    → Torii Gate
 *   https://app.torii.dev/api/*     → Torii Gate (proxies upstream)
 *
 * Cookie: __Host-session
 *   - __Host- prefix: enforces Secure + Path=/ + no Domain
 *   - SameSite=Strict: cookie only sent on same-origin requests
 *   - No Domain attribute: scoped to exact origin
 *   - Strongest possible cookie security — recommended topology
 *
 * ── subdomain ──────────────────────────────────────────────────────────────
 * SPA and BFF are on different subdomains of a shared parent domain.
 *
 *   https://app.torii.dev           → SPA
 *   https://bff.torii.dev/auth/*    → Torii Gate
 *   https://bff.torii.dev/api/*     → Torii Gate
 *
 * Cookie: __Secure-session; Domain=.torii.dev
 *   - __Secure- prefix: requires Secure (cannot use __Host- — it forbids Domain)
 *   - SameSite=Lax: required — app.torii.dev → bff.torii.dev is cross-site
 *     in the Schemeful Same-Site model. Strict would block the cookie entirely.
 *   - Domain=.torii.dev: shared across all subdomains
 *
 * Security trade-offs vs same-domain:
 *   - __Secure- is weaker than __Host- (Domain attribute is permitted)
 *   - SameSite=Lax is weaker than SameSite=Strict
 *   - A compromised subdomain can read/set the cookie (shared Domain)
 *   - CORS required (cross-origin fetches from SPA to BFF)
 *   - CSRF header check becomes the primary CSRF defence (already enforced)
 *
 * Neither topology uses SameSite=None — that would require removing Secure
 * in some environments and is fundamentally incompatible with the BFF model.
 * Truly separate domains (app.io + api.com) are not supported.
 */

export type Topology = 'same-domain' | 'subdomain';

/**
 * Discriminated union that constrains the cookie name prefix to the correct
 * value for the deployment topology.
 *
 * Reuse this as a base for any config type that accepts a topology + cookie name
 * so that TypeScript rejects the wrong prefix at the call site:
 *
 *   same-domain → cookieName must start with __Host-
 *   subdomain   → cookieName must start with __Secure-
 *
 * The `cookieDomain` field is enforced by the discriminant:
 *   same-domain → cookieDomain must not be present
 *   subdomain   → cookieDomain is required (subdomain topology needs a shared domain)
 */
export type TopologyAwareCookieOptions =
  | {
      topology?: 'same-domain' | undefined;
      /** Must start with __Host- */
      cookieName?: `__Host-${string}`;
      cookieDomain?: never;
    }
  | {
      topology: 'subdomain' | undefined;
      /** Must start with __Secure- */
      cookieName?: `__Secure-${string}`;
      /** Required for subdomain topology — the shared parent domain */
      cookieDomain: string;
    };

export interface TopologyConfig {
  topology: Topology;
  /**
   * Parent domain shared by SPA and BFF subdomains.
   * Required when topology is 'subdomain'.
   *
   * @example 'torii.dev'  — for app.torii.dev + bff.torii.dev
   *
   * Must not include a leading dot — the dot is added automatically
   * when building the Domain cookie attribute (Domain=.torii.dev).
   * Must not include a scheme or port.
   */
  cookieDomain?: string | undefined;
}

/**
 * Returns the required cookie name prefix for the given topology.
 *
 * same-domain → '__Host-'   (strongest — no Domain, Path=/ enforced by browser)
 * subdomain   → '__Secure-' (requires Domain attribute — __Host- forbids it)
 */
export function getCookiePrefix(topology: Topology): '__Host-' | '__Secure-' {
  return topology === 'same-domain' ? '__Host-' : '__Secure-';
}

/**
 * Returns true if the cookie name is valid for the given topology.
 *
 * same-domain: must start with __Host-
 * subdomain:   must start with __Secure- (or __Host- — __Host- is a subset)
 */
export function isCookieNameValid(name: string, topology: Topology): boolean {
  if (topology === 'same-domain') return name.startsWith('__Host-');
  // subdomain accepts __Secure- or __Host- (though __Host- won't work with Domain)
  return name.startsWith('__Secure-') || name.startsWith('__Host-');
}

/**
 * Derives the correct cookie name base for a topology.
 * If the provided name has the wrong prefix for the topology, replaces it.
 *
 * @example
 *   deriveCookieName('__Host-session', 'subdomain') → '__Secure-session'
 *   deriveCookieName('__Secure-session', 'same-domain') → '__Host-session'
 *   deriveCookieName('__Host-session', 'same-domain') → '__Host-session' (unchanged)
 */
export function deriveCookieName(baseName: string, topology: Topology): string {
  const stripPrefixes = (name: string): string => name.replace(/^(__Host-|__Secure-)/, '');

  const base = stripPrefixes(baseName);
  return `${getCookiePrefix(topology)}${base}`;
}

/**
 * Returns the required SameSite value for the given topology.
 *
 * same-domain → 'Strict'  (cookie only sent on same-origin requests)
 * subdomain   → 'Lax'     (cookie sent on cross-site navigations and fetches
 *                          with credentials:include from SPA to BFF subdomain)
 */
export function getCookieSameSite(topology: Topology): 'Strict' | 'Lax' {
  return topology === 'same-domain' ? 'Strict' : 'Lax';
}

/**
 * Builds the topology options object for spreading into cookie config objects.
 *
 * Includes `topology`, optional `cookieDomain`, and optionally a `cookieName`
 * branded to the correct prefix for the topology (`__Host-` / `__Secure-`).
 * This is the bridge between the schema's plain `string` cookie name and the
 * typed `TopologyAwareCookieOptions` — startup validation already guarantees
 * the prefix is correct, so the internal cast is safe.
 *
 * Handles the `exactOptionalPropertyTypes` constraint — optional fields are
 * only included in the returned object when their value is defined.
 *
 * @example
 *   // cookie name will use the topology default
 *   buildSessionCookie(id, { ...buildTopologyOptions(topology, domain), maxAge })
 *   // cookie name explicitly provided
 *   buildTopologyOptions(topology, domain, cookieName)
 */
export function buildTopologyOptions(
  topology: 'same-domain',
  cookieDomain?: string,
  cookieName?: string,
): { topology: 'same-domain'; cookieName?: `__Host-${string}` };
export function buildTopologyOptions(
  topology: 'subdomain',
  cookieDomain: string,
  cookieName?: string,
): { topology: 'subdomain'; cookieDomain: string; cookieName?: `__Secure-${string}` };
export function buildTopologyOptions(topology: Topology, cookieDomain?: string, cookieName?: string): TopologyAwareCookieOptions {
  const opts: Record<string, unknown> = { topology };
  if (topology === 'subdomain') {
    if (!cookieDomain) throw new Error('cookieDomain is required when topology is subdomain');
    opts['cookieDomain'] = cookieDomain;
  }
  if (cookieName) opts['cookieName'] = cookieName;
  return opts as TopologyAwareCookieOptions;
}

/**
 * Returns the Domain cookie attribute string for the given topology.
 *
 * same-domain → ''                         (no Domain attribute — __Host- forbids it)
 * subdomain   → 'Domain=.torii.dev'      (leading dot = includes subdomains)
 *
 * @throws if topology is 'subdomain' but cookieDomain is not provided
 */
export function buildDomainAttribute(config: TopologyConfig): string {
  if (config.topology === 'same-domain') return '';

  if (!config.cookieDomain) {
    throw new Error(`topology 'subdomain' requires cookieDomain to be set. ` + `Set TORII_COOKIE_DOMAIN=torii.dev (the shared parent domain).`);
  }

  // Normalise — strip any leading dot or scheme the user might have included
  // Use destructuring to avoid non-null assertion (split always returns at least one element)
  const [domain = ''] = config.cookieDomain
    .replace(/^\./, '')
    .replace(/^https?:\/\//, '')
    .split('/'); // strip any path

  return `Domain=.${domain}`;
}

export interface TopologyValidationError {
  field: string;
  message: string;
}

/**
 * Cross-field validation for topology config.
 * Returns an array of errors — empty means valid.
 *
 * Called at startup after Valibot schema validation passes.
 * Valibot handles per-field validation; this handles cross-field rules.
 */
export function validateTopologyConfig(
  topology: Topology,
  cookieDomain: string | undefined,
  allowedOrigins: string[],
  cookieName: string,
): TopologyValidationError[] {
  const errors: TopologyValidationError[] = [];

  if (topology === 'subdomain') {
    // cookieDomain required
    if (!cookieDomain) {
      errors.push({
        field: 'security.cookieDomain',
        message: "topology 'subdomain' requires security.cookieDomain " + "(e.g. 'torii.dev' for app.torii.dev + bff.torii.dev)",
      });
    }

    // At least one allowed origin required for CORS
    if (allowedOrigins.length === 0) {
      errors.push({
        field: 'security.allowedOrigins',
        message: "topology 'subdomain' requires at least one entry in security.allowedOrigins " + '(the SPA origin, e.g. https://app.torii.dev)',
      });
    }

    // cookieName must NOT use __Host- prefix — it is incompatible with Domain attribute
    if (cookieName.startsWith('__Host-')) {
      errors.push({
        field: 'security.cookieName',
        message:
          `topology 'subdomain' requires a __Secure- cookie name prefix (got '${cookieName}'). ` +
          `The __Host- prefix forbids the Domain attribute which is required for subdomain cookies. ` +
          `Use '__Secure-session' or let Torii derive the name automatically.`,
      });
    }
  }

  if (topology === 'same-domain') {
    // cookieName must NOT use __Secure- prefix — __Host- is required for same-domain
    if (cookieName.startsWith('__Secure-') && !cookieName.startsWith('__Host-')) {
      errors.push({
        field: 'security.cookieName',
        message: `topology 'same-domain' requires a __Host- cookie name prefix (got '${cookieName}'). ` + `Use '__Host-session' (the default).`,
      });
    }

    // cookieDomain makes no sense for same-domain
    if (cookieDomain) {
      errors.push({
        field: 'security.cookieDomain',
        message:
          `topology 'same-domain' does not use cookieDomain (got '${cookieDomain}'). ` + `Remove TORII_COOKIE_DOMAIN, or switch to topology 'subdomain'.`,
      });
    }
  }

  return errors;
}
