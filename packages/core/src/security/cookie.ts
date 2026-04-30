/**
 * Session Cookie Builder
 *
 * RFC 6265bis — Cookie security attributes
 * RFC 9700    — §7: Token Handler session cookie requirements
 *
 * Builds Set-Cookie headers whose security attributes are derived from the
 * deployment topology — consumers do not configure SameSite or Domain directly.
 * The topology drives all security-critical attributes to prevent misconfiguration.
 *
 * same-domain topology (default):
 *   __Host-session=…; Max-Age=…; Path=/; Secure; HttpOnly; SameSite=Strict
 *   - __Host- prefix: enforces Secure + Path=/ + no Domain (browser-enforced)
 *   - SameSite=Strict: cookie only sent on same-origin requests
 *   - No Domain attribute: scoped exactly to the BFF origin
 *
 * subdomain topology:
 *   __Secure-session=…; Max-Age=…; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=.example.com
 *   - __Secure- prefix: requires Secure (__Host- cannot coexist with Domain)
 *   - SameSite=Lax: required — SPA and BFF are on different subdomains
 *   - Domain=.example.com: cookie shared across SPA and BFF subdomains
 */

import { getCookieSameSite, buildDomainAttribute, isCookieNameValid, type Topology, type TopologyConfig } from './topology.js';
import { extractCookieValue } from './utils/index.js';

/**
 * Cookie name constraint for same-domain topology.
 * Must use the __Host- prefix which enforces Secure + Path=/ + no Domain.
 */
export interface SameDomainCookieConfig {
  /**
   * Deployment topology — drives SameSite and Domain attributes.
   * Defaults to 'same-domain'.
   */
  topology?: 'same-domain' | undefined;
  /**
   * Cookie name — must start with __Host- for same-domain topology.
   * Defaults to '__Host-session'.
   */
  cookieName?: `__Host-${string}` | undefined;
  /**
   * Parent domain for subdomain topology.
   * Not allowed for same-domain topology.
   */
  cookieDomain?: never;
}

/**
 * Cookie name constraint for subdomain topology.
 * Must use the __Secure- prefix (Domain attribute forbids __Host-).
 */
export interface SubdomainCookieConfig {
  /**
   * Deployment topology — drives SameSite and Domain attributes.
   */
  topology: 'subdomain';
  /**
   * Cookie name — must start with __Secure- for subdomain topology.
   * Defaults to '__Secure-session'.
   */
  cookieName?: `__Secure-${string}` | undefined;
  /**
   * Parent domain for subdomain topology.
   * Required when topology is 'subdomain'.
   * @example 'example.com'
   */
  cookieDomain: string;
}

/**
 * Common cookie properties shared across all topologies.
 */
export interface CommonCookieProperties {
  /** Max-Age in seconds — defaults to 900 (15 minutes) */
  maxAge?: number;
  /**
   * Cookie path — MUST be '/' and cannot be changed.
   * Exists only to produce a clear error if a narrower path is attempted.
   */
  path?: '/';
}

/**
 * Cookie configuration with strict typing for cookie names based on topology.
 *
 * Uses a discriminated union to enforce:
 * - same-domain: cookieName must start with __Host-
 * - subdomain:   cookieName must start with __Secure-
 */
export type CookieOptions = (SameDomainCookieConfig | SubdomainCookieConfig) & CommonCookieProperties;

const DEFAULT_MAX_AGE = 900;
const MAX_ALLOWED_AGE = 28 * 60 * 60; // 28 hours — hard ceiling
const DEFAULT_SAME_DOMAIN_NAME = '__Host-session' as const;
const DEFAULT_SUBDOMAIN_NAME = '__Secure-session' as const;

/**
 * Returns the default cookie name for the given topology.
 */
export function defaultCookieName(topology: Topology = 'same-domain'): string {
  return topology === 'same-domain' ? DEFAULT_SAME_DOMAIN_NAME : DEFAULT_SUBDOMAIN_NAME;
}

/**
 * Builds a Set-Cookie header with security attributes derived from topology.
 *
 * Throws at construction time on any invariant violation — fail-fast prevents
 * misconfigured cookies from ever being sent.
 */
export function buildSessionCookie(value: string, options: CookieOptions): string {
  const topology = options.topology ?? 'same-domain';
  const name = options.cookieName ?? defaultCookieName(topology);
  const maxAge = options.maxAge ?? DEFAULT_MAX_AGE;
  const sameSite = getCookieSameSite(topology);
  const topoCfg: TopologyConfig = { topology, cookieDomain: options.cookieDomain };

  // ── Invariant checks ──────────────────────────────────────────────────────

  if (!isCookieNameValid(name, topology)) {
    const required = topology === 'same-domain' ? '__Host-' : '__Secure-';
    throw new Error(
      `Cookie name '${name}' is invalid for topology '${topology}'. ` +
        `Expected prefix: ${required}. ` +
        (topology === 'subdomain'
          ? `The __Host- prefix cannot coexist with the Domain attribute required for subdomain cookies.`
          : `The __Host- prefix enforces Secure, Path=/, and no Domain attribute.`),
    );
  }

  // NOSONAR: typescript:S2367 — intentional runtime guard against type cast bypass
  if (options.path !== undefined && (options.path as string) !== '/') {
    throw new Error(
      `Cookie path must be '/' — the browser rejects cookies with a narrower path ` +
        `when using __Host- or __Secure- prefixes (got '${options.path as string}').`,
    );
  }

  if (maxAge > MAX_ALLOWED_AGE) {
    throw new Error(
      `maxAge ${maxAge}s exceeds the 28-hour ceiling (${MAX_ALLOWED_AGE}s). ` + `Use the Redis adapter for sessions requiring a longer lifetime.`,
    );
  }

  // ── Build header ──────────────────────────────────────────────────────────

  const domainAttr = buildDomainAttribute(topoCfg);

  const parts = [`${name}=${value}`, `Max-Age=${maxAge}`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=${sameSite}`];

  // Domain is only added for subdomain topology — __Host- forbids it
  if (domainAttr) parts.push(domainAttr);

  return parts.join('; ');
}

/**
 * Builds a Set-Cookie header that immediately expires the session cookie.
 * Retains all topology-appropriate security attributes.
 */
export function clearSessionCookie(cookieName?: string, options: Pick<CookieOptions, 'topology' | 'cookieDomain'> = {}): string {
  const topology = options.topology ?? 'same-domain';
  const name = cookieName ?? defaultCookieName(topology);
  const sameSite = getCookieSameSite(topology);
  const topoCfg: TopologyConfig = { topology, cookieDomain: options.cookieDomain };

  if (!isCookieNameValid(name, topology)) {
    const required = topology === 'same-domain' ? '__Host-' : '__Secure-';
    throw new Error(`Cookie name '${name}' is invalid for topology '${topology}'. Expected prefix: ${required}.`);
  }

  const domainAttr = buildDomainAttribute(topoCfg);

  const parts = [`${name}=`, `Max-Age=0`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=${sameSite}`];

  if (domainAttr) parts.push(domainAttr);

  return parts.join('; ');
}

/**
 * Extracts the session ID from a Cookie request header.
 * Returns null if the cookie is absent.
 */
export function parseSessionCookieName(cookieHeader: string, cookieName: string): string | null {
  return extractCookieValue(cookieHeader, cookieName);
}
