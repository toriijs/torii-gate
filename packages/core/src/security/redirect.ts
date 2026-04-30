/**
 * Redirect URI validation helpers.
 *
 * RFC 9700 §2.1   — authorization server and client MUST require exact
 *                   redirect_uri matches (no prefix, no pattern).
 * RFC 9700 §4.11  — open redirector in the logout flow must be prevented.
 *
 * Torii enforces exact match client-side so a compromised or permissive
 * authorization server cannot redirect authorization responses to a URL
 * other than the one we configured.
 */

/**
 * Asserts that the request URL matches the configured redirect_uri exactly.
 *
 * Comparison rules:
 *   - scheme + host + port (via `origin`) must match exactly
 *   - pathname must match after trailing-slash normalisation (`/cb` ≡ `/cb/`)
 *   - query string and fragment are intentionally ignored — the authorization
 *     response adds `code`, `state`, `iss` which are not part of the configured URI
 *
 * @throws Error (with message starting "redirect_uri mismatch") on any mismatch.
 */
export function assertExactRedirectUri(requestUrl: URL, configured: string): void {
  let expected: URL;
  try {
    expected = new URL(configured);
  } catch {
    throw new Error('redirect_uri mismatch: configured value is not a valid URL');
  }

  if (requestUrl.origin !== expected.origin) {
    throw new Error(`redirect_uri mismatch: origin "${requestUrl.origin}" !== "${expected.origin}"`);
  }

  if (normalisePath(requestUrl.pathname) !== normalisePath(expected.pathname)) {
    throw new Error(`redirect_uri mismatch: path "${requestUrl.pathname}" !== "${expected.pathname}"`);
  }
}

function normalisePath(path: string): string {
  if (path.length > 1 && path.endsWith('/')) return path.slice(0, -1);
  return path;
}

/**
 * Validates a post-logout redirect URI candidate against an allowlist.
 *
 * Allowlist entries are compared on `origin + pathname` (ignoring query/fragment)
 * using the same normalisation as `assertExactRedirectUri`. Wildcards are
 * intentionally unsupported — each allowed URI must be listed explicitly.
 *
 * Returns the candidate on success. Throws on failure.
 */
export function validatePostLogoutRedirectUri(candidate: string, allowlist: readonly string[]): string {
  if (allowlist.length === 0) {
    throw new Error('post-logout redirect URI rejected: no allowlist configured');
  }

  let candidateUrl: URL;
  try {
    candidateUrl = new URL(candidate);
  } catch {
    throw new Error(`post-logout redirect URI rejected: not a valid URL ("${candidate}")`);
  }

  const candidateKey = `${candidateUrl.origin}${normalisePath(candidateUrl.pathname)}`;

  for (const entry of allowlist) {
    let entryUrl: URL;
    try {
      entryUrl = new URL(entry);
    } catch {
      continue;
    }
    const entryKey = `${entryUrl.origin}${normalisePath(entryUrl.pathname)}`;
    if (entryKey === candidateKey) return candidate;
  }

  throw new Error(`post-logout redirect URI "${candidate}" is not in the allowlist`);
}
