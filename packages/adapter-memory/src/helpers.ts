/**
 * Extracts session ID from Cookie header in Request.
 * Returns null if cookie not found.
 */
export function extractSessionId(request: Request, cookieName: string): string | null {
  const cookieHeader = request.headers.get('cookie');
  if (!cookieHeader) return null;

  const cookies = parseCookies(cookieHeader);
  return cookies.get(cookieName) ?? null;
}

/**
 * Parses Cookie header into a Map.
 */
export function parseCookies(header: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const pair of header.split(';')) {
    const eq = pair.indexOf('=');
    if (eq < 0) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair
      .slice(eq + 1)
      .trim()
      .replaceAll(/^"|"$/g, '');
    if (name) map.set(name, value);
  }
  return map;
}

/**
 * Generates a cryptographically random session ID.
 */
export function generateSessionId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
