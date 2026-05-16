export function unauthorized(reason: string): Response {
  // Reason is logged server-side only — never sent to the browser
  console.error(`[torii] proxy 401: ${reason}`);

  return new Response(JSON.stringify({ error: 'unauthorized' }), {
    status: 401,
    headers: {
      'content-type': 'application/json',
      // Prevent caching of 401 responses
      'cache-control': 'no-store',
    },
  });
}

export function buildUpstreamUrl(requestUrl: string, target: string): string {
  const url = new URL(requestUrl);
  const targetUrl = new URL(target);

  // Preserve path and query string, replace origin with target
  targetUrl.pathname = url.pathname;
  targetUrl.search = url.search;

  return targetUrl.toString();
}
