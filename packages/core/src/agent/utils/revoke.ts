/**
 * Token Revocation — RFC 7009
 *
 * Shared utility for revoking OAuth tokens at the provider's revocation endpoint.
 * Used by both logout and refresh-token reuse detection flows.
 */

export interface RevokeTokensParams {
  accessToken: string;
  refreshToken: string | undefined;
  revocationEndpoint: string;
  clientId: string;
  clientSecret: string | undefined;
  fetch: typeof fetch;
}

/**
 * Revokes tokens at the provider's RFC 7009 revocation endpoint.
 *
 * Revokes both access and refresh tokens (if present). Refresh token is revoked
 * first as it has higher privilege. Uses Promise.allSettled so partial failures
 * don't block the entire operation.
 *
 * @throws Never — all fetch failures are caught and settled
 */
export async function revokeTokens(params: RevokeTokensParams): Promise<void> {
  const revoke = async (token: string, tokenTypeHint: string): Promise<void> => {
    const body = new URLSearchParams({
      token,
      token_type_hint: tokenTypeHint,
      client_id: params.clientId,
    });

    // Add client_secret for confidential clients (e.g., Keycloak)
    if (params.clientSecret) {
      body.set('client_secret', params.clientSecret);
    }

    await params.fetch(params.revocationEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
  };

  // Revoke both tokens — refresh token first (higher privilege)
  const tasks: Promise<void>[] = [];

  if (params.refreshToken) {
    tasks.push(revoke(params.refreshToken, 'refresh_token'));
  }

  tasks.push(revoke(params.accessToken, 'access_token'));

  await Promise.allSettled(tasks);
}
