/**
 * Token Revocation Test Suite — RFC 7009
 *
 * Unit tests for revokeTokens utility implementing OAuth 2.0 Token Revocation.
 * This function is used by both logout and refresh-token reuse detection flows.
 *
 * RFC 7009 compliance areas tested:
 * - Request format (POST, urlencoded)
 * - Required parameters (token, token_type_hint, client_id)
 * - Optional parameters (client_secret)
 * - Token type hints (refresh_token vs access_token)
 * - Resilient failure handling (Promise.allSettled)
 *
 * Integration callers:
 * - packages/core/src/agent/logout.ts:79-86
 * - packages/core/src/agent/refresh.ts:109-116
 */

import { describe, it, expect, vi } from 'vitest';
import { revokeTokens, type RevokeTokensParams } from './revoke';

/**
 * Creates a RevokeTokensParams object with sensible defaults for testing.
 * All fields can be overridden via the overrides parameter.
 */
const createParams = (overrides?: Partial<RevokeTokensParams>): RevokeTokensParams => ({
  accessToken: 'test_access_token',
  refreshToken: 'test_refresh_token',
  revocationEndpoint: 'https://auth.torii.dev/revoke',
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  fetch: vi.fn().mockResolvedValue(new Response('', { status: 200 })),
  ...overrides,
});

/**
 * Extracts URLSearchParams from a specific fetch call.
 * @param fetchMock - The mocked fetch function
 * @param callIndex - Which call to extract from (0-based)
 */
const getBodyParams = (fetchMock: ReturnType<typeof vi.fn>, callIndex = 0): URLSearchParams => {
  const call = fetchMock.mock.calls[callIndex];
  if (!call) {
    throw new Error(`No fetch call at index ${callIndex}`);
  }
  const options = call[1] as RequestInit;
  return new URLSearchParams(options.body as string);
};

// ─── Request Format (RFC 7009 §2.1) ──────────────────────────────────────────

describe('revokeTokens — request format', () => {
  it('sends POST request with correct content-type header', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
    const params = createParams({ fetch: mockFetch });

    // Act
    await revokeTokens(params);

    // Assert - Should make 2 calls (refresh + access token)
    expect(mockFetch).toHaveBeenCalledTimes(2);

    // Both calls should use POST with urlencoded content-type
    expect(mockFetch).toHaveBeenCalledWith(
      'https://auth.torii.dev/revoke',
      expect.objectContaining({
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      }),
    );
  });
});

describe('revokeTokens — both tokens present', () => {
  it('revokes both refresh_token and access_token when both present', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
    const params = createParams({ fetch: mockFetch });

    // Act
    await revokeTokens(params);

    // Assert
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(mockFetch).toHaveBeenNthCalledWith(1, 'https://auth.torii.dev/revoke', expect.objectContaining({ method: 'POST' }));
    expect(mockFetch).toHaveBeenNthCalledWith(2, 'https://auth.torii.dev/revoke', expect.objectContaining({ method: 'POST' }));
  });

  it('sends refresh_token first, then access_token', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
    const params = createParams({ fetch: mockFetch });

    // Act
    await revokeTokens(params);

    // First call should have the refresh token
    const firstCallParams = getBodyParams(mockFetch, 0);

    // Assert
    expect(firstCallParams.get('token')).toBe('test_refresh_token');

    // Second call should have the access token
    const secondCallParams = getBodyParams(mockFetch, 1);

    expect(secondCallParams.get('token')).toBe('test_access_token');
  });

  it('includes correct token_type_hint for each token', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
    const params = createParams({ fetch: mockFetch });

    // Act
    await revokeTokens(params);

    // Refresh token call should have token_type_hint=refresh_token
    const firstCallParams = getBodyParams(mockFetch, 0);

    // Assert
    expect(firstCallParams.get('token_type_hint')).toBe('refresh_token');

    // Access token call should have token_type_hint=access_token
    const secondCallParams = getBodyParams(mockFetch, 1);

    expect(secondCallParams.get('token_type_hint')).toBe('access_token');
  });
});

describe('revokeTokens — client credentials', () => {
  it('includes client_id in all revocation requests', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
    const params = createParams({ fetch: mockFetch, clientId: 'my-custom-client' });

    // Act
    await revokeTokens(params);

    // Both calls should include client_id
    const firstCallParams = getBodyParams(mockFetch, 0);

    // Assert
    expect(firstCallParams.get('client_id')).toBe('my-custom-client');

    const secondCallParams = getBodyParams(mockFetch, 1);

    expect(secondCallParams.get('client_id')).toBe('my-custom-client');
  });

  it('includes client_secret when provided (confidential client)', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
    const params = createParams({ fetch: mockFetch, clientSecret: 'my-secret-123' });

    // Act
    await revokeTokens(params);

    // Both calls should include client_secret
    const firstCallParams = getBodyParams(mockFetch, 0);

    // Assert
    expect(firstCallParams.get('client_secret')).toBe('my-secret-123');

    const secondCallParams = getBodyParams(mockFetch, 1);

    expect(secondCallParams.get('client_secret')).toBe('my-secret-123');
  });

  it('excludes client_secret when undefined (public client)', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
    const params = createParams({ fetch: mockFetch, clientSecret: undefined });

    // Act
    await revokeTokens(params);

    // Neither call should include client_secret
    const firstCallParams = getBodyParams(mockFetch, 0);

    // Assert
    expect(firstCallParams.has('client_secret')).toBe(false);

    const secondCallParams = getBodyParams(mockFetch, 1);

    expect(secondCallParams.has('client_secret')).toBe(false);
  });
});

describe('revokeTokens — refresh token optional', () => {
  it('revokes only access_token when refreshToken is undefined', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
    const params = createParams({ fetch: mockFetch, refreshToken: undefined });

    // Act
    await revokeTokens(params);

    // Assert - Only one call should be made
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // The single call should be for the access token
    const callParams = getBodyParams(mockFetch, 0);

    expect(callParams.get('token')).toBe('test_access_token');
    expect(callParams.get('token_type_hint')).toBe('access_token');
  });

  it('sends correct parameters when only access_token present', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
    const params = createParams({
      fetch: mockFetch,
      refreshToken: undefined,
      accessToken: 'my-access-token',
      clientId: 'my-client',
    });

    // Act
    await revokeTokens(params);

    const callParams = getBodyParams(mockFetch, 0);

    // Assert
    expect(callParams.get('token')).toBe('my-access-token');
    expect(callParams.get('token_type_hint')).toBe('access_token');
    expect(callParams.get('client_id')).toBe('my-client');

    // Should not contain refresh token
    expect(callParams.get('token')).not.toBe('test_refresh_token');
  });
});

describe('revokeTokens — error resilience', () => {
  it('completes successfully even when first revocation fails', async () => {
    // Arrange
    const mockFetch = vi
      .fn()
      .mockRejectedValueOnce(new Error('Network error'))
      .mockResolvedValueOnce(new Response('', { status: 200 }));

    const params = createParams({ fetch: mockFetch });

    // Act & Assert - Should not throw
    await expect(revokeTokens(params)).resolves.toBeUndefined();

    // Both attempts should have been made
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('completes successfully even when second revocation fails', async () => {
    // Arrange
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce(new Response('', { status: 200 }))
      .mockRejectedValueOnce(new Error('Network error'));

    const params = createParams({ fetch: mockFetch });

    // Act & Assert - Should not throw
    await expect(revokeTokens(params)).resolves.toBeUndefined();

    // Both attempts should have been made
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('completes when both revocations fail', async () => {
    // Arrange
    const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'));
    const params = createParams({ fetch: mockFetch });

    // Act & Assert
    // Should not throw — critical for logout flow
    // Local session should clear even if provider is down
    await expect(revokeTokens(params)).resolves.toBeUndefined();

    // Both attempts should have been made
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('completes when provider returns 4xx error', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('{"error":"invalid_token"}', { status: 400 }));
    const params = createParams({ fetch: mockFetch });

    // Act & Assert - Should not throw — fire-and-forget behavior
    await expect(revokeTokens(params)).resolves.toBeUndefined();

    expect(mockFetch).toHaveBeenCalledTimes(2);
  });
});

describe('revokeTokens — edge cases', () => {
  it('sends urlencoded body string, not JSON', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
    const params = createParams({ fetch: mockFetch });

    // Act
    await revokeTokens(params);

    // Verify Content-Type is application/x-www-form-urlencoded
    expect(mockFetch).toHaveBeenCalledWith(
      'https://auth.torii.dev/revoke',
      expect.objectContaining({
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- expect.stringContaining returns any by design
        body: expect.stringContaining('token='),
      }),
    );

    // Verify body is a string in urlencoded format
    const call = mockFetch.mock.calls[0];
    const options = call?.[1] as RequestInit;

    expect(options.body).toBeTypeOf('string');
    expect(options.body).toContain('token_type_hint=');
  });

  it('encodes special characters in token values', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
    // Token with special chars that need URL encoding
    const specialToken = 'token+with/special=chars&more';
    const params = createParams({
      fetch: mockFetch,
      accessToken: specialToken,
      refreshToken: undefined,
    });

    // Act
    await revokeTokens(params);

    // URLSearchParams should properly decode the token
    const callParams = getBodyParams(mockFetch, 0);

    // Assert
    expect(callParams.get('token')).toBe(specialToken);

    // Verify the raw body has URL encoding (prevents injection)
    expect(mockFetch).toHaveBeenCalledWith(
      'https://auth.torii.dev/revoke',
      expect.objectContaining({
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- expect.stringMatching returns any by design
        body: expect.stringMatching(/%2B.*%2F.*%3D.*%26/), // +, /, =, &
      }),
    );
  });
});
