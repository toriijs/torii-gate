import { describe, it, expect, vi } from 'vitest';
import { exchangeToken, type TokenExchangeParams } from './token-exchange';

const TEST_TOKEN_ENDPOINT = 'https://torii.dev/token';
const TEST_ERROR_CONTEXT = 'Test exchange';

function createParams(fetchMock: ReturnType<typeof vi.fn>): TokenExchangeParams {
  return {
    tokenEndpoint: TEST_TOKEN_ENDPOINT,
    body: new URLSearchParams({ grant_type: 'authorization_code' }),
    fetch: fetchMock as typeof fetch,
    errorContext: TEST_ERROR_CONTEXT,
  };
}

describe(exchangeToken, () => {
  it('successfully exchanges tokens with valid response', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          access_token: 'test_access_token',
          expires_in: 3600,
          refresh_token: 'test_refresh_token',
        }),
    });
    const params = createParams(mockFetch);

    // Act
    const result = await exchangeToken(params);

    // Assert
    expect(result).toStrictEqual({
      access_token: 'test_access_token',
      expires_in: 3600,
      refresh_token: 'test_refresh_token',
    });
    expect(mockFetch).toHaveBeenCalledWith(TEST_TOKEN_ENDPOINT, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body: params.body.toString(),
    });
  });

  it('throws error when response is not ok', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      text: () => Promise.resolve('Invalid grant'),
    });

    const params = createParams(mockFetch);

    // Act & Assert
    await expect(exchangeToken(params)).rejects.toThrow('Test exchange failed: 400 Bad Request — Invalid grant');
  });

  it('throws error when response is missing access_token', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          expires_in: 3600,
        }),
    });

    const params = createParams(mockFetch);

    // Act & Assert
    await expect(exchangeToken(params)).rejects.toThrow('Test exchange response missing access_token');
  });

  it('handles error when text() fails', async () => {
    // Arrange
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      text: () => Promise.reject(new Error('Failed to read response')),
    });

    const params = createParams(mockFetch);

    // Act & Assert
    await expect(exchangeToken(params)).rejects.toThrow('Test exchange failed: 500 Internal Server Error — unknown error');
  });
});
