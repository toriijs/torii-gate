/**
 * OIDC Discovery Test Suite
 *
 * OpenID Connect Discovery 1.0
 * RFC 8414 — OAuth 2.0 Authorization Server Metadata
 */

import { describe, it, expect, vi } from 'vitest';
import { discoverIssuer, DiscoveryError } from './discovery.js';

const ISSUER = 'https://auth.torii.dev/realms/test';

const VALID_METADATA = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/protocol/openid-connect/auth`,
  token_endpoint: `${ISSUER}/protocol/openid-connect/token`,
  revocation_endpoint: `${ISSUER}/protocol/openid-connect/revoke`,
  end_session_endpoint: `${ISSUER}/protocol/openid-connect/logout`,
  jwks_uri: `${ISSUER}/protocol/openid-connect/certs`,
  response_types_supported: ['code'],
  code_challenge_methods_supported: ['S256'],
};

function mockFetch(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    }),
  );
}

describe('discoverIssuer — valid metadata', () => {
  it('returns parsed metadata on success', async () => {
    // Act
    const metadata = await discoverIssuer(ISSUER, {
      fetch: mockFetch(VALID_METADATA),
    });

    // Assert
    expect(metadata.issuer).toBe(ISSUER);
    expect(metadata.authorization_endpoint).toBe(VALID_METADATA.authorization_endpoint);
    expect(metadata.token_endpoint).toBe(VALID_METADATA.token_endpoint);
  });

  it('constructs the correct discovery URL', async () => {
    // Arrange
    const fetchFn = mockFetch(VALID_METADATA);

    // Act
    await discoverIssuer(ISSUER, { fetch: fetchFn });

    // Assert
    expect(fetchFn).toHaveBeenCalledWith(
      `${ISSUER}/.well-known/openid-configuration`,
      expect.objectContaining({
        headers: { accept: 'application/json' },
      }),
    );
  });

  it('handles issuer URL with trailing slash', async () => {
    // Arrange
    const issuerWithSlash = `${ISSUER}/`;
    const metadata = { ...VALID_METADATA, issuer: issuerWithSlash };
    const fetchFn = mockFetch(metadata);

    // Act
    const result = await discoverIssuer(issuerWithSlash, { fetch: fetchFn });

    // Assert
    expect(fetchFn).toHaveBeenCalledWith(
      `${issuerWithSlash}.well-known/openid-configuration`,
      expect.objectContaining({
        headers: { accept: 'application/json' },
      }),
    );
    expect(result.issuer).toBe(issuerWithSlash);
  });

  it('includes optional fields when present', async () => {
    // Act
    const metadata = await discoverIssuer(ISSUER, {
      fetch: mockFetch(VALID_METADATA),
    });

    // Assert
    expect(metadata.revocation_endpoint).toBe(VALID_METADATA.revocation_endpoint);
    expect(metadata.end_session_endpoint).toBe(VALID_METADATA.end_session_endpoint);
    expect(metadata.jwks_uri).toBe(VALID_METADATA.jwks_uri);
  });

  it('optional fields are undefined when absent', async () => {
    // Arrange
    const minimal = {
      issuer: ISSUER,
      authorization_endpoint: VALID_METADATA.authorization_endpoint,
      token_endpoint: VALID_METADATA.token_endpoint,
    };

    // Act
    const metadata = await discoverIssuer(ISSUER, {
      fetch: mockFetch(minimal),
    });

    // Arrange
    expect(metadata.revocation_endpoint).toBeUndefined();
    expect(metadata.end_session_endpoint).toBeUndefined();
  });
});

describe('discoverIssuer — HTTPS enforcement', () => {
  it('throws DiscoveryError for HTTP issuer URL', async () => {
    // Act & Assert
    await expect(
      discoverIssuer('http://auth.torii.dev', {
        fetch: mockFetch(VALID_METADATA),
      }),
    ).rejects.toThrow(DiscoveryError);
  });

  it('error code is invalid_issuer_url for HTTP', async () => {
    // Act & Assert
    await expect(
      discoverIssuer('http://auth.torii.dev', {
        fetch: mockFetch(VALID_METADATA),
      }),
    ).rejects.toThrow(DiscoveryError);
    await expect(
      discoverIssuer('http://auth.torii.dev', {
        fetch: mockFetch(VALID_METADATA),
      }),
    ).rejects.toMatchObject({ code: 'invalid_issuer_url' });
  });
});

describe('discoverIssuer — issuer mismatch', () => {
  it('throws when returned issuer does not match requested issuer', async () => {
    // Arrange
    const tampered = { ...VALID_METADATA, issuer: 'https://evil.attacker.com' };

    // Act & Assert
    await expect(discoverIssuer(ISSUER, { fetch: mockFetch(tampered) })).rejects.toThrow(DiscoveryError);
  });

  it('error code is issuer_mismatch', async () => {
    // Arrange
    const tampered = { ...VALID_METADATA, issuer: 'https://evil.attacker.com' };

    // Act & Assert
    await expect(discoverIssuer(ISSUER, { fetch: mockFetch(tampered) })).rejects.toMatchObject({ code: 'issuer_mismatch' });
  });
});

describe('discoverIssuer — missing required fields', () => {
  it('throws when authorization_endpoint is missing', async () => {
    // Arrange
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { authorization_endpoint: _, ...noAuth } = VALID_METADATA;

    // Act & Assert
    await expect(discoverIssuer(ISSUER, { fetch: mockFetch(noAuth) })).rejects.toThrow(DiscoveryError);
  });

  it('throws when token_endpoint is missing', async () => {
    // Arrange
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { token_endpoint: _, ...noToken } = VALID_METADATA;

    // Act & Assert
    await expect(discoverIssuer(ISSUER, { fetch: mockFetch(noToken) })).rejects.toThrow(DiscoveryError);
  });

  it('error code is missing_field', async () => {
    // Arrange
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { authorization_endpoint: _, ...noAuth } = VALID_METADATA;

    // Act & Assert
    await expect(discoverIssuer(ISSUER, { fetch: mockFetch(noAuth) })).rejects.toMatchObject({ code: 'missing_field' });
  });
});

describe('discoverIssuer — HTTP errors', () => {
  it('throws on HTTP 404', async () => {
    // Act & Assert
    await expect(discoverIssuer(ISSUER, { fetch: mockFetch('Not Found', 404) })).rejects.toThrow(DiscoveryError);
  });

  it('throws on HTTP 500', async () => {
    // Act & Assert
    await expect(discoverIssuer(ISSUER, { fetch: mockFetch('Server Error', 500) })).rejects.toThrow(DiscoveryError);
  });

  it('error code is http_error', async () => {
    // Act & Assert
    await expect(discoverIssuer(ISSUER, { fetch: mockFetch('error', 503) })).rejects.toMatchObject({ code: 'http_error' });
  });
});

describe('discoverIssuer — network failure', () => {
  it('throws when fetch rejects', async () => {
    // Arrange
    const fetchFn = vi.fn().mockRejectedValue(new Error('network timeout'));

    // Act & Assert
    await expect(discoverIssuer(ISSUER, { fetch: fetchFn })).rejects.toThrow(DiscoveryError);
  });

  it('error code is fetch_failed', async () => {
    // Arrange
    const fetchFn = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    // Act & Assert
    await expect(discoverIssuer(ISSUER, { fetch: fetchFn })).rejects.toMatchObject({ code: 'fetch_failed' });
  });
});
