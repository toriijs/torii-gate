/**
 * Login Test Suite
 *
 * RFC 9700  — §4: Authorization Code + PKCE
 * RFC 9700  — §4.7: state and nonce requirements
 */

import { describe, it, expect } from 'vitest';
import { PKCE_METHOD, generateCodeChallenge } from '../../src/security/pkce.js';
import { TestPendingStore } from '../../tests/fixtures/pending-store.js';
import { buildLoginUrl } from './login.js';

const BASE_CONFIG = {
  authorizationEndpoint: 'https://auth.torii.dev/realms/test/protocol/openid-connect/auth',
  clientId: 'my-client',
  redirectUri: 'https://app.torii.dev/auth/callback',
  scopes: ['openid', 'profile', 'email'],
};

describe('buildLoginUrl — authorization URL', () => {
  it('returns a valid HTTPS URL', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    // Assert
    expect(() => new URL(redirectUrl)).not.toThrow();
    expect(redirectUrl).toMatch(/^https:\/\//);
  });

  it('sets response_type=code — Authorization Code flow only', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    // Assert
    expect(new URL(redirectUrl).searchParams.get('response_type')).toBe('code');
  });

  it('includes client_id', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    // Assert
    expect(new URL(redirectUrl).searchParams.get('client_id')).toBe(BASE_CONFIG.clientId);
  });

  it('includes redirect_uri', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    // Assert
    expect(new URL(redirectUrl).searchParams.get('redirect_uri')).toBe(BASE_CONFIG.redirectUri);
  });

  it('joins scopes with spaces', async () => {
    // Arrange
    const store = new TestPendingStore();
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    // Assert
    expect(new URL(redirectUrl).searchParams.get('scope')).toBe('openid profile email');
  });
});

describe('buildLoginUrl — PKCE', () => {
  it('includes code_challenge in the URL', async () => {
    // Arrange
    const store = new TestPendingStore();
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    // Assert
    expect(new URL(redirectUrl).searchParams.get('code_challenge')).toBeDefined();
  });

  it('sets code_challenge_method=S256 — plain never used', async () => {
    // Arrange
    const store = new TestPendingStore();
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);
    const method = new URL(redirectUrl).searchParams.get('code_challenge_method');

    // Assert
    expect(method).toBe(PKCE_METHOD);
    expect(method).toBe('S256');
  });

  it('code_challenge is different on every call — derived from unique verifier', async () => {
    // Act
    const [r1, r2] = await Promise.all([buildLoginUrl(BASE_CONFIG, new TestPendingStore()), buildLoginUrl(BASE_CONFIG, new TestPendingStore())]);
    const c1 = new URL(r1.redirectUrl).searchParams.get('code_challenge');
    const c2 = new URL(r2.redirectUrl).searchParams.get('code_challenge');

    // Assert
    expect(c1).not.toBe(c2);
  });

  it('code_challenge is the S256 hash of the stored codeVerifier', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    const url = new URL(redirectUrl);
    const state: string = url.searchParams.get('state')!;
    const challenge: string = url.searchParams.get('code_challenge')!;

    // Retrieve the stored pending auth (single-use — consumed here)
    const pending = await store.get(state);

    // Assert
    expect(pending).not.toBeNull();

    const derived = await generateCodeChallenge(pending!.codeVerifier);

    expect(derived).toBe(challenge);
  });
});

describe('buildLoginUrl — state', () => {
  it('includes state in the URL', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    // Assert
    expect(new URL(redirectUrl).searchParams.get('state')).toBeDefined();
  });

  it('state in URL matches the state stored in the pendingStore', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    const urlState: string = new URL(redirectUrl).searchParams.get('state')!;
    // Retrieve by the state key — proves they match
    const pending = await store.get(urlState);

    // Assert
    expect(pending).not.toBeNull();
    expect(pending!.state).toBe(urlState);
  });

  it('generates unique state on every call', async () => {
    // Act
    const [r1, r2] = await Promise.all([buildLoginUrl(BASE_CONFIG, new TestPendingStore()), buildLoginUrl(BASE_CONFIG, new TestPendingStore())]);
    const s1 = new URL(r1.redirectUrl).searchParams.get('state');
    const s2 = new URL(r2.redirectUrl).searchParams.get('state');

    // Assert
    expect(s1).not.toBe(s2);
  });
});

describe('buildLoginUrl — nonce', () => {
  it('includes nonce in the URL', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    // Assert
    expect(new URL(redirectUrl).searchParams.get('nonce')).toBeDefined();
  });

  it('nonce in URL differs on every call', async () => {
    // Act
    const [r1, r2] = await Promise.all([buildLoginUrl(BASE_CONFIG, new TestPendingStore()), buildLoginUrl(BASE_CONFIG, new TestPendingStore())]);
    const n1 = new URL(r1.redirectUrl).searchParams.get('nonce');
    const n2 = new URL(r2.redirectUrl).searchParams.get('nonce');

    // Assert
    expect(n1).not.toBe(n2);
  });

  it('nonce sent in URL is stored in pendingStore (not its hash)', async () => {
    // Arrange
    // The raw nonce goes to the provider in the URL and to the ID token.
    // TestPendingStore stores the raw nonce inside the PendingAuth entry.
    // (Hashing is the CookiePendingStore's concern for the pkce cookie.)
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    const urlState: string = new URL(redirectUrl).searchParams.get('state')!;
    const urlNonce: string = new URL(redirectUrl).searchParams.get('nonce')!;
    const pending = await store.get(urlState);

    // Assert
    expect(pending!.nonce).toBe(urlNonce);
  });
});

describe('buildLoginUrl — pendingStore', () => {
  it('stores a PendingAuth entry keyed by state', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    const state: string = new URL(redirectUrl).searchParams.get('state')!;
    const pending = await store.get(state);

    // Assert
    expect(pending).not.toBeNull();
    expect(pending!.codeVerifier).toBeDefined();
    expect(pending!.nonce).toBeDefined();
    expect(pending!.state).toBe(state);
  });

  it('pendingAuth expiresAt is in the future', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    const state: string = new URL(redirectUrl).searchParams.get('state')!;
    const pending = await store.get(state);

    expect(pending!.expiresAt).toBeGreaterThan(Date.now());
  });

  it('returns headers for the login redirect response', async () => {
    // TestPendingStore returns empty headers (nothing to set on the response)
    // CookiePendingStore would return { 'set-cookie': '...' }
    const store = new TestPendingStore();
    const { headers } = await buildLoginUrl(BASE_CONFIG, store);

    expect(headers).toBeTypeOf('object');
  });

  it('pendingStore entry is consumed on get — single use', async () => {
    // Arrange
    const store = new TestPendingStore();

    // Act
    const { redirectUrl } = await buildLoginUrl(BASE_CONFIG, store);

    const state: string = new URL(redirectUrl).searchParams.get('state')!;

    const first = await store.get(state);
    const second = await store.get(state); // already consumed

    expect(first).not.toBeNull();
    expect(second).toBeNull(); // single-use enforced
  });
});
