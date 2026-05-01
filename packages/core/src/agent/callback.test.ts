/**
 * OAuth Agent Callback Test Suite
 *
 * RFC 9700  — Section 4: Authorization Code callback processing
 * RFC 9207  — iss parameter validation (mix-up attack)
 * RFC 7636  — PKCE code_verifier submission
 * OpenID Connect Core — nonce validation in ID token
 *
 * The callback handler is the most security-critical path in the BFF.
 * Every validation must pass before the authorization code is exchanged.
 *
 * Validation order (fail-fast):
 *   1. error parameter check     — provider rejected the request
 *   2. state presence            — must be present in params
 *   3. pending auth lookup       — retrieved from PendingAuthStore (single-use)
 *   4. iss validation            — RFC 9207 mix-up defence
 *   5. code presence             — authorization code must exist
 *   6. token exchange            — PKCE code_verifier submitted
 *   7. nonce validation          — ID token replay prevention
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { CallbackError, handleCallback, type CallbackContext } from '../../src/agent/callback';
import { generateState } from '../../src/security/state';
import { generateNonce } from '../../src/security/nonce';
import { generateCodeVerifier } from '../../src/security/pkce';
import { base64urlEncode } from '../../src/security/utils/index.js';
import type { JwksKeySource } from '../../src/security/jwt.js';
import { TestPendingStore } from '../../tests/fixtures/pending-store';
import { createMockFetch } from '../../tests/fixtures/fixtures.js';

interface JwkWithKid extends JsonWebKey {
  kid: string;
}

const ISSUER = 'https://auth.torii.dev/realms/test';
const CLIENT_ID = 'test-client';
const CLIENT_SECRET = 'test-secret';
const REDIRECT_URI = 'https://app.torii.dev/auth/callback';
const TOKEN_ENDPOINT = 'https://auth.torii.dev/realms/test/protocol/openid-connect/token';

const MOCK_TOKEN_RESPONSE = { access_token: 'mock-access-token', token_type: 'Bearer', expires_in: 3600 };

/**
 * Builds a valid CallbackContext with a fresh TestPendingStore already
 * populated with one pending auth entry.
 *
 * Returns the context, the state value (to include in params), the pendingStore
 * so tests can inspect or further manipulate it, and the mockFetch so tests
 * can override responses per-case.
 */
async function buildValidContext(): Promise<{
  context: CallbackContext;
  state: string;
  nonce: string;
  pendingStore: TestPendingStore;
  mockFetch: ReturnType<typeof createMockFetch>;
}> {
  const state = await generateState();
  const nonce = await generateNonce();
  const codeVerifier = await generateCodeVerifier();
  const expiresAt = Date.now() + 10_000;

  const pendingStore = new TestPendingStore();
  await pendingStore.set({ state, nonce, codeVerifier, expiresAt });

  const mockFetch = createMockFetch(MOCK_TOKEN_RESPONSE);

  const context: CallbackContext = {
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    pendingStore,
    tokenEndpoint: TOKEN_ENDPOINT,
    fetch: mockFetch,
    requireIdToken: false,
  };

  return { context, state, nonce, pendingStore, mockFetch };
}

describe('handleCallback — error parameter', () => {
  it('throws when authorization response contains an error parameter', async () => {
    // Arrange
    const { context } = await buildValidContext();
    const params = new URLSearchParams({
      error: 'access_denied',
      error_description: 'User denied access',
    });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow('access_denied');
  });

  it('throws for login_required error', async () => {
    // Arrange
    const { context } = await buildValidContext();
    const params = new URLSearchParams({ error: 'login_required' });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(CallbackError);
  });

  it('error check runs before state lookup — no pending store access needed', async () => {
    // Error is checked first — even an empty pendingStore is fine here

    // Arrange
    const emptyStore = new TestPendingStore();
    const context: CallbackContext = {
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
      pendingStore: emptyStore,
      tokenEndpoint: TOKEN_ENDPOINT,
    };
    const params = new URLSearchParams({ error: 'server_error' });

    // Act & Expect
    await expect(handleCallback(params, context)).rejects.toThrow('server_error');
  });
});

describe('handleCallback — state validation', () => {
  it('throws when state parameter is missing from callback', async () => {
    // Arrange
    const { context } = await buildValidContext();
    const params = new URLSearchParams({ code: 'auth-code-123', iss: ISSUER });

    // Act & Expect
    await expect(handleCallback(params, context)).rejects.toThrow(/state/i);
  });

  it('throws when state does not match any stored state — CSRF attempt', async () => {
    // Arrange
    const { context } = await buildValidContext();
    const params = new URLSearchParams({
      code: 'auth-code-123',
      state: 'tampered-state-value',
      iss: ISSUER,
    });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(/state/i);
  });

  it('throws on state replay — second callback with same state', async () => {
    // Arrange
    const { context, state } = await buildValidContext();

    // First callback — consumes the state from the store (single-use)
    const params1 = new URLSearchParams({ code: 'code-1', state, iss: ISSUER });
    await handleCallback(params1, context);

    // Second callback — state already consumed by TestPendingStore
    const params2 = new URLSearchParams({ code: 'code-2', state, iss: ISSUER });

    // Act & Assert
    await expect(handleCallback(params2, context)).rejects.toThrow(/state/i);
  });

  it('throws when pending auth has expired', async () => {
    // Arrange
    const state = await generateState();
    const nonce = await generateNonce();
    const codeVerifier = await generateCodeVerifier();

    const pendingStore = new TestPendingStore();
    // Store with expiresAt in the past
    await pendingStore.set({ state, nonce, codeVerifier, expiresAt: Date.now() - 1 });

    const context: CallbackContext = {
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
      pendingStore,
      tokenEndpoint: TOKEN_ENDPOINT,
    };

    const params = new URLSearchParams({ code: 'code', state, iss: ISSUER });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(/state/i);
  });
});

describe('handleCallback — iss validation (RFC 9207)', () => {
  it('throws when iss parameter is missing — potential mix-up attack', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const params = new URLSearchParams({
      code: 'auth-code-123',
      state,
      // No iss
    });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(/iss/i);
  });

  it('throws when iss does not match expected issuer — mix-up attack', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const params = new URLSearchParams({
      code: 'auth-code-123',
      state,
      iss: 'https://evil.attacker.com/realms/evil',
    });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(/iss/i);
  });

  it('proceeds past iss check when iss matches expected issuer exactly', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const params = new URLSearchParams({
      code: 'auth-code-123',
      state,
      iss: ISSUER,
    });

    // Act - iss passes — token exchange succeeds with mock fetch
    const result = await handleCallback(params, context);

    expect(result.sessionData).toBeDefined();
    expect(result.sessionData.accessToken).toBe('mock-access-token');
  });
});

describe('handleCallback — authorization code', () => {
  it('throws when code parameter is missing from callback', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const params = new URLSearchParams({ state, iss: ISSUER });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(/code/i);
  });

  it('throws when code is an empty string', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const params = new URLSearchParams({ code: '', state, iss: ISSUER });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(/code/i);
  });
});

describe('handleCallback — return type contract', () => {
  it('returns a Promise — never returns a token synchronously', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const params = new URLSearchParams({ code: 'valid-code', state, iss: ISSUER });

    // Act
    const result = handleCallback(params, context);

    // Assert
    expect(result).toBeInstanceOf(Promise);

    await result;
  });

  it('all security validations run before token exchange', async () => {
    // Arrange
    // This test verifies ordering: a tampered state should throw with a state error,
    // not a token exchange error — state is checked (step 3) before token exchange (step 6)
    const { context } = await buildValidContext();
    const params = new URLSearchParams({
      code: 'valid-code',
      state: 'tampered',
      iss: ISSUER,
    });

    // Act & Assert - Must throw about state, not about network/token exchange
    await expect(handleCallback(params, context)).rejects.toThrow(/state/i);
  });

  it('token exchange uses configured fetch — mock is called with token endpoint', async () => {
    // Arrange
    const { context, state, mockFetch } = await buildValidContext();
    const params = new URLSearchParams({ code: 'auth-code', state, iss: ISSUER });

    // Act
    await handleCallback(params, context);

    // Assert
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockFetch).toHaveBeenCalledWith(TOKEN_ENDPOINT, expect.objectContaining({ method: 'POST' }));
  });

  it('throws when token exchange returns a non-OK response', async () => {
    // Arrange
    const { context, state, mockFetch } = await buildValidContext();
    mockFetch.mockResolvedValueOnce(new Response('Unauthorized', { status: 401 }));
    const params = new URLSearchParams({ code: 'auth-code', state, iss: ISSUER });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(/token exchange failed/i);
  });
});

describe('handleCallback — ID token verification (RFC 9700 §4.5.1)', () => {
  let rsaKeyPair: CryptoKeyPair;
  let rsaJwk: JwkWithKid;

  beforeAll(async () => {
    rsaKeyPair = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );
    const exported = await crypto.subtle.exportKey('jwk', rsaKeyPair.publicKey);
    rsaJwk = { ...exported, kid: 'test-key-id' };
  });

  async function buildIdToken(payload: Record<string, unknown>): Promise<string> {
    const header = { alg: 'RS256', kid: 'test-key-id', typ: 'JWT' };
    const headerB64 = base64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
    const payloadB64 = base64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', rsaKeyPair.privateKey, signingInput);
    const signatureB64 = base64urlEncode(new Uint8Array(signature));
    return `${headerB64}.${payloadB64}.${signatureB64}`;
  }

  function buildContextWithJwks(mockFetch: ReturnType<typeof createMockFetch>): CallbackContext {
    const keySource: JwksKeySource = {
      async getKey() {
        return crypto.subtle.importKey('jwk', rsaJwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
      },
    };

    return {
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
      pendingStore: new TestPendingStore(),
      tokenEndpoint: TOKEN_ENDPOINT,
      fetch: mockFetch,
      keySource,
      requireIdToken: true,
    };
  }

  it('verifies valid id_token signature and claims', async () => {
    // Arrange
    const nowSec = Math.floor(Date.now() / 1000);
    const nonce = await generateNonce();
    const idToken = await buildIdToken({
      iss: ISSUER,
      aud: CLIENT_ID,
      sub: 'user-123',
      exp: nowSec + 300,
      iat: nowSec,
      nonce,
    });

    const state = await generateState();
    const codeVerifier = await generateCodeVerifier();
    const pendingStore = new TestPendingStore();
    await pendingStore.set({ state, nonce, codeVerifier, expiresAt: Date.now() + 10000 });

    const mockFetch = createMockFetch({ ...MOCK_TOKEN_RESPONSE, id_token: idToken });
    const context = { ...buildContextWithJwks(mockFetch), pendingStore };

    const params = new URLSearchParams({ code: 'valid-code', state, iss: ISSUER });

    // Act
    const result = await handleCallback(params, context);

    // Assert
    expect(result.sessionData.idToken).toBe(idToken);
    expect(result.idTokenClaims).toBeDefined();
    expect(result.idTokenClaims?.sub).toBe('user-123');
  });

  it('throws when id_token signature is invalid', async () => {
    // Arrange
    const nowSec = Math.floor(Date.now() / 1000);
    const nonce = await generateNonce();
    let idToken = await buildIdToken({
      iss: ISSUER,
      aud: CLIENT_ID,
      exp: nowSec + 300,
      nonce,
    });

    // Tamper with signature
    const parts = idToken.split('.');
    const sigPart = parts[2] ?? '';
    const sigBytes = Uint8Array.from(atob(sigPart.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.codePointAt(0) ?? 0);
    const firstByte = sigBytes[0];
    // eslint-disable-next-line vitest/no-conditional-in-test
    if (firstByte !== undefined) {
      sigBytes[0] = firstByte ^ 0xff;
    }
    parts[2] = base64urlEncode(sigBytes);
    idToken = parts.join('.');

    const state = await generateState();
    const codeVerifier = await generateCodeVerifier();
    const pendingStore = new TestPendingStore();
    await pendingStore.set({ state, nonce, codeVerifier, expiresAt: Date.now() + 10000 });

    const mockFetch = createMockFetch({ ...MOCK_TOKEN_RESPONSE, id_token: idToken });
    const context = { ...buildContextWithJwks(mockFetch), pendingStore };

    const params = new URLSearchParams({ code: 'valid-code', state, iss: ISSUER });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(/verification failed/i);
  });

  it('throws when id_token is missing but required', async () => {
    // Arrange
    const state = await generateState();
    const nonce = await generateNonce();
    const codeVerifier = await generateCodeVerifier();
    const pendingStore = new TestPendingStore();
    await pendingStore.set({ state, nonce, codeVerifier, expiresAt: Date.now() + 10000 });

    const mockFetch = createMockFetch(MOCK_TOKEN_RESPONSE); // No id_token
    const context = { ...buildContextWithJwks(mockFetch), pendingStore, requireIdToken: true };

    const params = new URLSearchParams({ code: 'valid-code', state, iss: ISSUER });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(/missing id_token/i);
  });

  it('throws when id_token nonce does not match', async () => {
    // Arrange
    const nowSec = Math.floor(Date.now() / 1000);
    const storedNonce = await generateNonce();
    const wrongNonce = 'wrong-nonce-value';
    const idToken = await buildIdToken({
      iss: ISSUER,
      aud: CLIENT_ID,
      exp: nowSec + 300,
      nonce: wrongNonce,
    });

    const state = await generateState();
    const codeVerifier = await generateCodeVerifier();
    const pendingStore = new TestPendingStore();
    await pendingStore.set({ state, nonce: storedNonce, codeVerifier, expiresAt: Date.now() + 10000 });

    const mockFetch = createMockFetch({ ...MOCK_TOKEN_RESPONSE, id_token: idToken });
    const context = { ...buildContextWithJwks(mockFetch), pendingStore };

    const params = new URLSearchParams({ code: 'valid-code', state, iss: ISSUER });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(/nonce/i);
  });
});

// ─── redirect_uri validation (Phase 1.3) ──────────────────────────────────────

describe('handleCallback — redirect_uri exact match (RFC 9700 §2.1)', () => {
  it('accepts callback when request URL matches configured redirect_uri', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const request = new Request(REDIRECT_URI + '?code=abc&state=' + state + '&iss=' + encodeURIComponent(ISSUER));
    const contextWithRequest = { ...context, request };

    const params = new URLSearchParams({ code: 'abc', state, iss: ISSUER });

    // Act
    const result = await handleCallback(params, contextWithRequest);

    // Assert
    expect(result.sessionData).toBeDefined();
  });

  it('throws when request URL origin does not match redirect_uri', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const request = new Request('https://attacker.com/auth/callback?code=abc&state=' + state);
    const contextWithRequest = { ...context, request };

    const params = new URLSearchParams({ code: 'abc', state, iss: ISSUER });

    // Act & Assert
    await expect(handleCallback(params, contextWithRequest)).rejects.toThrow(/redirect_uri mismatch.*origin/i);
  });

  it('throws when request URL path does not match redirect_uri', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const request = new Request('https://app.torii.dev/auth/evil?code=abc&state=' + state);
    const contextWithRequest = { ...context, request };

    const params = new URLSearchParams({ code: 'abc', state, iss: ISSUER });

    // Act & Assert
    await expect(handleCallback(params, contextWithRequest)).rejects.toThrow(/redirect_uri mismatch.*path/i);
  });
});

describe('handleCallback — client_id echo (RFC 9700 §4.4)', () => {
  it('accepts when client_id parameter matches configured client_id', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const params = new URLSearchParams({ code: 'abc', state, iss: ISSUER, client_id: CLIENT_ID });

    // Act
    const result = await handleCallback(params, context);

    // Assert
    expect(result.sessionData).toBeDefined();
  });

  it('accepts when client_id parameter is absent (many providers do not echo)', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const params = new URLSearchParams({ code: 'abc', state, iss: ISSUER });

    // Act
    const result = await handleCallback(params, context);

    // Assert
    expect(result.sessionData).toBeDefined();
  });

  it('throws when client_id parameter does not match configured client_id', async () => {
    // Arrange
    const { context, state } = await buildValidContext();
    const params = new URLSearchParams({ code: 'abc', state, iss: ISSUER, client_id: 'wrong-client-id' });

    // Act & Assert
    await expect(handleCallback(params, context)).rejects.toThrow(/client_id echo mismatch/i);
  });
});
