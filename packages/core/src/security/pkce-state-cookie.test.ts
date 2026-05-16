/**
 * PKCE State Cookie Test Suite
 *
 * Tests the stateless PKCE state mechanism that replaces
 * module-scope Maps for serverless / scale-to-zero compatibility.
 */

import { describe, it, expect, expectTypeOf } from 'vitest';
import { buildPkceStateCookie, readPkceStateCookie, clearPkceStateCookie, type PkceStateCookieData } from './pkce-state-cookie.js';

const SECRET = 'test-secret-minimum-32-characters!!';

const VALID_DATA: PkceStateCookieData = {
  codeVerifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
  nonce: 'abc123nonce',
  state: 'xyz789state',
  expiresAt: Date.now() + 600_000,
};

describe(buildPkceStateCookie, () => {
  it('returns a Set-Cookie header string', async () => {
    // Act
    const header = await buildPkceStateCookie(VALID_DATA, { secret: SECRET });

    // Assert
    expect(header).toBeTypeOf('string');
    expect(header).toContain('__Host-torii-pkce=');

    expectTypeOf(header).toBeString();
  });

  it('sets SameSite=Lax — required for provider redirect callback', async () => {
    // Act
    const header = await buildPkceStateCookie(VALID_DATA, { secret: SECRET });

    // Assert
    expect(header).toMatch(/SameSite=Lax/i);
  });

  it('sets HttpOnly', async () => {
    // Act
    const header = await buildPkceStateCookie(VALID_DATA, { secret: SECRET });

    // Assert
    expect(header).toMatch(/HttpOnly/i);
  });

  it('sets Secure', async () => {
    // Act
    const header = await buildPkceStateCookie(VALID_DATA, { secret: SECRET });

    // Assert
    expect(header).toMatch(/Secure/i);
  });

  it('sets Path=/', async () => {
    // Act
    const header = await buildPkceStateCookie(VALID_DATA, { secret: SECRET });

    // Assert
    expect(header).toMatch(/Path=\//i);
  });

  it('sets Max-Age=600 by default', async () => {
    // Act
    const header = await buildPkceStateCookie(VALID_DATA, { secret: SECRET });

    // Assert
    expect(header).toContain('Max-Age=600');
  });

  it('respects custom maxAge', async () => {
    // Act
    const header = await buildPkceStateCookie(VALID_DATA, {
      secret: SECRET,
      maxAge: 300,
    });

    // Assert
    expect(header).toContain('Max-Age=300');
  });

  it('value is opaque — not readable JSON', async () => {
    // Arrange
    const header = await buildPkceStateCookie(VALID_DATA, { secret: SECRET });
    const value = header.split(';')[0]!.split('=').slice(1).join('=');

    // Act & Assert
    expect(() => {
      JSON.parse(value);
    }).toThrow(SyntaxError);
  });
});

describe(readPkceStateCookie, () => {
  it('round-trips: build then read returns original data', async () => {
    // Arrange
    const header = await buildPkceStateCookie(VALID_DATA, { secret: SECRET });
    // Extract cookie value from Set-Cookie header and build a Cookie header
    const value = header.split(';')[0]!;
    const cookieHeader = value;

    // Act
    const result = await readPkceStateCookie(cookieHeader, SECRET);

    // Assert
    expect(result).not.toBeNull();
    expect(result?.codeVerifier).toBe(VALID_DATA.codeVerifier);
    expect(result?.nonce).toBe(VALID_DATA.nonce);
    expect(result?.state).toBe(VALID_DATA.state);
  });

  it('returns null when cookie is missing', async () => {
    // Act
    const result = await readPkceStateCookie('', SECRET);

    // Assert
    expect(result).toBeNull();
  });

  it('returns null when cookie is absent from header', async () => {
    // Act
    const result = await readPkceStateCookie('other-cookie=value', SECRET);

    // Assert
    expect(result).toBeNull();
  });

  it('returns null for tampered value', async () => {
    // Arrange
    const header = await buildPkceStateCookie(VALID_DATA, { secret: SECRET });
    const value = header.split(';')[0]!.split('=').slice(1).join('=');
    const tampered = `__Host-torii-pkce=${value.slice(0, -5)}AAAAA`;

    // Act
    const result = await readPkceStateCookie(tampered, SECRET);

    // Assert
    expect(result).toBeNull();
  });

  it('returns null for expired cookie', async () => {
    // Arrange
    const expired: PkceStateCookieData = {
      ...VALID_DATA,
      expiresAt: Date.now() - 1,
    };
    const header = await buildPkceStateCookie(expired, { secret: SECRET });
    const value = header.split(';')[0]!;

    // Act
    const result = await readPkceStateCookie(value, SECRET);

    // Assert
    expect(result).toBeNull();
  });

  it('returns null when decrypted with wrong secret', async () => {
    // Arrange
    const header = await buildPkceStateCookie(VALID_DATA, { secret: SECRET });
    const value = header.split(';')[0]!;

    // Act
    const result = await readPkceStateCookie(value, 'wrong-secret-min-32-characters!!!');

    // Assert
    expect(result).toBeNull();
  });

  it('is stateless — no server-side store needed', async () => {
    // Arrange - Two separate encrypt/decrypt calls with no shared state
    const header1 = await buildPkceStateCookie(VALID_DATA, { secret: SECRET });
    const header2 = await buildPkceStateCookie({ ...VALID_DATA, state: 'different-state' }, { secret: SECRET });

    const v1 = header1.split(';')[0]!;
    const v2 = header2.split(';')[0]!;

    // Act
    const r1 = await readPkceStateCookie(v1, SECRET);
    const r2 = await readPkceStateCookie(v2, SECRET);

    // Assert
    expect(r1?.state).toBe('xyz789state');
    expect(r2?.state).toBe('different-state');
  });
});

describe(clearPkceStateCookie, () => {
  it('sets Max-Age=0', () => {
    // Act
    const header = clearPkceStateCookie();

    // Assert
    expect(header).toContain('Max-Age=0');
  });

  it('sets empty value', () => {
    // Act
    const header = clearPkceStateCookie();

    // Assert
    expect(header).toMatch(/__Host-torii-pkce=;|__Host-torii-pkce=""/);
  });

  it('retains security flags', () => {
    // Act
    const header = clearPkceStateCookie();

    // Assert
    expect(header).toMatch(/Secure/i);
    expect(header).toMatch(/HttpOnly/i);
    expect(header).toMatch(/Path=\//i);
    expect(header).toMatch(/SameSite=Lax/i);
  });
});
