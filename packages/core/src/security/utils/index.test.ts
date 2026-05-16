/**
 * Security Utilities Test Suite
 *
 * Tests for timing-safe comparison, base64url encoding (RFC 7636),
 * and cookie parsing utilities.
 *
 * References:
 *   RFC 7636 §4.1 — Base64url encoding for PKCE
 *   RFC 4648 §5  — Base64 Encoding with URL and Filename Safe Alphabet
 *   RFC 6265bis  — Cookie parsing requirements
 */

import { describe, it, expect, expectTypeOf } from 'vitest';
import { escapeRegex, extractCookieValue, base64urlEncode, base64urlDecode, timingSafeEqual } from './index.js';

// ─── escapeRegex ──────────────────────────────────────────────────────────────

describe(escapeRegex, () => {
  it('escapes all regex metacharacters', () => {
    // Arrange
    const input = '.*+?^${}()|[]\\';

    // Act
    const escaped = escapeRegex(input);

    // Assert
    expect(() => new RegExp(escaped)).not.toThrow();

    const regex = new RegExp(escaped);

    expect(regex.test(input)).toBe(true);
    expect(regex.test('different')).toBe(false);
  });

  it('escapes period (.) to match literal dot, not any character', () => {
    // Arrange
    const escaped = escapeRegex('.');
    const regex = new RegExp(escaped);

    // Act & Assert
    expect(regex.test('.')).toBe(true);
    expect(regex.test('x')).toBe(false);
  });

  it('escapes asterisk (*) to prevent greedy matching', () => {
    // Arrange
    const escaped = escapeRegex('*');
    const regex = new RegExp(escaped);

    // Act & Assert
    expect(regex.test('*')).toBe(true);
    expect(regex.test('xxx')).toBe(false);
  });

  it('handles strings with no special characters', () => {
    // Arrange
    const input = 'simple-cookie_name123';

    // Act
    const escaped = escapeRegex(input);

    // Arrange
    expect(escaped).toBe(input);
  });

  it('handles empty string', () => {
    // Assert
    expect(escapeRegex('')).toBe('');
  });

  it('handles backslash correctly', () => {
    // Arrange
    const escaped = escapeRegex('\\');

    // Assert
    expect(escaped).toBe('\\\\');
    expect(new RegExp(escaped).test('\\')).toBe(true);
  });
});

// ─── extractCookieValue ───────────────────────────────────────────────────────

describe(extractCookieValue, () => {
  it('extracts cookie value from simple header', () => {
    // Act
    const result = extractCookieValue('session=abc123', 'session');

    // Assert
    expect(result).toBe('abc123');
  });

  it('extracts cookie from header with multiple cookies', () => {
    // Arrange
    const header = 'foo=bar; session=xyz789; other=value';

    // Act & Assert
    expect(extractCookieValue(header, 'session')).toBe('xyz789');
  });

  it('handles cookie at start of header', () => {
    // Arrange
    const header = 'target=first; other=second';

    // Act & Assert
    expect(extractCookieValue(header, 'target')).toBe('first');
  });

  it('handles cookie at end of header', () => {
    // Arrange
    const header = 'other=value; target=last';

    // Act & Assert
    expect(extractCookieValue(header, 'target')).toBe('last');
  });

  it('returns null when cookie not found', () => {
    // Assert
    expect(extractCookieValue('foo=bar', 'missing')).toBeNull();
  });

  it('returns null for empty header', () => {
    // Assert
    expect(extractCookieValue('', 'any')).toBeNull();
  });

  it('does not match partial cookie names', () => {
    // Arrange
    const header = 'session-admin=evil';

    // Act & Assert
    expect(extractCookieValue(header, 'session')).toBeNull();
  });

  it('handles __Host- prefixed cookies (RFC 6265bis)', () => {
    // Arrange
    const header = '__Host-session=secure-value';

    // Act & Assert
    expect(extractCookieValue(header, '__Host-session')).toBe('secure-value');
  });

  it('handles cookie names with special characters via escapeRegex', () => {
    // Arrange
    const header = '__Host-app.session=value123';

    // Act & Assert
    expect(extractCookieValue(header, '__Host-app.session')).toBe('value123');
  });

  it('does not execute regex metacharacters in cookie name', () => {
    // Arrange
    const header = 'safe-cookie=safe; dangerous.*=attack';

    // Act & Assert
    expect(extractCookieValue(header, 'dangerous.*')).toBe('attack');
  });

  it('handles cookie values with = character (not split on it)', () => {
    // Arrange
    const header = 'token=base64==';

    // Act & Assert
    expect(extractCookieValue(header, 'token')).toBe('base64==');
  });

  it('handles spaces around cookie separators', () => {
    // Arrange
    const header = 'a=1;   b=2  ;c=3';

    // Act & Assert
    expect(extractCookieValue(header, 'b')).toBe('2  ');
  });
});

// ─── base64urlEncode ──────────────────────────────────────────────────────────

describe(base64urlEncode, () => {
  it('returns a string', () => {
    // Act
    const result = base64urlEncode(new Uint8Array([1, 2, 3]));

    // Assert
    expectTypeOf(result).toBeString();
  });

  it('uses URL-safe alphabet (- and _ instead of + and /)', () => {
    // Arrange
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf]);

    // Act
    const result = base64urlEncode(bytes);

    // Assert
    expect(result).not.toMatch(/[+/]/);
    expect(result).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it.each([
    { bytes: new Uint8Array([1]), description: '1 byte' },
    { bytes: new Uint8Array([1, 2]), description: '2 bytes' },
    { bytes: new Uint8Array([1, 2, 3, 4]), description: '4 bytes' },
  ])('removes padding (=) per RFC 7636 §4.1 - $description', ({ bytes }) => {
    // Act
    const result = base64urlEncode(bytes);

    // Assert
    expect(result).not.toMatch(/=/);
  });

  it('handles empty array', () => {
    expect(base64urlEncode(new Uint8Array([]))).toBe('');
  });

  it('produces URL-safe characters per RFC 7636', () => {
    // Arrange
    const bytes = new Uint8Array(32).map((_, i) => i);

    // Act
    const result = base64urlEncode(bytes);

    // Assert
    expect(result).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('encodes single byte correctly', () => {
    // Act
    const result = base64urlEncode(new Uint8Array([0x41]));

    // Assert
    expect(result).toBe('QQ');
  });

  it('round-trips with base64urlDecode', () => {
    // Arrange
    const original = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128]);

    // Act
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);

    // Assert
    expect(decoded).toStrictEqual(original);
  });
});

describe(base64urlDecode, () => {
  it('returns Uint8Array', () => {
    // Act
    const result = base64urlDecode('AQID');

    // Assert
    expectTypeOf(result).toEqualTypeOf<Uint8Array>();
  });

  it('decodes URL-safe base64 (- and _)', () => {
    // Arrange
    const encoded = 'AQID_-A';

    // Act
    const decoded = base64urlDecode(encoded);

    // Assert
    expect(decoded).toBeInstanceOf(Uint8Array);
  });

  it('handles unpadded input per RFC 7636', () => {
    const unpadded = 'AQID';

    // Act and Assert
    expect(() => base64urlDecode(unpadded)).not.toThrow();
  });

  it('handles empty string', () => {
    // Act
    const result = base64urlDecode('');

    // Assert
    expect(result).toStrictEqual(new Uint8Array([]));
  });

  it.each(['SGVsbG8gV29ybGQ', 'AQIDBA', 'YQ', '_w'])('round-trips with base64urlEncode - %s', (encoded) => {
    // Act
    const decoded = base64urlDecode(encoded);
    const reEncoded = base64urlEncode(decoded);

    // Assert
    expect(reEncoded).toBe(encoded);
  });

  it('decodes single character', () => {
    // Act
    const result = base64urlDecode('QQ');

    // Assert
    expect(result).toStrictEqual(new Uint8Array([0x41]));
  });

  it.each([
    { input: 'YQ', expected: new Uint8Array([0x61]), description: '1 byte (unpadded)' },
    { input: 'YWI', expected: new Uint8Array([0x61, 0x62]), description: '2 bytes (unpadded)' },
    { input: 'YWJj', expected: new Uint8Array([0x61, 0x62, 0x63]), description: '3 bytes (no padding needed)' },
  ])('handles various padding scenarios - $description', ({ input, expected }) => {
    // Act
    const result = base64urlDecode(input);

    // Assert
    expect(result).toStrictEqual(expected);
  });
});

describe(timingSafeEqual, () => {
  it('returns a Promise<boolean>', () => {
    // Act
    const result = timingSafeEqual('a', 'a');

    // Assert
    expectTypeOf(result).toEqualTypeOf<Promise<boolean>>();
  });

  it('returns true for identical strings', async () => {
    // Act & Assert
    await expect(timingSafeEqual('hello', 'hello')).resolves.toBe(true);
  });

  it('returns true for identical long strings', async () => {
    // Arrange
    const str = 'a'.repeat(1000);

    // Act & Assert
    await expect(timingSafeEqual(str, str)).resolves.toBe(true);
  });

  it('returns false for different strings', async () => {
    // Act & Assert
    await expect(timingSafeEqual('hello', 'world')).resolves.toBe(false);
  });

  it('returns false for strings differing by one character', async () => {
    // Act & Assert
    await expect(timingSafeEqual('hello', 'hallo')).resolves.toBe(false);
  });

  it('returns false for different length strings', async () => {
    // Act & Assert
    await expect(timingSafeEqual('short', 'very-long-string')).resolves.toBe(false);
  });

  it('returns false for empty vs non-empty', async () => {
    // Act & Assert
    await expect(timingSafeEqual('', 'x')).resolves.toBe(false);
  });

  it('returns true for two empty strings', async () => {
    // Act & Assert
    await expect(timingSafeEqual('', '')).resolves.toBe(true);
  });

  it('handles Unicode strings correctly', async () => {
    // Act & Assert
    await expect(timingSafeEqual('😀', '😀')).resolves.toBe(true);
    await expect(timingSafeEqual('😀', '😁')).resolves.toBe(false);
  });

  it('handles special characters', async () => {
    // Arrange
    const str = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    // Act & Assert
    await expect(timingSafeEqual(str, str)).resolves.toBe(true);
  });
});
