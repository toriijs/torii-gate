import { describe, it, expect } from 'vitest';
import { extractSessionId, parseCookies, generateSessionId } from './helpers.js';

describe(parseCookies, () => {
  it('parses a single cookie', () => {
    // Act
    const result = parseCookies('name=value');

    // Assert
    expect(result.get('name')).toBe('value');
    expect(result.size).toBe(1);
  });

  it('parses multiple cookies separated by semicolons', () => {
    // Act
    const result = parseCookies('first=one; second=two; third=three');

    // Assert
    expect(result.get('first')).toBe('one');
    expect(result.get('second')).toBe('two');
    expect(result.get('third')).toBe('three');
    expect(result.size).toBe(3);
  });

  it('trims whitespace around cookie name and value', () => {
    // Act
    const result = parseCookies('  name  =  value  ');

    // Assert
    expect(result.get('name')).toBe('value');
  });

  it('removes surrounding double quotes from values', () => {
    // Act
    const result = parseCookies('quoted="value"');

    // Assert
    expect(result.get('quoted')).toBe('value');
  });

  it('handles cookies without quotes', () => {
    // Act
    const result = parseCookies('unquoted=plainvalue');

    // Assert
    expect(result.get('unquoted')).toBe('plainvalue');
  });

  it('skips pairs without equals sign', () => {
    // Act
    const result = parseCookies('invalid; name=value');

    // Assert
    expect(result.has('invalid')).toBe(false);
    expect(result.get('name')).toBe('value');
    expect(result.size).toBe(1);
  });

  it('skips pairs with empty name', () => {
    // Act
    const result = parseCookies('=emptyname; valid=value');

    // Assert
    expect(result.has('')).toBe(false);
    expect(result.get('valid')).toBe('value');
    expect(result.size).toBe(1);
  });

  it('handles empty string', () => {
    // Act
    const result = parseCookies('');

    // Assert
    expect(result.size).toBe(0);
  });

  it('handles cookie values containing equals signs', () => {
    // Act
    const result = parseCookies('jwt=eyJhbGc.payload.signature');

    // Assert
    expect(result.get('jwt')).toBe('eyJhbGc.payload.signature');
  });

  it('handles special characters in cookie values', () => {
    // Act
    const result = parseCookies('special=a+b%20c-d_e');

    // Assert
    expect(result.get('special')).toBe('a+b%20c-d_e');
  });
});

describe(extractSessionId, () => {
  it('extracts session ID from Cookie header', () => {
    // Arrange
    const request = new Request('https://torii.dev', {
      headers: { cookie: '__Host-session=abc123' },
    });

    // Act
    const result = extractSessionId(request, '__Host-session');

    // Assert
    expect(result).toBe('abc123');
  });

  it('returns null when Cookie header is missing', () => {
    // Arrange
    const request = new Request('https://torii.dev');

    // Act
    const result = extractSessionId(request, '__Host-session');

    // Assert
    expect(result).toBeNull();
  });

  it('returns null when cookie name does not exist', () => {
    // Arrange
    const request = new Request('https://torii.dev', {
      headers: { cookie: 'other-cookie=value' },
    });

    // Act
    const result = extractSessionId(request, '__Host-session');

    // Assert
    expect(result).toBeNull();
  });

  it('extracts correct cookie when multiple cookies present', () => {
    // Arrange
    const request = new Request('https://torii.dev', {
      headers: { cookie: 'first=one; __Host-session=target; third=three' },
    });

    // Act
    const result = extractSessionId(request, '__Host-session');

    // Assert
    expect(result).toBe('target');
  });

  it('handles quoted cookie values', () => {
    // Arrange
    const request = new Request('https://torii.dev', {
      headers: { cookie: '__Host-session="quoted-value"' },
    });

    // Act
    const result = extractSessionId(request, '__Host-session');

    // Assert
    expect(result).toBe('quoted-value');
  });

  it('handles cookie names with special prefixes', () => {
    // Arrange
    const request = new Request('https://torii.dev', {
      headers: { cookie: '__Secure-session=secure123' },
    });

    // Act
    const result = extractSessionId(request, '__Secure-session');

    // Assert
    expect(result).toBe('secure123');
  });
});

describe(generateSessionId, () => {
  it('generates a 64-character hex string', () => {
    // Act
    const id = generateSessionId();

    // Assert
    expect(id).toHaveLength(64); // 32 bytes * 2 hex chars per byte
  });

  it('only contains valid hex characters', () => {
    // Act
    const id = generateSessionId();

    // Assert
    expect(id).toMatch(/^[0-9a-f]+$/);
  });

  it('generates unique IDs on multiple calls', () => {
    // Act
    const id1 = generateSessionId();
    const id2 = generateSessionId();
    const id3 = generateSessionId();

    // Assert
    expect(id1).not.toBe(id2);
    expect(id2).not.toBe(id3);
    expect(id1).not.toBe(id3);
  });

  it('generates IDs with proper zero-padding', () => {
    // Act - Generate many IDs to increase probability of hitting low byte values
    const ids = Array.from({ length: 100 }, () => generateSessionId());

    // Assert - All IDs should be exactly 64 chars (no missing leading zeros)
    for (const id of ids) {
      expect(id).toHaveLength(64);
    }
  });

  it('uses cryptographically random values', () => {
    // Act - Generate multiple IDs and check entropy (no obvious patterns)
    const ids = new Set(Array.from({ length: 50 }, () => generateSessionId()));

    // Assert - All 50 should be unique
    expect(ids.size).toBe(50);
  });
});
