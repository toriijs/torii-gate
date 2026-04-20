/**
 * HTTPS Validation Utility Test Suite
 *
 * Tests the shared isValidHttpsUrl() function used across:
 * - Config validation layer
 * - OIDC discovery layer
 * - Issuer validation layer
 */

import { describe, it, expect } from 'vitest';
import { isValidHttpsUrl } from './https.js';

describe(isValidHttpsUrl, () => {
  it('accepts HTTPS URLs', () => {
    expect(isValidHttpsUrl('https://auth.torii.dev')).toBe(true);
    expect(isValidHttpsUrl('https://localhost:8080')).toBe(true);
    expect(isValidHttpsUrl('https://api.torii.dev/path')).toBe(true);
    expect(isValidHttpsUrl('https://127.0.0.1:8080')).toBe(true);
    expect(isValidHttpsUrl('https://[::1]:8080')).toBe(true);
  });

  it('rejects HTTP URLs', () => {
    expect(isValidHttpsUrl('http://auth.torii.dev')).toBe(false);
    expect(isValidHttpsUrl('http://localhost:8080')).toBe(false);
    expect(isValidHttpsUrl('http://127.0.0.1:8080')).toBe(false);
    expect(isValidHttpsUrl('http://keycloak:8080')).toBe(false);
  });

  it('rejects invalid URLs', () => {
    expect(isValidHttpsUrl('not-a-url')).toBe(false);
    expect(isValidHttpsUrl('')).toBe(false);
    expect(isValidHttpsUrl('ftp://torii.dev')).toBe(false);
  });
});
