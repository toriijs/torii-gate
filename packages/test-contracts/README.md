# @torii-gate/test-contracts

**RFC 9700 compliance tests and fixtures for building OAuth 2.0 Token Handler session adapters.**

Comprehensive test suite covering all OAuth 2.0 for Browser-Based Apps security requirements.

## Installation

```bash
pnpm add -D @torii-gate/test-contracts
# or
npm install --save-dev @torii-gate/test-contracts
# or
yarn add -D @torii-gate/test-contracts
```

**Peer Dependencies:**

- `@torii-gate/core` (for SessionAdapter and PendingAuthStore interfaces)
- `vitest` ≥4.0.0 (for running contract tests)

---

## For Community Adapter Authors

Building a custom Torii adapter? Use these compliance tests to ensure your adapter meets **all RFC 9700 Token Handler requirements** with strict security enforcement.

---

## Adapter Types

All test functions require an explicit `type` parameter to ensure tests match your adapter's architecture.

### SessionAdapter Types

**Stateful (`type: 'stateful'`)**

- Session ID (short random string) stored in cookie
- Session data (tokens, metadata) stored server-side (Redis, Memory, SQL, etc.)
- Supports instant revocation
- Requires server-side storage infrastructure
- Examples: `@torii-gate/adapter-memory`, `@torii-gate/adapter-redis`

**Stateless (`type: 'stateless'`)**

- Encrypted session data stored directly in cookie
- No server-side storage required
- Revocation requires token blacklist or TTL expiry
- Must implement AES-GCM authenticated encryption
- Examples: `@torii-gate/adapter-cookie`

### PendingAuthStore Types

**Server-Side (`type: 'server-side'`)**

- PKCE state stored on server (Redis, Memory, SQL, etc.)
- Must support atomic single-use enforcement (e.g., Redis GETDEL)
- Required for preventing TOCTOU vulnerabilities
- Examples: `@torii-gate/adapter-memory`, `@torii-gate/adapter-redis`

**Cookie-Based (`type: 'cookie-based'`)**

- Encrypted PKCE state stored in cookie
- Single-use enforced via deletion headers in callback response
- Must use timing-safe state comparison
- Examples: `@torii-gate/adapter-cookie`

---

## Contract Test Suites

### `runAdapterContractTests()`

Complete RFC 9700 compliance test suite for `SessionAdapter` implementations.

**28 tests covering:**

#### Core Operations (6 tests)

- ✅ Session storage and retrieval
- ✅ Null returns for missing/invalid cookies
- ✅ All SessionData fields preserved (including `refreshGeneration` and `userInfo`)
- ✅ Session deletion with proper cache invalidation

#### RFC 9700 §6.3 — Session Expiration (2 tests)

- ✅ Expired sessions (`expiresAt` in past) return `null`
- ✅ `Max-Age` value matches configured `maxAge`

#### RFC 9700 §7 — Cookie Security Attributes (11 tests)

- ✅ **Same-domain topology:**
  - `__Host-` prefix required
  - `SameSite=Strict`
  - No `Domain` attribute
  - `Path=/`
- ✅ **Subdomain topology:**
  - `__Secure-` prefix required
  - `SameSite=Lax`
  - `Domain` attribute with correct value
  - `Path=/`
- ✅ `Secure` and `HttpOnly` flags on all cookies
- ✅ `Max-Age=0` on deletion cookies

#### RFC 9700 §7 — Session Rotation (4 tests, optional)

- ✅ New session identifier generated
- ✅ Old session invalidated
- ✅ Updated session data accessible with new ID
- ✅ Cookie security attributes preserved

#### RFC 9700 §6.3 — Encryption for Stateless Adapters (3 tests)

- ✅ Tokens not visible in plaintext cookie values
- ✅ Tampered cookies return `null` (AES-GCM integrity)
- ✅ Truncated cookies return `null`

#### Concurrent Operations (2 tests)

- ✅ Concurrent reads without data corruption
- ✅ Concurrent writes without data loss (token values validated)

**Usage:**

```typescript
import { runAdapterContractTests } from '@torii-gate/test-contracts';

// Stateful adapter (session ID in cookie, data in database)
// eslint-disable-next-line vitest/require-hook -- runAdapterContractTests is a test suite generator, not setup
runAdapterContractTests(() => new MyRedisAdapter(), { type: 'stateful' });

// Stateless adapter (encrypted data in cookie)
// eslint-disable-next-line vitest/require-hook -- runAdapterContractTests is a test suite generator, not setup
runAdapterContractTests(() => new MyCookieAdapter({ secret }), { type: 'stateless' });
```

> **Note:** The `eslint-disable-next-line` comment is required to suppress the Vitest lint warning. Contract test functions register test suites rather than performing setup, so they're called at module level (not in hooks).

---

### `runPendingStoreContractTests()`

Complete contract test suite for `PendingAuthStore` implementations (PKCE state storage).

**11 tests covering:**

#### Core Operations (3 tests)

- ✅ Store and retrieve pending auth data
- ✅ Return `null` for non-existent state
- ✅ All `PendingAuth` fields preserved

#### RFC 9700 §4.7 — Single-Use Enforcement (2 tests)

- ✅ **Strict atomic enforcement:** Exactly 1 parallel get succeeds (server-side stores)
- ✅ Entry consumed after first retrieval
- ✅ Cookie-based stores validated separately

#### TTL Enforcement (2 tests)

- ✅ Expired entries return `null`
- ✅ Valid entry retrieved before expiry, `null` after

#### Cleanup (2 tests)

- ✅ `clear()` returns proper headers
- ✅ `clear()` callable without errors

#### Concurrent Operations (1 test)

- ✅ Concurrent sets without data loss

#### Request Parameter Handling (1 test)

- ✅ Optional request parameter works correctly

**Usage:**

```typescript
import { runPendingStoreContractTests } from '@torii-gate/test-contracts';

// Server-side store (Redis, Memory, SQL)
// eslint-disable-next-line vitest/require-hook -- runPendingStoreContractTests is a test suite generator, not setup
runPendingStoreContractTests(() => new MyRedisPendingStore(), { type: 'server-side' });

// Cookie-based store
// eslint-disable-next-line vitest/require-hook -- runPendingStoreContractTests is a test suite generator, not setup
runPendingStoreContractTests(() => new MyCookiePendingStore({ secret }), { type: 'cookie-based' });
```

---

### `runSecurityAuditTests()` (Optional)

**Advanced security validation** for timing-safe operations and cryptographic properties.

**⚠️ Note:** These tests are heuristic and may be flaky. Run separately from main contract tests.

**Usage:**

```typescript
import { runSecurityAuditTests } from '@torii-gate/test-contracts';
import { MyCookiePendingStore } from './my-pending-store';

// eslint-disable-next-line vitest/require-hook -- runSecurityAuditTests is a test suite generator, not setup
runSecurityAuditTests(() => new MyCookiePendingStore({ secret: 'test-secret-min-32-characters!!' }), { type: 'cookie-based' });
```

**Tests:**

- ⚠️ Timing-safe state comparison (heuristic, may have false positives)

---

## Test Fixtures

Predefined `SessionData` and `PendingAuth` objects for testing:

### SessionData Fixtures

- `VALID_SESSION` - Complete session with all fields (1 hour TTL)
- `MINIMAL_SESSION` - Session with only required fields
- `EXPIRED_SESSION` - Session with `expiresAt` in the past
- `SESSION_WITH_USERINFO` - Session with cached userInfo claims

### PendingAuth Fixtures

- `VALID_PENDING_AUTH` - Complete pending auth (10 minute TTL)
- `EXPIRED_PENDING_AUTH` - Pending auth with `expiresAt` in the past

**Usage:**

```typescript
import { VALID_SESSION, EXPIRED_SESSION, VALID_PENDING_AUTH } from '@torii-gate/test-contracts';

it('handles expired sessions', async () => {
  const headers = await adapter.set(EXPIRED_SESSION, options);
  const result = await adapter.get(request);
  expect(result).toBeNull();
});
```

---

## Helper Functions

### `mockRequest(cookieHeader: string): Request`

Create a mock HTTP Request with Cookie header for testing.

```typescript
import { mockRequest } from '@torii-gate/test-contracts';

const request = mockRequest('__Host-session=abc123; Path=/');
const session = await adapter.get(request);
```

### `extractCookieValue(setCookieHeader: string, cookieName: string): string`

Extract cookie value from Set-Cookie header string.

```typescript
import { extractCookieValue } from '@torii-gate/test-contracts';

const headers = await adapter.set(session, options);
const cookieValue = extractCookieValue(headers[0], '__Host-session');
const request = mockRequest(`__Host-session=${cookieValue}`);
```

---

## RFC 9700 Compliance Checklist

### Mandatory Requirements (All adapters must pass)

✅ **Core contract tests automatically verify:**

- RFC 9700 §6.3 — Tokens never sent to browser (encrypted or server-side)
- RFC 9700 §7 — Cookie security attributes by topology
- RFC 9700 §4.7 — Single-use PKCE state enforcement (atomic operations required)
- RFC 6265bis — Cookie prefix (`__Host-` for same-domain, `__Secure-` for subdomain)
- RFC 6265bis — `Secure`, `HttpOnly`, `SameSite` flags
- Session expiration enforcement (`expiresAt` validation)
- Data integrity (all 6 SessionData fields preserved)
- Concurrent access safety (no race conditions)

### Optional Features (Tested if implemented)

⚪ **Session Rotation** (RFC 9700 §7)

- Tests automatically skip if `rotate()` method not implemented
- Recommended for session fixation defense

⚪ **Security Audit Suite**

- Advanced timing-safe operation tests
- Heuristic validation (may be flaky)
- Run separately via `runSecurityAuditTests()`

---

## Common Adapter Implementation Mistakes

These are typical errors caught by the contract tests. If your adapter fails a test, check for these patterns:

### 1. **Non-Atomic Single-Use Enforcement** (PendingAuthStore)

**Symptom:** Test fails: "multiple parallel gets only succeed once"

**Problem:** Using separate read + delete operations instead of atomic operation:

```typescript
// ❌ WRONG: Race condition (TOCTOU vulnerability)
const data = await redis.get(state);
await redis.del(state);
return data;

// ✅ CORRECT: Atomic operation
return await redis.getdel(state); // Redis GETDEL command
```

**RFC Reference:** RFC 9700 §4.7 — PKCE state must be single-use

---

### 2. **Non-Constant-Time State Comparison**

**Symptom:** Security audit test fails (timing variance > 2x)

**Problem:** Using `===` for state comparison allows timing attacks:

```typescript
// ❌ WRONG: Early exit leaks information
if (provided === stored) { ... }

// ✅ CORRECT: Web Crypto API timing-safe comparison (edge-compatible)
const match = crypto.subtle.timingSafeEqual(
  new TextEncoder().encode(provided),
  new TextEncoder().encode(stored)
);

// Or manual implementation for broader compatibility:
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);
  let result = 0;
  for (let i = 0; i < aBytes.length; i++) {
    result |= aBytes[i]! ^ bBytes[i]!;
  }
  return result === 0;
}
```

**RFC Reference:** RFC 8725 §3.8 — Cryptographic comparisons must be timing-safe

---

### 3. **Missing SameSite Attribute**

**Symptom:** Test fails: "uses SameSite=Strict" or "uses SameSite=Lax"

**Problem:** Not setting `SameSite` based on topology:

```typescript
// ❌ WRONG: Always SameSite=Lax
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax

// ✅ CORRECT: Topology-aware
// Same-domain: SameSite=Strict
// Subdomain:   SameSite=Lax
```

**RFC Reference:** RFC 9700 §7.1 — CSRF defense via SameSite

---

### 4. **Forgetting to Check expiresAt on Every get()**

**Symptom:** Test fails: "returns null for expired session"

**Problem:** Relying on TTL at storage layer instead of checking `expiresAt`:

```typescript
// ❌ WRONG: Only checks storage TTL
async get(request) {
  return await db.get(sessionId); // Might return expired session
}

// ✅ CORRECT: Always validate expiresAt
async get(request) {
  const session = await db.get(sessionId);
  if (session && session.expiresAt < Date.now()) {
    await db.del(sessionId); // Lazy cleanup
    return null;
  }
  return session;
}
```

**RFC Reference:** RFC 9700 §6.3 — Token storage must enforce TTL

---

### 5. **Wrong Cookie Prefix for Topology**

**Symptom:** Test fails: "uses **Host- prefix" or "uses **Secure- prefix"

**Problem:** Not using correct prefix based on topology:

```typescript
// ❌ WRONG: Always __Secure-
cookieName: '__Secure-session';

// ✅ CORRECT: Topology-aware
// Same-domain: __Host-session (no Domain attribute)
// Subdomain:   __Secure-session (with Domain=.example.com)
```

**RFC Reference:** RFC 9700 §7 — Cookie prefixes prevent downgrade attacks

---

### 6. **Not Handling Cookie Chunking**

**Symptom:** Test fails: "handles session data approaching 4KB cookie limit"

**Problem:** Stateless adapters must chunk large cookies (4KB browser limit):

```typescript
// ❌ WRONG: Single large cookie exceeds 4KB
Set-Cookie: session=<5KB-encrypted-data>; ...

// ✅ CORRECT: Multiple chunks
Set-Cookie: session_0=<chunk0>; ...
Set-Cookie: session_1=<chunk1>; ...
Set-Cookie: session_2=<chunk2>; ...
```

**Reference:** RFC 6265bis §5.3 — User agents may impose limits (typically 4KB)

---

### 7. **Encryption Without Integrity Check**

**Symptom:** Test fails: "tampered cookie value returns null"

**Problem:** Using encryption without authentication (e.g., AES-CBC without HMAC):

```typescript
// ❌ WRONG: AES-CBC alone (no tamper detection)
const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, data); // No integrity check!

// ✅ CORRECT: AES-GCM (authenticated encryption)
const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, data); // Built-in tamper detection
```

**RFC Reference:** RFC 9700 §6.3 — Stateless sessions must prevent tampering

---

## Error Handling Contract

Adapters should handle errors defensively:

### Storage Backend Failures

- **Network errors:** Return `null` from `get()`, throw from `set()`/`delete()`
- **Timeouts:** Return `null` from `get()` after timeout (fail-safe)
- **Invalid data:** Return `null` from `get()` (don't propagate parse errors)

### Invalid Input

- **Negative expiresAt:** Treat as expired (return `null`)
- **NaN expiresAt:** Reject at `set()` time or treat as expired at `get()`
- **Oversized data:** Throw from `set()` with clear error message
- **Empty required fields:** Adapters may store but should validate at application layer

### Concurrent Operations

- **Double delete:** Should be idempotent (no error)
- **Concurrent rotate():** At least one should succeed, others may fail
- **Race conditions:** Use transactions/locks where needed (Redis, SQL)

---

## Example: Building a Custom Adapter

```typescript
import type { SessionAdapter, SessionData, CookieOptions } from '@torii-gate/core/adapters/interface';
import { runAdapterContractTests } from '@torii-gate/test-contracts';

export class MyCustomAdapter implements SessionAdapter {
  async get(request: Request): Promise<SessionData | null> {
    // Extract session ID from cookie
    // Look up in your storage backend
    // Check if expired
    return sessionData;
  }

  async set(sessionData: SessionData, options: CookieOptions): Promise<string[]> {
    // Generate session ID
    // Store in your backend
    // Return Set-Cookie headers
    return [`${options.cookieName}=${sessionId}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${options.maxAge}`];
  }

  async delete(request: Request, options: CookieOptions): Promise<string[]> {
    // Extract session ID
    // Delete from backend
    // Return deletion headers
    return [`${options.cookieName}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`];
  }

  // Optional: Session rotation for session fixation defense
  async rotate?(request: Request, sessionData: SessionData, options: CookieOptions): Promise<string[]> {
    // Generate new session ID
    // Delete old session
    // Store new session
    return this.set(sessionData, options);
  }
}

// In your test file:
describe('MyCustomAdapter', () => {
  runAdapterContractTests(() => new MyCustomAdapter(), { type: 'stateful' });

  // Add adapter-specific tests
  describe('custom features', () => {
    it('handles connection pooling', async () => {
      // ...
    });
  });
});
```

---

## Reference Implementations

See the official adapters for production-ready examples:

- **[@torii-gate/adapter-cookie](https://github.com/toriijs/torii/tree/main/packages/adapter-cookie)** — Stateless, AES-GCM encrypted sessions
- **[@torii-gate/adapter-memory](https://github.com/toriijs/torii/tree/main/packages/adapter-memory)** — In-memory sessions (dev/test only)
- **[@torii-gate/adapter-redis](https://github.com/toriijs/torii/tree/main/packages/adapter-redis)** — Redis-backed sessions (Node.js + Upstash)

---

## "RFC 9700 Certified" Badge

Adapters passing all contract tests can display:

```markdown
[![RFC 9700 Certified](https://img.shields.io/badge/RFC%209700-Certified-brightgreen)](https://www.rfc-editor.org/rfc/rfc9700.html)
```

[![RFC 9700 Certified](https://img.shields.io/badge/RFC%209700-Certified-brightgreen)](https://www.rfc-editor.org/rfc/rfc9700.html)

---

## License

[EUPL-1.2](./LICENSE) © [2026] [Chathuranga Hengodage](https://github.com/iamchathu)
