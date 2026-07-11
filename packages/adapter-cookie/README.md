# @torii-gate/adapter-cookie

[![RFC 9700 Certified](https://img.shields.io/badge/RFC%209700-Certified-brightgreen)](https://www.rfc-editor.org/rfc/rfc9700.html)

**Stateless, encrypted cookie session adapter for Torii** — Production-ready for edge runtimes.

## Features

- ✅ **RFC 9700 Certified** — Passes all 28 SessionAdapter contract tests
- ✅ **Edge-native** — Works on Cloudflare Workers, Deno Deploy, Vercel Edge, Bun, Node.js ≥24
- ✅ **Stateless** — No database required, scales infinitely
- ✅ **AES-GCM-256 encryption** — Tokens never visible in cookies
- ✅ **Automatic chunking** — Handles large sessions (splits across multiple cookies)
- ✅ **Tamper detection** — Authenticated encryption (AEAD)
- ✅ **HKDF key derivation** — Secure key stretching from your secret

## Installation

```bash
pnpm add @torii-gate/adapter-cookie
```

## Quick Start

```typescript
import { CookieAdapter } from '@torii-gate/adapter-cookie';

const adapter = new CookieAdapter({
  secret: process.env.SESSION_SECRET, // Min 32 characters
});

// Session operations
const headers = await adapter.set(sessionData, {
  cookieName: '__Host-session',
  maxAge: 900,
  topology: 'same-domain',
});

const session = await adapter.get(request);
await adapter.delete(request, options);
```

## Configuration

```typescript
interface CookieAdapterOptions {
  /**
   * Encryption secret (REQUIRED).
   * Must be ≥32 characters.
   *
   * Store in environment variables:
   * - Development: .env.local
   * - Production: Platform secrets (Cloudflare, Vercel, etc.)
   */
  secret: string;

  /**
   * Max size per cookie chunk in bytes.
   * Default: 3072 (3KB, safely under 4KB browser limit)
   *
   * Cookies are automatically split into chunks if needed.
   */
  chunkSize?: number;
}
```

### Secret Requirements

- **Minimum length:** 32 characters
- **Randomness:** Use a cryptographically secure random string
- **Storage:** Store in environment variables, never commit to git

**Generate a secret:**

```bash
# Node.js / Bun
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# OpenSSL
openssl rand -base64 32

# 1Password / Bitwarden
# Generate a 32+ character random password
```

## How It Works

### Encryption

1. **Key derivation:** HKDF-SHA256 derives encryption key from your secret
2. **Encryption:** AES-GCM-256 encrypts SessionData with random IV per session
3. **Encoding:** Base64url encodes encrypted payload
4. **Chunking:** Splits into 3KB chunks if needed (browser limit is 4KB)

### Chunking

Large sessions (e.g., with userInfo claims) are automatically split:

```http
Set-Cookie: __Host-session=<3KB-chunk-0>; Secure; HttpOnly; ...
Set-Cookie: __Host-session-1=<3KB-chunk-1>; Secure; HttpOnly; ...
Set-Cookie: __Host-session-2=<3KB-chunk-2>; Secure; HttpOnly; ...
```

**Reassembly:** Chunks are automatically reassembled on `get()`.

**Deletion:** All chunks are cleared on `delete()` (base + chunks 0-9).

### Security Properties

- ✅ **Confidentiality:** Tokens encrypted with AES-GCM-256
- ✅ **Integrity:** Authenticated encryption prevents tampering
- ✅ **Freshness:** Random IV per session prevents replay attacks
- ✅ **No server state:** Fully stateless, scale-to-zero safe

## Edge Runtime Compatibility

Tested on:

- ✅ **Cloudflare Workers**
- ✅ **Deno Deploy**
- ✅ **Vercel Edge Functions**
- ✅ **Bun** ≥1.0
- ✅ **Node.js** ≥24 (with `--experimental-global-web-crypto`)

Uses Web Crypto API (`globalThis.crypto`) — no Node.js built-ins.

## Contract Test Compliance

This adapter passes all [@torii-gate/test-contracts](../test-contracts) tests:

- ✅ 28 SessionAdapter contract tests
- ✅ 11 PendingAuthStore contract tests (CookiePendingStore)
- ✅ RFC 9700 §6.3 — Tokens encrypted in cookies
- ✅ RFC 9700 §7 — Cookie security attributes
- ✅ Encryption validation (plaintext leak prevention)
- ✅ Tamper detection (AES-GCM integrity)
- ✅ Truncation detection
- ✅ All SessionData fields preserved
- ✅ Concurrent operations safety

## When to Use Cookie Adapter

### ✅ Great For:

- Edge runtimes (Cloudflare, Deno, Vercel Edge)
- Stateless architectures
- Scale-to-zero deployments
- No database overhead
- Simple deployments

### ⚠️ Consider Redis Instead If:

- You need server-side session revocation
- You have very large session data (>10KB consistently)
- You need session activity tracking
- You want centralized session management

## Pending Auth Store

The package also exports `CookiePendingStore` for PKCE state:

```typescript
import { CookiePendingStore } from '@torii-gate/adapter-cookie/pending';

const pendingStore = new CookiePendingStore({
  secret: process.env.SESSION_SECRET, // Same secret as adapter
  maxAge: 600, // 10 minutes (default)
});
```

**Features:**

- ✅ Encrypted PKCE state (`codeVerifier`, `nonce`, `state`)
- ✅ Timing-safe state comparison (prevents timing attacks)
- ✅ Automatic expiration
- ✅ Single-use enforcement via `clear()` headers

## Related Packages

- [@torii-gate/adapter-memory](../adapter-memory) — Dev/test adapter
- [@torii-gate/adapter-redis](../adapter-redis) — Server-side sessions with revocation
- [@torii-gate/test-contracts](../test-contracts) — Test your own adapter
- [@torii-gate/core](../core) — Core OAuth Agent + Proxy

## License

MIT © Torii Contributors
