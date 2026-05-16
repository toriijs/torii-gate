/**
 * @torii-gate/core
 *
 * RFC 9700 compliant Token Handler BFF for edge runtimes.
 * Web Standards only — Cloudflare Workers, Deno Deploy, Bun, Node.js ≥ 24.
 */

export * from './security/index.js';
export type { SessionAdapter, SessionData } from './adapters/interface.js';
export { createProxy, type ProxyConfig } from './proxy/index.js';
export * from './agent/index.js';
export * from './oidc/index.js';
export * from './config/index.js';
export { getRuntime, deriveSessionKey, type RuntimeState } from './runtime/initializer.js';
