/**
 * Fetch API type augmentations
 *
 * The TypeScript DOM lib (lib.dom.d.ts) lags behind the living Fetch spec.
 * These declarations fill gaps that exist at runtime on all target platforms
 * (Node.js 18+, Cloudflare Workers, Deno, Bun) but are absent from the
 * current TypeScript built-in type definitions.
 *
 * Using interface merging (declaration merging) on the global RequestInit
 * interface is the correct approach — it extends the existing type rather
 * than overriding it, so all existing RequestInit properties remain intact.
 *
 * References:
 *   Fetch spec §5.4 — https://fetch.spec.whatwg.org/#dom-request-duplex
 *   TypeScript issue  — https://github.com/microsoft/TypeScript-DOM-lib-generator/pull/1729
 *   Node.js 18+ — requires duplex: 'half' when body is a ReadableStream
 */

declare global {
  interface RequestInit {
    /**
     * Controls whether the request body can be sent while the response
     * is still being received (half-duplex streaming).
     *
     * Required by the Fetch spec when body is a ReadableStream.
     * Node.js 18+, Cloudflare Workers, and Deno all require 'half'
     * for streaming request bodies.
     *
     * @see https://fetch.spec.whatwg.org/#dom-request-duplex
     */
    duplex?: 'half';
  }
}

export {};
