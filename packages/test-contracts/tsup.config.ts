import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/**/*.ts', '!src/**/*.test.ts'],
  format: ['esm'],
  dts: true,
  splitting: false,
  sourcemap: false,
  clean: true,
  target: 'es2022',
  // neutral platform — no Node.js polyfills, runs on CF Workers / Deno / Bun
  platform: 'neutral',
  external: ['@torii-gate/core', 'vitest'],
  tsconfig: 'tsconfig.build.json',
});
