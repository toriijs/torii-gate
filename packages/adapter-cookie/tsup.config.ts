import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/**/*.ts', '!src/**/*.test.ts', '!src/**/*.spec.ts'],
  format: ['esm'],
  dts: true,
  splitting: false,
  sourcemap: false,
  clean: true,
  target: 'es2022',
  // neutral platform — no Node.js polyfills, runs on CF Workers / Deno / Bun
  platform: 'neutral',
  tsconfig: 'tsconfig.build.json',
});
