import { defineConfig } from 'vitest/config';
import type { ViteUserConfig } from 'vitest/config';

export const sharedConfig: ViteUserConfig = {
  test: {
    // edge-runtime: Web Crypto, fetch, URL all available — matches CF Workers / Deno
    environment: 'edge-runtime',
    globals: false,

    silent: false,

    testTimeout: 10_000,

    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      exclude: [
        'src/**/*.d.ts',
        'src/**/index.ts', // barrel files — no logic to cover
        'tests/**',
        'dist/**',
      ],
      thresholds: {
        lines: 90,
        functions: 90,
        branches: 85,
        statements: 90,
      },
    },

    css: false,

    reporters: ['tree'],
  },
};

export default defineConfig(sharedConfig);
