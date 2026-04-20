import { defineConfig, mergeConfig } from 'vitest/config';
import { sharedConfig } from '../../vitest.base.js';

export default mergeConfig(
  sharedConfig,
  defineConfig({
    test: {
      include: ['src/**/*.spec.ts', 'tests/**/*.test.ts'],
      exclude: ['tests/adapters/contract.test.ts'],
      coverage: {
        include: ['src/**/*.ts'],
      },
      typecheck: {
        enabled: true,
        tsconfig: 'tsconfig.json',
      },
    },
  }),
);
