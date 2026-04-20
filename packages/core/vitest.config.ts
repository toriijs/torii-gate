import { defineConfig, mergeConfig } from 'vitest/config';
import { sharedConfig } from '../../vitest.base.ts';

export default mergeConfig(
  sharedConfig,
  defineConfig({
    test: {
      include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
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
