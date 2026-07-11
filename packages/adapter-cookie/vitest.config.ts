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
        exclude: [
          'src/**/*.d.ts',
          'src/**/index.ts',
          'src/adapters/interface.ts', // TypeScript interfaces only
          'src/adapters/pending.ts', // TypeScript interfaces only
          'src/security/constants.ts', // Compile-time constants only
        ],
      },
      typecheck: {
        enabled: true,
        tsconfig: 'tsconfig.json',
      },
    },
  }),
);
