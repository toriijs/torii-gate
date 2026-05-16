import js from '@eslint/js';
import ts from 'typescript-eslint';
import vitest from '@vitest/eslint-plugin';
import prettierConfig from 'eslint-config-prettier';
import globals from 'globals';

/** @type {import('eslint').Linter.Config[]} */
export default [
  // Global Ignores (Flat Config's version of .eslintignore)
  // Must be the first object and contain ONLY 'ignores' to be global.
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/coverage/**',
      '**/.wrangler/**',
      '**/.devvars',
      '**/temp/**',
      '**/.wrangler/**',
      '**/.turbo/**',
      '**/vitest.config.ts',
      '**/tsup.config.ts',
      '**/*.config.js',
      '**/pnpm-lock.yaml',
      '**/package.json',
      '**/*.md',
      '**/*.json',
      'vitest.base.ts',
      '**/vitest.config.ts',
    ],
  },

  // JavaScript Base & Edge Globals
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.serviceworker, // Support for Cloudflare Workers / Fetch API
      },
    },
  },

  // TypeScript Strict & Stylistic Rules
  // We spread these arrays directly into the main config array.
  ...ts.configs.strictTypeChecked,
  ...ts.configs.stylisticTypeChecked,

  // TypeScript Parser & Project Service
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parser: ts.parser,
      parserOptions: {
        globals: {
          ...globals.serviceworker, // Vital for Hono/Edge (Cloudflare/Bun)
          ...globals.node,
          ...globals.es2021,
        },
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/restrict-template-expressions': [
        'error',
        {
          allowNumber: true,
          allowAny: false,
          allowBoolean: false,
          allowNullish: false,
        },
      ],
    },
  },

  // Vitest (Unit & Integration)
  {
    files: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
    plugins: {
      vitest,
    },
    rules: {
      ...vitest.configs.all.rules,
      'vitest/consistent-test-it': ['error', { fn: 'it' }],
      'vitest/no-focused-tests': 'error',
      'vitest/prefer-expect-assertions': 'off',
      'vitest/require-mock-type-parameters': 'off',
      'vitest/no-hooks': 'off',
      'vitest/valid-title': ['error', { allowArguments: true }],
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
    languageOptions: {
      globals: {
        ...vitest.environments.env.globals,
      },
    },
    settings: {
      vitest: {
        typecheck: true,
      },
    },
  },

  // Prettier (Rule Disabling)
  {
    files: ['**/*.{js,mjs,cjs,ts,tsx,json,md}'],
    ...prettierConfig,
  },
];
