import rootConfig from '../../eslint.config.js';

/** @type {import('eslint').Linter.Config[]} */
export default [
  ...rootConfig,
  {
    languageOptions: {
      parserOptions: {
        defaultProject: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    // Contract test files contain test definitions with justified non-null assertions
    // after explicit array length checks (e.g., expect(headers.length).toBeGreaterThanOrEqual(1))
    files: ['src/contract.ts', 'src/security-audit.ts'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
  {
    ignores: ['dist/'],
  },
];
