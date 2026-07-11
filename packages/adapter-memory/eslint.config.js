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
    ignores: ['dist/'],
  },
];
