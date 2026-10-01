import { defineConfig, globalIgnores } from 'eslint/config';
import nextVitals from 'eslint-config-next/core-web-vitals';
import nextTs from 'eslint-config-next/typescript';

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  globalIgnores([
    '.next/**',
    'node_modules/**',
    'dist/**',
    '.cache/**',
    'playwright-report/**',
    'test-results/**',
    'next-env.d.ts',
    '*.js',
    '*.py'
  ]),
  {
    files: ['**/*.{js,jsx,mjs,ts,tsx}'],
    // Baseline: rules with existing violations are warnings so CI can gate new errors.
    // Fix the warnings, then promote each rule back to 'error'.
    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-empty-object-type': 'warn',
      '@typescript-eslint/no-require-imports': 'warn',
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/purity': 'warn',
      'react-hooks/immutability': 'warn',
      'react/no-unescaped-entities': 'warn',
      'react/jsx-no-comment-textnodes': 'warn',
      '@next/next/no-html-link-for-pages': 'warn',
      'prefer-const': 'warn'
    }
  },
  {
    files: ['**/*.cjs'],
    rules: { '@typescript-eslint/no-require-imports': 'off' }
  }
]);
