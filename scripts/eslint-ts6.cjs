/**
 * typescript-eslint does not support the TS 7 API yet
 * (https://github.com/typescript-eslint/typescript-eslint/issues/10940).
 * Preloaded only for ESLint: maps `typescript` imports to the side-by-side TS 6 package.
 * Typecheck and build keep using TS 7. Delete once typescript-eslint supports TS 7.
 */
const Module = require('module');

const originalResolve = Module._resolveFilename;
Module._resolveFilename = function resolveTs6(request, ...rest) {
  if (request === 'typescript' || request.startsWith('typescript/')) {
    request = '@typescript/typescript6' + request.slice('typescript'.length);
  }
  return originalResolve.call(this, request, ...rest);
};
