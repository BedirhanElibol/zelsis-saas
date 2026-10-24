import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runStaticCodeScan } from '@/lib/scanner-engine';

// Generated code (protobuf.js and the like) opens with a comment and carries /** */ blocks on every member.
// A lazy [\s\S]*? comment match inside a repeated group hung the whole scan on apollographql/apollo-server.
test('a file full of block comments scans in bounded time', async () => {
  // Pairs of block comments separated by a blank line: each pair doubled the old regex's work (2^n)
  const member = (i: number) => `/**\n * Field ${i}.\n */\n\n/**\n * Getter ${i}.\n */\nProto.prototype.f${i} = 0;\n`;
  const content = '/*eslint-disable*/\n"use strict";\n' + Array.from({ length: 40 }, (_, i) => member(i)).join('');
  const started = Date.now();
  await runStaticCodeScan([{ path: 'packages/proto/generated/cjs/protobuf.js', content }], 'x', { dependencyAudit: false });
  assert.ok(Date.now() - started < 10_000, `scan took ${Date.now() - started} ms`);
});
