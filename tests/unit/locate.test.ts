import { test } from 'node:test';
import assert from 'node:assert/strict';
import { locateMatchLine } from '@/lib/rules/shared/locate';

const isCode = (l: string) => !l.trim().startsWith('//');

test('points at the first code line matching a trigger pattern', () => {
  const lines = ['// x-forwarded-host', 'import a from "a";', 'const h = req.headers.get("x-forwarded-host");'];
  assert.equal(locateMatchLine(lines, [/x-forwarded-host/i], isCode), 2);
});

test('global regexes do not carry lastIndex between lines', () => {
  const lines = ['eval(a)', 'eval(b)'];
  assert.equal(locateMatchLine(lines, [/eval\(/g], isCode), 0);
});

test('falls back to the first code line for multi-line triggers', () => {
  const lines = ['// header', 'a', 'b'];
  assert.equal(locateMatchLine(lines, [/a\nb/], isCode), 1);
});
