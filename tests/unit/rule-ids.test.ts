import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = join(__dirname, '../..');
const sources = [
  ...readdirSync(join(root, 'lib/rules')).filter((f) => f.endsWith('.ts')).map((f) => `lib/rules/${f}`),
  'lib/scanner/builtin-rules.ts',
  'lib/scanner/osv.ts',
  'lib/scanner/live-checks.ts'
];

/** Same rule emitted from two places or as language variants: one id on purpose. */
const SHARED_ON_PURPOSE = new Set([1, 16, 18101, 23005]);

test('every rule id belongs to one rule (evidence and ignores are keyed by id)', () => {
  const titlesById = new Map<number, Set<string>>();
  for (const source of sources) {
    const text = readFileSync(join(root, source), 'utf8');
    for (const m of text.matchAll(/ruleId:\s*(\d+),/g)) {
      const title = text.slice(m.index!, m.index! + 600).match(/title:\s*[`"']([^`"'\n]+)/)?.[1] ?? '';
      const stem = title.replace(/^[A-Z0-9][A-Z0-9-]*-\d+:\s*/, '').slice(0, 30);
      const id = Number(m[1]);
      if (!titlesById.has(id)) titlesById.set(id, new Set());
      titlesById.get(id)!.add(stem);
    }
  }
  const clashes = [...titlesById]
    .filter(([id, stems]) => stems.size > 1 && !SHARED_ON_PURPOSE.has(id))
    .map(([id, stems]) => `${id}: ${[...stems].join(' | ')}`);
  assert.deepEqual(clashes, [], `rule ids reused by different rules:\n${clashes.join('\n')}`);
});
