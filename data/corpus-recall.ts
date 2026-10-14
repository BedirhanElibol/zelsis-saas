/**
 * Published result of scripts/benchmark/corpus-recall.ts on public/benchmark/real-incident-corpus.txt.
 * tests/unit/corpus-recall.test.ts fails if a rule change drops below these numbers; raise them when recall improves.
 */
export const CORPUS_RECALL = { total: 108, highCritical: 92, withMedium: 107 } as const;

export const corpusPct = (n: number): number => Math.round((100 * n) / CORPUS_RECALL.total);
