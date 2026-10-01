/**
 * Generates one synthetic credential per secret rule (lib/rules/secrets-rules.ts) from the rule's own
 * regex, keeping only samples the regex really matches. Samples are stored reversed so repository
 * secret scanners do not treat them as leaked credentials. The test in tests/rules/secret-samples.test.ts
 * proves each rule fires on its sample and stays silent on the env-var version.
 *
 * Run: npx tsx scripts/gen-secret-fixtures.ts
 */
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const root = join(__dirname, '..');
const src = readFileSync(join(root, 'lib/rules/secrets-rules.ts'), 'utf8');

// Deterministic pseudo-random choice so samples look like tokens, not placeholders (xxxx, 0000).
let seed = 7;
const rand = (n: number) => {
  seed = (seed * 1103515245 + 12345) % 2147483648;
  return Math.floor((seed / 2147483648) * n);
};

type CharSet = { ranges: [number, number][]; negated: boolean };

const DIGITS: CharSet = { ranges: [[48, 57]], negated: false };
const WORD: CharSet = { ranges: [[48, 57], [65, 90], [97, 122]], negated: false };

function pick(set: CharSet): string {
  if (set.negated) {
    const candidates = 'kQ7mZr3pW9bT'.split('').filter((c) => !set.ranges.some(([a, b]) => c.charCodeAt(0) >= a && c.charCodeAt(0) <= b));
    return candidates[rand(candidates.length)] ?? 'q';
  }
  const total = set.ranges.reduce((n, [a, b]) => n + (b - a + 1), 0);
  let k = rand(total);
  for (const [a, b] of set.ranges) {
    if (k <= b - a) return String.fromCharCode(a + k);
    k -= b - a + 1;
  }
  return 'a';
}

/** Minimal regex-to-sample generator: first alternative, minimum repetition (1 for + and *). */
function generate(source: string): string {
  let i = 0;
  const parseSeq = (): (() => string)[] => {
    const atoms: (() => string)[] = [];
    while (i < source.length && source[i] !== '|' && source[i] !== ')') {
      let atom: () => string;
      const c = source[i];
      if (c === '\\') {
        const e = source[i + 1];
        i += 2;
        if (e === 'b' || e === 'B') { atom = () => ''; }
        else if (e === 'd') atom = () => pick(DIGITS);
        else if (e === 'w') atom = () => pick(WORD);
        else if (e === 's') atom = () => ' ';
        else if (e === 'S') atom = () => 'k';
        else atom = () => e;
      } else if (c === '[') {
        i++;
        const set: CharSet = { ranges: [], negated: false };
        if (source[i] === '^') { set.negated = true; i++; }
        while (i < source.length && source[i] !== ']') {
          let ch = source[i];
          if (ch === '\\') {
            const e = source[i + 1];
            i += 2;
            if (e === 'd') { set.ranges.push([48, 57]); continue; }
            if (e === 'w') { set.ranges.push(...WORD.ranges, [95, 95]); continue; }
            if (e === 's') { set.ranges.push([32, 32], [9, 10]); continue; }
            ch = e;
          } else i++;
          if (source[i] === '-' && source[i + 1] && source[i + 1] !== ']') {
            let end = source[i + 1];
            i += 2;
            if (end === '\\') { end = source[i]; i++; }
            set.ranges.push([ch.charCodeAt(0), end.charCodeAt(0)]);
          } else set.ranges.push([ch.charCodeAt(0), ch.charCodeAt(0)]);
        }
        i++;
        atom = () => pick(set);
      } else if (c === '(') {
        i++;
        let lookaround = false;
        if (source[i] === '?') {
          if (source[i + 1] === '=' || source[i + 1] === '!') { lookaround = true; i += 2; }
          else if (source[i + 1] === '<' && (source[i + 2] === '=' || source[i + 2] === '!')) { lookaround = true; i += 3; }
          else if (source[i + 1] === ':') i += 2;
          else if (source[i + 1] === '<') i = source.indexOf('>', i) + 1;
        }
        const alternatives: (() => string)[][] = [parseSeq()];
        while (source[i] === '|') { i++; alternatives.push(parseSeq()); }
        i++;
        const first = alternatives[0];
        atom = lookaround ? () => '' : () => first.map((a) => a()).join('');
      } else if (c === '.') { i++; atom = () => 'k'; }
      else if (c === '^' || c === '$') { i++; atom = () => ''; }
      else { i++; atom = () => c; }

      let times = 1;
      const q = source[i];
      if (q === '{') {
        const m = source.slice(i).match(/^\{(\d+)(?:,(\d*))?\}/);
        if (m) { times = Number(m[1]); i += m[0].length; }
      } else if (q === '+' || q === '*') { times = 1; i++; }
      else if (q === '?') { times = 1; i++; }
      if (source[i] === '?') i++; // lazy modifier
      const base = atom;
      atoms.push(() => Array.from({ length: times }, base).join(''));
    }
    return atoms;
  };
  const alternatives = [parseSeq()];
  while (source[i] === '|') { i++; alternatives.push(parseSeq()); }
  return alternatives[0].map((a) => a()).join('');
}

const samples: [number, string][] = [];
const skipped: number[] = [];
for (const m of src.matchAll(/const pattern\d+ = (\/.+\/[a-z]*);\n/g)) {
  const after = src.slice(m.index! + m[0].length, m.index! + m[0].length + 1500);
  const ruleId = Number(after.match(/ruleId:\s*(\d+),/)?.[1]);
  const regex = new Function(`return ${m[1]}`)() as RegExp;
  const ok = (s: string) => regex.test(s) && !/placeholder|EXAMPLE|dummy|x{10,}|00000000/i.test(s);
  let sample = '';
  for (let attempt = 0; attempt < 50 && !ok(sample); attempt++) sample = generate(regex.source);
  if (ruleId && ok(sample)) samples.push([ruleId, sample]);
  else { skipped.push(ruleId); if (process.env.DEBUG_SAMPLES) console.log(ruleId, JSON.stringify(sample)); }
}

const reverse = (s: string) => [...s].reverse().join('');
const body = samples.map(([id, s]) => `  [${id}, ${JSON.stringify(reverse(s))}],`).join('\n');
writeFileSync(
  join(root, 'tests/rules/secret-samples.generated.ts'),
  `// Generated by scripts/gen-secret-fixtures.ts. Do not edit.\n// Synthetic credentials derived from each rule's regex, stored reversed (see SECRET_SAMPLES).\n\nconst RAW: [number, string][] = [\n${body}\n];\n\nexport const SECRET_SAMPLES: [number, string][] = RAW.map(([id, s]) => [id, [...s].reverse().join('')]);\n`
);
console.log(`secret samples: ${samples.length} generated, ${skipped.length} skipped${skipped.length ? ` (${skipped.join(', ')})` : ''}`);
