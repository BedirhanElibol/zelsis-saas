import { test } from 'node:test';
import assert from 'node:assert/strict';
import { trustPageShareLinks } from '../../lib/share-links';

const url = 'https://zelsis.com/verified/acme';

test('a clear trust page gets X and LinkedIn links with the encoded URL', () => {
  const links = trustPageShareLinks(url, 'Acme', 0);
  assert.deepEqual(links.map((l) => l.label), ['Share on X', 'Share on LinkedIn']);
  assert.ok(links[0].href.includes(encodeURIComponent(url)));
  assert.ok(links[0].href.includes(encodeURIComponent('Acme is checked by Zelsis')));
  assert.ok(links[1].href.startsWith('https://www.linkedin.com/sharing/share-offsite/?url='));
});

test('no share links while issues are open or before the page is live', () => {
  assert.deepEqual(trustPageShareLinks(url, 'Acme', 2), []);
  assert.deepEqual(trustPageShareLinks(undefined, 'Acme', 0), []);
});
