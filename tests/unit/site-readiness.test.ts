import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { checkSiteReadiness } from '../../lib/site-readiness';

const failing = (html: string, url = 'https://app.test/') =>
  checkSiteReadiness(html, url).filter((i) => !i.ok).map((i) => i.id).sort();

describe('site readiness check', () => {
  it('flags a starter template page', () => {
    const html = '<html><head><title>Create Next App</title></head><body><p>Lorem ipsum dolor sit amet</p></body></html>';
    assert.deepEqual(failing(html), ['description', 'icon', 'lang', 'og-image', 'placeholder', 'title', 'viewport']);
  });

  it('passes a finished page', () => {
    const html = `<html lang="en"><head><title>Invoicely | Invoices that chase themselves</title>
      <meta name="description" content="Send invoices and get paid on time, without writing reminder emails.">
      <meta property="og:image" content="https://invoicely.test/og.png">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <link rel="icon" href="/icon.svg"></head><body><h1>Get paid on time</h1></body></html>`;
    assert.deepEqual(failing(html), []);
  });

  it('reads unquoted attributes in minified HTML', () => {
    const html = '<!doctype html><html lang=en><head><meta charset=utf-8><link rel=icon href=/i.png><meta name=viewport content="width=device-width,initial-scale=1"><title>Example Domain</title></head><body><p>Hi</p></body></html>';
    assert.deepEqual(failing(html), ['description', 'og-image']);
  });

  it('flags plain http and accepts the /favicon.ico fallback', () => {
    const items = checkSiteReadiness('<html><head><title>Acme</title></head></html>', 'http://acme.test/', { faviconFallbackOk: true });
    assert.equal(items.find((i) => i.id === 'https')?.ok, false);
    assert.equal(items.find((i) => i.id === 'icon')?.ok, true);
  });
});
