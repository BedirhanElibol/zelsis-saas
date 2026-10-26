'use client';

import { useEffect } from 'react';
import { usePathname } from 'next/navigation';
import { recordSiteEvent } from '@/actions/site-events';

/** Where the visit came from: utm_source, else the referring site's hostname, else "direct". */
function visitSource(): string {
  try {
    const utm = new URLSearchParams(window.location.search).get('utm_source');
    if (utm) return utm.toLowerCase().replace(/[^a-z0-9.\-_]/g, '').slice(0, 60) || 'direct';
    if (document.referrer) {
      const host = new URL(document.referrer).hostname.replace(/^www\./, '').toLowerCase();
      if (host && host !== window.location.hostname.replace(/^www\./, '')) return host.slice(0, 60);
    }
  } catch {
    /* unreadable referrer: count as direct */
  }
  return 'direct';
}

const SOURCE_KEY = 'zelsis:visit-source';

/**
 * Counts page views and clicks on calls to action, anonymously and without cookies. The visit source is kept in
 * sessionStorage only so later pages of the same visit keep the source of the first one.
 */
export function SiteEvents() {
  const pathname = usePathname();

  useEffect(() => {
    let source = 'direct';
    try {
      source = sessionStorage.getItem(SOURCE_KEY) ?? '';
      if (!source) {
        source = visitSource();
        sessionStorage.setItem(SOURCE_KEY, source);
      }
    } catch {
      source = visitSource();
    }
    void recordSiteEvent({ kind: 'view', path: pathname || '/', source, label: '' }).catch(() => {});
  }, [pathname]);

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      const el = (e.target as HTMLElement | null)?.closest('a,button') as HTMLElement | null;
      if (!el) return;
      let label = el.getAttribute('data-track') ?? '';
      if (!label && el instanceof HTMLAnchorElement) {
        try {
          const url = new URL(el.href, window.location.href);
          if (url.origin !== window.location.origin) return;
          if (/^\/(dashboard|checkout|open-source|agencies|guides)/.test(url.pathname)) label = `to:${url.pathname}`.slice(0, 40);
        } catch {
          return;
        }
      }
      if (!label) return;
      let source = 'direct';
      try {
        source = sessionStorage.getItem(SOURCE_KEY) || 'direct';
      } catch {
        /* storage blocked */
      }
      void recordSiteEvent({ kind: 'cta', path: window.location.pathname, source, label }).catch(() => {});
    };
    document.addEventListener('click', onClick, { capture: true });
    return () => document.removeEventListener('click', onClick, { capture: true });
  }, []);

  return null;
}
