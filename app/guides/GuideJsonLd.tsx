'use client';

import { usePathname } from 'next/navigation';
import { GUIDES } from './guides';

const SITE = 'https://zelsis.com';

/** Article structured data for each guide page; dates appear only when the guide has real ones. */
export function GuideJsonLd() {
  const slug = (usePathname() ?? '').split('/').filter(Boolean)[1];
  const guide = GUIDES.find((g) => g.slug === slug);
  if (!guide) return null;

  const data = {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: guide.title,
    description: guide.summary,
    mainEntityOfPage: `${SITE}/guides/${guide.slug}`,
    ...(guide.published ? { datePublished: guide.published } : {}),
    ...(guide.updated ? { dateModified: guide.updated } : {}),
    author: { '@type': 'Organization', name: 'Zelsis', url: SITE },
    publisher: { '@type': 'Organization', name: 'Zelsis', url: SITE },
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data).replace(/</g, '\u003c') }}
    />
  );
}
