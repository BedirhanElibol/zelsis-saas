const SITE = 'https://zelsis.com';

// Lets search and AI tools recognise Zelsis as one product by one organization.
const data = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'Organization',
      '@id': `${SITE}/#organization`,
      name: 'Zelsis',
      url: SITE,
      sameAs: ['https://x.com/zelsisapp'],
    },
    {
      '@type': 'SoftwareApplication',
      '@id': `${SITE}/#product`,
      name: 'Zelsis',
      url: SITE,
      applicationCategory: 'DeveloperApplication',
      operatingSystem: 'Web',
      description:
        'Checks every pull request before it merges for security issues and for what users of the app would hit, and fails the build when a critical bug gets in.',
      publisher: { '@id': `${SITE}/#organization` },
    },
  ],
};

export function ProductJsonLd() {
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data).replace(/</g, '\u003c') }}
    />
  );
}
