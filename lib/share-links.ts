/** X and LinkedIn share URLs for a public trust page. Empty while the page shows open issues. */
export function trustPageShareLinks(url: string | undefined, name: string, blockers: number | undefined): { label: string; href: string }[] {
  if (!url || blockers) return [];
  const text = `${name || 'Our app'} is checked by Zelsis before every release:`;
  return [
    { label: 'Share on X', href: `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}` },
    { label: 'Share on LinkedIn', href: `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(url)}` },
  ];
}
