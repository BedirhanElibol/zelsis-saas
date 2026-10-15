export interface BlogPost {
  slug: string;
  title: string;
  summary: string;
  date: string; // ISO date, shown as published date
}

export const POSTS: BlogPost[] = [
  {
    slug: 'open-source-release-check',
    title: 'What a release check found in well-kept open-source apps',
    summary:
      'A fallback JWT secret, a storage policy that ignores the owner, containers running as root, CI actions pinned to tags and more, each with the fix.',
    date: '2026-10-15',
  },
];

export function formatPostDate(iso: string): string {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
}
