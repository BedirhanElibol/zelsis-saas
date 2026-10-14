import { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'Zelsis Release Gate',
    short_name: 'Zelsis',
    description: 'Release checks for web, mobile, SaaS, API and desktop apps: logic bugs, security, dependencies, UI and privacy.',
    start_url: '/',
    display: 'standalone',
    background_color: '#0D0D0D',
    theme_color: '#0D0D0D',
    icons: [
      {
        src: '/zelsis-logo.svg',
        sizes: 'any',
        type: 'image/svg+xml',
      },
    ],
  };
}
