import { MetadataRoute } from 'next';
import { getConfiguredAppUrl } from '@/lib/app-url';

export default function robots(): MetadataRoute.Robots {
  const baseUrl = getConfiguredAppUrl();

  return {
    rules: {
      userAgent: '*',
      allow: '/',
      disallow: ['/api/'],
    },
    sitemap: `${baseUrl}/sitemap.xml`,
  };
}
