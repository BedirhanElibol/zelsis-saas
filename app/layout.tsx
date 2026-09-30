import type { Metadata, Viewport } from 'next';
import localFont from 'next/font/local';
import { JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { OfflineBanner } from '@/components/ui/OfflineBanner';
import { ToastProvider } from '@/lib/toast';
import { CookieBanner } from '@/components/CookieBanner';
import { AnalyticsScripts } from '@/components/analytics/AnalyticsScripts';
import { ChunkErrorListener } from '@/components/common/ChunkErrorListener';

const satoshi = localFont({
  src: [
    { path: '../public/fonts/Satoshi-Regular.woff2', weight: '400', style: 'normal' },
    { path: '../public/fonts/Satoshi-Medium.woff2', weight: '500', style: 'normal' },
    { path: '../public/fonts/Satoshi-Bold.woff2', weight: '700', style: 'normal' },
    { path: '../public/fonts/Satoshi-Black.woff2', weight: '900', style: 'normal' },
  ],
  variable: '--font-satoshi',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '700'],
  variable: '--font-jetbrains-mono',
  display: 'swap',
});

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
  interactiveWidget: 'resizes-content',
};

function getMetadataBase(): URL {
  const raw = process.env.NEXT_PUBLIC_APP_URL ?? (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null);
  if (!raw || typeof raw !== 'string' || !raw.trim()) {
    return new URL('https://zelsis.com');
  }
  const trimmed = raw.trim();
  const withProtocol = trimmed.startsWith('http://') || trimmed.startsWith('https://')
    ? trimmed
    : `https://${trimmed}`;
  try {
    return new URL(withProtocol);
  } catch {
    return new URL('https://zelsis.com');
  }
}

export const metadata: Metadata = {
  metadataBase: getMetadataBase(),
  title: {
    default: 'Zelsis | Production Release Gate for Modern Web & Cloud Apps',
    template: '%s | Zelsis',
  },
  description:
    'Automated pre-flight security clearance, WCAG 2.2 AA accessibility, and cloud infrastructure release gatekeeper for modern web and cloud applications.',
  keywords: [
    'Zelsis',
    'Release Gate',
    'Security Audit',
    'OWASP Security',
    'Code Quality',
    'Production Readiness',
    'DevOps CI/CD',
    'Next.js',
  ],
  alternates: {
    canonical: './',
  },
  openGraph: {
    title: 'Zelsis | Production Release Gate for Modern Web & Cloud Apps',
    description:
      'Automated pre-flight security clearance, WCAG 2.2 AA accessibility, and cloud infrastructure release gatekeeper for modern web and cloud applications.',
    url: './',
    siteName: 'Zelsis',
    images: [
      {
        url: '/og-image.png',
        width: 1200,
        height: 630,
        type: 'image/png',
        alt: 'Zelsis | Production Release Gate for Modern Web & Cloud Apps',
      },
    ],
    locale: 'en_US',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Zelsis | Production Release Gate for Modern Web & Cloud Apps',
    description:
      'Automated pre-flight security clearance, WCAG 2.2 AA accessibility, and cloud infrastructure release gatekeeper for modern web and cloud applications.',
    images: ['/og-image.png'],
  },
  icons: {
    icon: [
      { url: '/favicon.svg?v=2', type: 'image/svg+xml' },
      { url: '/favicon.ico?v=2', sizes: 'any' },
    ],
    shortcut: '/favicon.svg?v=2',
    apple: '/favicon.png?v=2',
  },
  manifest: '/manifest.webmanifest',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`dark notranslate ${satoshi.variable} ${jetbrainsMono.variable}`} translate="no" suppressHydrationWarning>
      <head>
        <title>Zelsis | Automated Codebase Security &amp; Release Gate</title>
        <meta name="description" content="Prove your application is secure, polished, and ready for production before launch. Comprehensive OWASP security pre-flight checks and automated code verification." />
        <meta property="og:title" content="Zelsis | Automated Codebase Security &amp; Release Gate" />
        <meta property="og:description" content="Prove your application is secure, polished, and ready for production before launch." />
      </head>
      <body className="bg-[#0A0A0A] text-[#EDEDED] antialiased selection:bg-white selection:text-black notranslate" translate="no" suppressHydrationWarning>
        <ChunkErrorListener />
        <AnalyticsScripts />
        <a href="#main-content" className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-white focus:text-black focus:rounded-md focus:font-mono focus:text-xs">Skip to main content</a>
        <OfflineBanner />
        <ToastProvider>
          <main id="main-content">
            {children}
          </main>
          <CookieBanner />
        </ToastProvider>
      </body>
    </html>
  );
}
