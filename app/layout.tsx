import type { Metadata, Viewport } from 'next';
import localFont from 'next/font/local';
import { JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { OfflineBanner } from '@/components/ui/OfflineBanner';
import { ToastProvider } from '@/lib/toast';
import { CookieBanner } from '@/components/CookieBanner';
import { AnalyticsScripts } from '@/components/analytics/AnalyticsScripts';
import { ChunkErrorListener } from '@/components/common/ChunkErrorListener';
import { getConfiguredAppUrl } from '@/lib/app-url';

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

// Canonical, og:url and og:image resolve against this: it must be a live host (see lib/app-url.ts)
function getMetadataBase(): URL {
  return new URL(getConfiguredAppUrl());
}

export const metadata: Metadata = {
  metadataBase: getMetadataBase(),
  title: {
    default: 'Zelsis | Security Scanner & Release Gate for Web Apps',
    template: '%s | Zelsis',
  },
  description:
    'Scan your GitHub repository for leaked secrets, open Supabase RLS policies, injection and vulnerable dependencies. Free for public repos, with a CI gate that fails the release on critical issues.',
  keywords: [
    'Zelsis',
    'Release Gate',
    'Security Audit',
    'OWASP Security',
    'Code Quality',
    'Production Readiness',
    'DevOps CI/CD',
    'Next.js',
    'Supabase RLS',
    'Secret Scanning',
    'SAST',
  ],
  alternates: {
    canonical: './',
  },
  openGraph: {
    title: 'Zelsis | Security Scanner & Release Gate for Web Apps',
    description:
      'Scan your GitHub repository for leaked secrets, open Supabase RLS policies, injection and vulnerable dependencies. Free for public repos, with a CI gate that fails the release on critical issues.',
    url: './',
    siteName: 'Zelsis',
    images: [
      {
        url: '/og-image.png',
        width: 1200,
        height: 630,
        type: 'image/png',
        alt: 'Zelsis | Security Scanner & Release Gate for Web Apps',
      },
    ],
    locale: 'en_US',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Zelsis | Security Scanner & Release Gate for Web Apps',
    description:
      'Scan your GitHub repository for leaked secrets, open Supabase RLS policies, injection and vulnerable dependencies. Free for public repos, with a CI gate that fails the release on critical issues.',
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
