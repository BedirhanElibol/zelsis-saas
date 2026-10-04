import React from 'react';

export const metadata = { title: 'Getting Started - Zelsis Docs' };

export default function GettingStartedPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Getting Started</h1>
      <p className="text-zinc-400">Welcome to Zelsis! Start scanning your code in minutes.</p>

      <section className="space-y-4 mt-8">
        <h2 className="text-xl font-semibold text-white">1. Account Setup</h2>
        <p>
          Sign up using GitHub or email. Upon signing in, you will be directed to your personal workspace. 
          Enterprise users can access dedicated organization workspaces with team management.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">2. Public Repo Scanning</h2>
        <p>
          You don\'t need to provide a GitHub token to scan public repositories. Simply enter the URL of any public GitHub repository 
          (e.g., <code>github.com/owner/repo</code>) into the top search bar and press <strong>Scan</strong>. 
          Zelsis will automatically clone and analyze the codebase.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">3. Your First Scan</h2>
        <p>
          When you trigger a scan, Zelsis performs a multi-phase audit:
        </p>
        <ul className="list-disc pl-5 space-y-2">
          <li><strong>Code Retrieval:</strong> Fetches the target repository (using your personal access token for private repos).</li>
          <li><strong>Static Analysis:</strong> Scans for security vulnerabilities (OWASP, secrets, injection).</li>
          <li><strong>UI & Accessibility:</strong> Checks frontend code for WCAG 2.2 AA compliance and UI standard violations.</li>
          <li><strong>Infrastructure:</strong> Audits Next.js configurations, database schemas, and CI/CD pipelines.</li>
        </ul>
        <p>
          The dashboard will display a comprehensive <strong>Readiness Score</strong> along with detailed findings categorized by severity.
        </p>
      </section>
    </div>
  );
}
