import React from 'react';
import type { Metadata } from 'next';
import { GITHUB_TOKEN_URL } from '@/components/dashboard/GithubTokenSteps';

export const metadata: Metadata = {
  title: 'Scan a Private Repository - Zelsis Docs',
  description: 'Give Zelsis read-only access to a private GitHub repository with a fine-grained token in about a minute.',
};

export default function PrivateReposPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Scan a Private Repository</h1>
      <p className="text-zinc-400">
        Public repositories need nothing: paste the URL and scan. For a private repository, you can either connect our GitHub App in a few clicks (recommended) or provide a fine-grained read-only personal access token.
      </p>

      <section className="space-y-3">
        <h2 className="text-xl font-semibold text-white">Easiest: connect GitHub</h2>
        <p className="text-zinc-300">
          Connect your GitHub account directly to scan private repositories without creating or managing tokens:
        </p>
        <ol className="list-decimal pl-5 space-y-2 text-zinc-300">
          <li>Go to <strong className="text-white">Dashboard → Connected Projects</strong>.</li>
          <li>Click <strong className="text-white">Connect New AI App</strong>, then select <strong className="text-white">Connect GitHub</strong>.</li>
          <li>On GitHub, choose <strong className="text-white">Only select repositories</strong> and pick the repositories you want to scan, then click <strong className="text-white">Install</strong>.</li>
          <li>Back in Zelsis, pick the repository from your connected list.</li>
        </ol>
        <p className="text-zinc-400 text-sm">
          Already installed the app (another browser or account)? Use &quot;Already installed the Zelsis app on GitHub? Link it to this account&quot;.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className="text-xl font-semibold text-white">Alternative: a read-only token</h2>
        <p className="text-zinc-300">
          If you prefer not to install the GitHub App, you can open GitHub&apos;s token page with our settings already filled in (name, 90-day expiry, read-only access to code):
        </p>
        <a href={GITHUB_TOKEN_URL} target="_blank" rel="noopener noreferrer" className="inline-block bg-white text-black font-semibold text-sm px-4 py-2 rounded-lg no-underline hover:bg-zinc-200">
          Create a read-only token on GitHub
        </a>
        <p className="text-zinc-300">
          Under <strong className="text-white">Repository access</strong>, pick <strong className="text-white">Only select repositories</strong>, choose the
          repository you want to scan, then click <strong className="text-white">Generate token</strong>. If the repository belongs to an organization, choose
          that organization as the <strong className="text-white">Resource owner</strong> first (an admin may have to approve the token).
        </p>
        <h3 className="text-lg font-medium text-white pt-2">Paste it into Zelsis</h3>
        <ul className="list-disc pl-5 space-y-2 text-zinc-300">
          <li><strong className="text-white">New project:</strong> Dashboard → add a project → paste the repository URL and the token in the &quot;GitHub access token&quot; field.</li>
          <li><strong className="text-white">Quick scan:</strong> paste the URL and start the scan. When Zelsis sees the repository is private it asks for the token.</li>
          <li><strong className="text-white">CI release gate:</strong> the GitHub Action runs inside your repository, so it already has access. See <a href="/docs/ci-gate">CI Release Gate</a>.</li>
        </ul>
      </section>

      <section className="space-y-3">
        <h2 className="text-xl font-semibold text-white">What Zelsis can do with the app and token</h2>
        <ul className="list-disc pl-5 space-y-2 text-zinc-300">
          <li><strong className="text-white">GitHub App:</strong> Zelsis can read code and repository metadata for security scans. Checks and pull request permissions are used strictly to report automated CI/PR check results. Access can be revoked at any time in GitHub → Settings → Applications.</li>
          <li><strong className="text-white">Fine-grained token:</strong> It only has the read permission you chose; Zelsis cannot push, open pull requests, or change settings with it. The token stays in your browser tab and is sent with the scan request to download files—it is not saved in our database. You can revoke it at any time under GitHub → Settings → Developer settings → Fine-grained tokens.</li>
        </ul>
        <p className="text-zinc-400 text-sm">More about what is stored and for how long: <a href="/docs/data-handling">Data Handling</a>.</p>
      </section>

      <section className="space-y-3">
        <h2 className="text-xl font-semibold text-white">Troubleshooting</h2>
        <ul className="list-disc pl-5 space-y-2 text-zinc-300">
          <li><strong className="text-white">&quot;Repository not found&quot; with a token:</strong> the token does not include this repository. Edit the token on GitHub and add it under Repository access.</li>
          <li><strong className="text-white">Organization repository:</strong> the token&apos;s resource owner must be the organization, and some organizations require an admin to approve new tokens.</li>
          <li><strong className="text-white">Token expired:</strong> create a new one with the button above.</li>
        </ul>
      </section>
    </div>
  );
}
