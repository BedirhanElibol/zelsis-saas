import React from 'react';
import { ExternalLink } from 'lucide-react';

/**
 * GitHub's fine-grained token form, pre-filled: name, description, 90-day expiry and read-only Contents.
 * The user only picks the repository and clicks "Generate token".
 */
export const GITHUB_TOKEN_URL =
  'https://github.com/settings/personal-access-tokens/new?name=Zelsis%20scan&description=Read-only%20access%20so%20Zelsis%20can%20scan%20this%20repository&expires_in=90&contents=read';

/** Three-step guide for scanning a private repository, shown wherever a token is asked for. */
export function GithubTokenSteps({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`rounded-xl border border-white/10 bg-[#0A0A0A] ${compact ? 'p-3' : 'p-3.5'} flex flex-col gap-2.5 text-[11px] text-[#A1A1AA]`}>
      <p className="m-0 text-[#EDEDED] font-semibold text-xs">Private repository? It takes about a minute:</p>
      <ol className="m-0 pl-4 list-decimal flex flex-col gap-1.5 leading-relaxed">
        <li>
          Open GitHub&apos;s token page. We pre-filled it with <strong className="text-white">read-only</strong> access, so Zelsis can read your code but never change it.
        </li>
        <li>
          Under <strong className="text-white">Repository access</strong>, choose <strong className="text-white">Only select repositories</strong> and pick this repo, then click <strong className="text-white">Generate token</strong>.
        </li>
        <li>Copy the token (it starts with <code className="text-white">github_pat_</code>) and paste it here.</li>
      </ol>
      <a
        href={GITHUB_TOKEN_URL}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center justify-center gap-1.5 w-fit px-3 py-1.5 rounded-lg bg-white text-black font-semibold text-xs hover:bg-zinc-200 transition-colors"
      >
        Create a read-only token on GitHub
        <ExternalLink size={12} />
      </a>
      <p className="m-0 text-[10px] text-zinc-500">
        Zelsis keeps the token only in this browser tab and uses it to download the files for the scan; it is never saved on our servers. You can revoke it on GitHub at any time.
      </p>
    </div>
  );
}
