'use client';

import React from 'react';
import { Copy, Terminal } from 'lucide-react';

export function FixPromptsDemo() {
  const handleCopy = () => {
    navigator.clipboard.writeText(`The Zelsis scanner found a vulnerability in this file:
Rule 28001: Server Action deletes with the service-role client without checking the caller.

Please refactor this Server Action to use \`createServerClient()\` and check \`auth.getUser()\` before performing the deletion.`);
    // A real app might show a toast here
  };

  return (
    <section className="py-24 bg-[#0A0A0A]">
      <div className="max-w-7xl mx-auto px-6 lg:px-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          <div>
            <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
              AI-ready fix prompts.
            </h2>
            <p className="mt-4 text-lg text-zinc-400">
              Don't spend hours figuring out how to patch a complex Next.js SSR vulnerability. 
              Zelsis provides exact context-aware prompts you can paste directly into Claude, ChatGPT, or Cursor to get the right fix instantly.
            </p>
          </div>
          
          <div className="bg-[#141414] border border-white/10 rounded-xl overflow-hidden shadow-2xl">
            <div className="bg-black/40 px-4 py-3 border-b border-white/5 flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm text-zinc-400">
                <Terminal className="w-4 h-4" />
                <span>AI Prompt Generator</span>
              </div>
              <button 
                onClick={handleCopy}
                className="text-xs flex items-center gap-1.5 bg-white/5 hover:bg-white/10 text-zinc-300 px-3 py-1.5 rounded transition-colors"
                aria-label="Copy to clipboard"
              >
                <Copy className="w-3.5 h-3.5" />
                Copy Prompt
              </button>
            </div>
            <div className="p-5 font-mono text-sm leading-relaxed text-zinc-300">
              <span className="text-emerald-400">The Zelsis scanner found a vulnerability in this file:</span><br/>
              Rule 28001: Server Action deletes with the service-role client without checking the caller.<br/><br/>
              Please refactor this Server Action to use <code>createServerClient()</code> and check <code>auth.getUser()</code> before performing the deletion.
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
