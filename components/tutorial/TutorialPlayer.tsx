'use client';

import React, { useRef, useState } from 'react';

/** Start times (seconds) in public/videos/zelsis-tutorial.mp4. */
const CHAPTERS: { t: number; part: 1 | 2; title: string }[] = [
  { t: 8.3, part: 1, title: 'Overview' },
  { t: 16.1, part: 1, title: 'Connected Projects' },
  { t: 24.0, part: 1, title: 'Scan History' },
  { t: 31.8, part: 1, title: 'Security' },
  { t: 39.7, part: 1, title: 'Legal & Privacy' },
  { t: 47.6, part: 1, title: 'Infra & Database' },
  { t: 55.4, part: 1, title: 'Design & UX' },
  { t: 63.3, part: 1, title: 'Logic Bugs' },
  { t: 71.1, part: 1, title: 'All Rules' },
  { t: 78.9, part: 1, title: 'Fix Queue' },
  { t: 86.8, part: 1, title: 'CI/CD' },
  { t: 100.4, part: 2, title: 'Connect a repository' },
  { t: 108.5, part: 2, title: 'Run the check' },
  { t: 124.1, part: 2, title: 'Read the verdict' },
  { t: 129.2, part: 2, title: 'Security and Ready for users' },
  { t: 136.5, part: 2, title: 'Filter the findings' },
  { t: 144.6, part: 2, title: 'Open a finding' },
  { t: 151.1, part: 2, title: 'Copy the fix prompt' },
  { t: 163.7, part: 2, title: 'Add the check to pull requests' },
];

const fmt = (t: number) => `${Math.floor(t / 60)}:${String(Math.floor(t % 60)).padStart(2, '0')}`;

export function TutorialPlayer() {
  const ref = useRef<HTMLVideoElement>(null);
  const [now, setNow] = useState(0);
  const active = [...CHAPTERS].reverse().find((c) => now >= c.t - 0.2);
  const seek = (t: number) => {
    const v = ref.current;
    if (!v) return;
    v.currentTime = t;
    void v.play().catch(() => {});
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_300px] gap-6">
      <video
        ref={ref}
        src="/videos/zelsis-tutorial.mp4"
        poster="/videos/zelsis-tutorial.jpg"
        controls
        playsInline
        preload="metadata"
        onTimeUpdate={(e) => setNow(e.currentTarget.currentTime)}
        aria-label="Zelsis tutorial: every part of the dashboard, then one full check from a GitHub URL to a check on every pull request"
        className="w-full aspect-video rounded-xl border border-white/10 bg-black"
      />
      <nav aria-label="Chapters" className="rounded-xl border border-white/10 bg-[#111113] p-3 max-h-[560px] overflow-y-auto">
        {[1, 2].map((part) => (
          <div key={part} className="mb-3">
            <p className="px-2 py-1.5 text-xs font-mono uppercase tracking-widest text-emerald-400">
              {part === 1 ? '1 · The dashboard' : '2 · One full check'}
            </p>
            <ul>
              {CHAPTERS.filter((c) => c.part === part).map((c) => (
                <li key={c.t}>
                  <button
                    type="button"
                    onClick={() => seek(c.t)}
                    aria-current={active === c ? 'true' : undefined}
                    className={`w-full flex items-center justify-between gap-3 px-2 min-h-10 rounded-md text-left text-sm cursor-pointer ${active === c ? 'bg-white/10 text-white' : 'text-zinc-300 hover:bg-white/5'}`}
                  >
                    <span>{c.title}</span>
                    <span className="font-mono text-xs text-zinc-500">{fmt(c.t)}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
    </div>
  );
}
