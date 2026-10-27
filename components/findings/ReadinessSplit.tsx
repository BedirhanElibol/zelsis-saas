import React from 'react';
import { ShieldCheck, Users } from 'lucide-react';
import type { Finding } from '@/data/schema';

const RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const rank = (f: Finding) => RANK[f.severity] ?? 1;

/** Bugs a user would notice: logic, payments, performance, screens and anything that looks unfinished. */
export const isUserFacing = (f: Finding) =>
  f.type === 'VIBECARE' || f.type === 'VIBEPOLISH' || /perf|payment|checkout|accessib|cliché|cliche/i.test(f.category || '');

function verdict(list: Finding[]) {
  const top = list.reduce((m, f) => Math.max(m, rank(f)), 0);
  if (top >= 3) return { label: 'Blocking', tone: 'text-red-300 border-red-500/30 bg-red-500/10' };
  if (top === 2) return { label: 'Needs a look', tone: 'text-amber-200 border-amber-500/30 bg-amber-500/10' };
  return { label: 'Clear', tone: 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10' };
}

/** Two answers per scan: is the code safe, and is the app ready for the people who will use it. */
export function ReadinessSplit({ findings }: { findings: Finding[] }) {
  const open = findings.filter((f) => f && f.status !== 'RESOLVED' && !f.falsePositive);
  const users = open.filter(isUserFacing);
  const security = open.filter((f) => !isUserFacing(f));
  const firstNoticed = [...users].sort((a, b) => rank(b) - rank(a)).slice(0, 3);

  const cards = [
    { key: 'security', title: 'Security', hint: 'Can someone break in or read data they should not?', icon: ShieldCheck, list: security },
    { key: 'users', title: 'Ready for users', hint: 'Will people hit a bug, a slow page or something that looks unfinished?', icon: Users, list: users },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {cards.map(({ key, title, hint, icon: Icon, list }) => {
        const v = verdict(list);
        return (
          <div key={key} className="rounded-xl border border-white/10 bg-[#0E0E10] p-4 flex flex-col gap-2">
            <div className="flex items-center justify-between gap-3">
              <span className="flex items-center gap-2 text-sm font-semibold text-white">
                <Icon size={16} className="text-zinc-400" aria-hidden="true" /> {title}
              </span>
              <span className={`px-2 py-0.5 rounded border text-xs font-mono ${v.tone}`}>{v.label}</span>
            </div>
            <p className="text-xs text-zinc-400">{hint}</p>
            <p className="text-xs font-mono text-zinc-300">{list.length} open {list.length === 1 ? 'finding' : 'findings'}</p>
            {key === 'users' && firstNoticed.length > 0 && (
              <ul className="mt-1 flex flex-col gap-1 text-xs text-zinc-300">
                <li className="text-zinc-400">What users would notice first:</li>
                {firstNoticed.map((f) => (
                  <li key={f.id} className="truncate">
                    <span className="font-mono text-zinc-500">{f.severity}</span> {f.title}
                  </li>
                ))}
              </ul>
            )}
          </div>
        );
      })}
    </div>
  );
}
