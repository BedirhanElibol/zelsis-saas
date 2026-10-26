import React, { useEffect, useState } from 'react';
import { Project } from '@/data/schema';
import { CheckCircle2, Circle, Copy, Check, GitPullRequest } from 'lucide-react';
import { fetchLastGateRunAt } from '@/lib/supabase';
import { buildGateWorkflow } from '@/lib/ci-gate-snippet';
import { getConfiguredAppUrl } from '@/lib/app-url';
import { badgeUrlFor } from '@/lib/badge-url';

interface OnboardingChecklistProps {
  project: Project;
}

export const OnboardingChecklist: React.FC<OnboardingChecklistProps> = ({ project }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [gateRunAt, setGateRunAt] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (project?.id) void fetchLastGateRunAt(project.id).then((at) => !cancelled && setGateRunAt(at)).catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [project?.id]);

  const steps = [
    {
      id: 'connect',
      title: 'Connect Repository',
      description: 'Link your GitHub or GitLab repository to Zelsis.',
      isComplete: !!project && !!project.repoUrl,
    },
    {
      id: 'scan',
      title: 'First Scan',
      description: 'Run your first deep code analysis and security scan.',
      isComplete: !!project && !!project.lastScanAt,
    },
    {
      id: 'gate',
      title: 'Add CI Gate',
      description: '3 steps: create an API key in Settings & API Keys, add it to your GitHub repo as the ZELSIS_API_KEY secret, then commit the workflow below to .github/workflows/zelsis.yml.',
      link: { href: '/dashboard?nav=cicd', label: 'Open the CI setup page' },
      // Complete once a pull request or CI scan has reached the gate for this project
      isComplete: !!gateRunAt,
      snippet: buildGateWorkflow({ appUrl: getConfiguredAppUrl(), projectName: project.name }),
    },
    {
      id: 'badge',
      title: 'Add Status Badge',
      description: 'Show off your readiness score in your README.',
      isComplete: false,
      snippet: badgeUrlFor(project, getConfiguredAppUrl())
        ? `[![Zelsis Gate](${badgeUrlFor(project, getConfiguredAppUrl())})](${getConfiguredAppUrl()}/?ref=badge)`
        : 'Scan a public GitHub repository to get a badge for it.',
    },
  ];

  const progress = (steps.filter(s => s.isComplete).length / steps.length) * 100;
  // Right after the first scan, the next step that matters is running the same check on every pull request
  const nudgeGate = !!project?.lastScanAt && !gateRunAt;

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl overflow-hidden flex flex-col font-mono">
      <div className="p-4 border-b border-white/10 bg-white/5 flex items-center justify-between">
        <h3 className="text-white font-bold flex items-center gap-2">
          <span>🚀</span> Onboarding Checklist
        </h3>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-[#A1A1AA]">{Math.round(progress)}% Complete</span>
          <div className="w-24 h-2 bg-black rounded-full overflow-hidden">
            <div 
              className="h-full bg-emerald-500 transition-all duration-500"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      </div>

      {nudgeGate && (
        <div className="p-4 border-b border-emerald-500/20 bg-emerald-500/5 flex flex-col sm:flex-row sm:items-center gap-3">
          <GitPullRequest size={18} className="text-emerald-400 shrink-0" aria-hidden="true" />
          <div className="flex-1 font-sans">
            <p className="text-sm font-semibold text-white">Next: run this check on every pull request</p>
            <p className="text-xs text-[#A1A1AA] mt-0.5">
              This scan covered today&apos;s code. Add the gate and each pull request gets the same check, with findings on the changed
              lines and a failed check when something critical gets in. It takes about two minutes.
            </p>
          </div>
          <a
            href="/dashboard?nav=cicd"
            data-track="onboarding-add-gate"
            className="shrink-0 px-3 py-2 rounded-lg bg-emerald-500 text-black text-xs font-bold hover:bg-emerald-400 font-sans"
          >
            Add it to my pull requests
          </a>
        </div>
      )}

      <div className="flex flex-col divide-y divide-white/5">
        {steps.map((step, index) => (
          <div key={step.id} className="p-4 flex flex-col gap-3">
            <div className="flex items-start gap-3">
              <div className="mt-0.5">
                {step.isComplete ? (
                  <CheckCircle2 size={16} className="text-emerald-500" />
                ) : (
                  <Circle size={16} className="text-zinc-600" />
                )}
              </div>
              <div className="flex-1 flex flex-col gap-1">
                <span className={`text-sm font-bold ${step.isComplete ? 'text-[#A1A1AA] line-through' : 'text-white'}`}>
                  {step.title}
                </span>
                <span className="text-xs text-[#A1A1AA]">
                  {step.description}
                </span>
              </div>
            </div>

            {'link' in step && step.link && !step.isComplete && (
              <a href={step.link.href} className="ml-7 w-fit text-xs font-bold text-emerald-400 hover:text-emerald-300 underline underline-offset-2">
                {step.link.label} →
              </a>
            )}

            {step.snippet && !step.isComplete && (
              <details className="ml-7 mt-1 relative" open={step.id !== 'gate'}>
                <summary className="cursor-pointer text-xs text-[#A1A1AA] hover:text-white">{step.id === 'gate' ? 'Show the workflow file' : 'Show the snippet'}</summary>
                <pre className="bg-black/50 border border-white/10 rounded-lg p-3 text-[10px] text-zinc-300 overflow-x-auto">
                  <code>{step.snippet}</code>
                </pre>
                <button
                  onClick={() => handleCopy(step.snippet!, index)}
                  className="absolute top-8 right-2 p-1.5 bg-[#1A1A1A] border border-white/10 rounded text-[#A1A1AA] hover:text-white hover:bg-white/10 transition-colors focus:outline-none focus:ring-2 focus:ring-emerald-500"
                  aria-label="Copy snippet"
                >
                  {copiedIndex === index ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                </button>
              </details>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
