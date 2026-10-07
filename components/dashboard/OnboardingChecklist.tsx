import React, { useState } from 'react';
import { Project } from '@/data/schema';
import { CheckCircle2, Circle, Copy, Check } from 'lucide-react';
import { buildGateWorkflow } from '@/lib/ci-gate-snippet';
import { getConfiguredAppUrl } from '@/lib/app-url';
import { badgeUrlFor } from '@/lib/badge-url';

interface OnboardingChecklistProps {
  project: Project;
}

export const OnboardingChecklist: React.FC<OnboardingChecklistProps> = ({ project }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

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
      description: 'Block PRs that fail security or UI quality checks.',
      isComplete: false, // In a real app, this would check if the webhook/app is installed
      snippet: buildGateWorkflow({ appUrl: getConfiguredAppUrl(), projectName: project.name }),
    },
    {
      id: 'badge',
      title: 'Add Status Badge',
      description: 'Show off your readiness score in your README.',
      isComplete: false,
      snippet: badgeUrlFor(project, getConfiguredAppUrl())
        ? `[![Zelsis Gate](${badgeUrlFor(project, getConfiguredAppUrl())})](${getConfiguredAppUrl()})`
        : 'Scan a public GitHub repository to get a badge for it.',
    },
  ];

  const progress = (steps.filter(s => s.isComplete).length / steps.length) * 100;

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

            {step.snippet && !step.isComplete && (
              <div className="ml-7 mt-2 relative group">
                <pre className="bg-black/50 border border-white/10 rounded-lg p-3 text-[10px] text-zinc-300 overflow-x-auto">
                  <code>{step.snippet}</code>
                </pre>
                <button
                  onClick={() => handleCopy(step.snippet!, index)}
                  className="absolute top-2 right-2 p-1.5 bg-[#1A1A1A] border border-white/10 rounded text-[#A1A1AA] hover:text-white hover:bg-white/10 transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
                  aria-label="Copy snippet"
                >
                  {copiedIndex === index ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
