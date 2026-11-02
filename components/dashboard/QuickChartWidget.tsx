'use client';

import React, { useState } from 'react';
import Image from 'next/image';
import { Project } from '@/data/schema';

interface QuickChartWidgetProps {
  project: Project;
}

export const QuickChartWidget: React.FC<QuickChartWidgetProps> = ({ project }) => {
  const [copied, setCopied] = useState(false);

  const safeFindings = Array.isArray(project?.findings) ? project.findings : [];
  const openFindings = safeFindings.filter((f) => f && f.status === 'OPEN');
  const critical = openFindings.filter((f) => f && f.severity === 'CRITICAL').length;
  const high = openFindings.filter((f) => f && f.severity === 'HIGH').length;
  const medium = openFindings.filter((f) => f && f.severity === 'MEDIUM').length;

  const chartConfig = {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium'],
      datasets: [
        {
          data: [critical, high, medium],
          backgroundColor: ['#EF4444', '#F59E0B', '#3B82F6']
        }
      ]
    },
    options: {
      plugins: {
        legend: { labels: { fontColor: '#FFFFFF' } }
      }
    }
  };

  const chartUrl = `https://quickchart.io/chart?c=${encodeURIComponent(JSON.stringify(chartConfig))}&w=400&h=200&bkg=transparent`;

  const handleCopyUrl = () => {
    navigator.clipboard.writeText(chartUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col gap-4">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-white/10 pb-3">
        <div className="flex items-center gap-3">
          <div>
            <h3 className="text-sm font-extrabold text-[#EDEDED]">
              Public API #2: QuickChart Dynamic Image Generator
            </h3>
            <p className="text-[0.68rem] text-[#94A3B8]">
              Serverless chart PNG generation for email briefs, slack alerts &amp; PDF reports
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopyUrl}
            className="btn btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5 font-mono"
          >
            <span>{copied ? 'Copied URL!' : 'Copy Chart Image URL'}</span>
          </button>
          <a
            href={chartUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5 font-mono"
          >
            <span>Open Image</span>
          </a>
        </div>
      </div>

      {/* Chart Render Preview */}
      <div className="flex flex-col sm:flex-row items-center justify-between bg-[#0A0A0A] p-4 rounded-xl border border-white/10 gap-4">
        <div className="text-xs text-[#94A3B8] space-y-1.5 max-w-sm">
          <div className="font-mono font-bold uppercase text-[0.68rem] text-white">
            SERVERLESS CHART EMBED LINK
          </div>
          <p>
            QuickChart renders vector charts directly to PNG images on demand. Paste this link in Markdown documents or Slack Webhook payloads:
          </p>
          <div className="bg-[#141414] p-2 rounded border border-white/10 font-mono text-[0.65rem] text-white truncate">
            {chartUrl}
          </div>
        </div>

        {/* Live QuickChart Image Render */}
        <div className="shrink-0 bg-[#070A12] p-2 rounded-xl border border-white/10 flex items-center justify-center">
          <Image
            src={chartUrl}
            alt="QuickChart Live Render"
            width={400}
            height={200}
            unoptimized
            className="max-h-36 object-contain"
          />
        </div>
      </div>
    </div>
  );
};
