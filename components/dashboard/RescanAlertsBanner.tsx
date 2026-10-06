'use client';

import React from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { getActiveUserAuth } from '@/lib/supabase-client';
import { listUnreadRescanAlerts, markRescanAlertRead, type RescanAlert } from '@/app/actions/project-notifications';

/** Unread alerts from scheduled weekly rescans that found new CRITICAL/HIGH findings. */
export function RescanAlertsBanner() {
  const [alerts, setAlerts] = React.useState<RescanAlert[]>([]);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      const { accessToken } = await getActiveUserAuth();
      if (!accessToken) return;
      const res = await listUnreadRescanAlerts(accessToken);
      if (!cancelled && res.status === 'success') setAlerts(res.alerts);
    })();
    return () => { cancelled = true; };
  }, []);

  const dismiss = async (id: string) => {
    setAlerts((prev) => prev.filter((a) => a.id !== id));
    const { accessToken } = await getActiveUserAuth();
    if (accessToken) await markRescanAlertRead(id, accessToken);
  };

  if (alerts.length === 0) return null;

  return (
    <div className="mb-6 space-y-3" role="region" aria-label="New findings from weekly rescans">
      {alerts.map((alert) => {
        const total = alert.newCritical + alert.newHigh;
        return (
          <div key={alert.id} className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 p-4">
            <AlertTriangle size={18} className="mt-0.5 shrink-0 text-red-400" aria-hidden="true" />
            <div className="min-w-0 flex-1 text-sm">
              <p className="font-bold text-[#EDEDED]">
                Weekly rescan: {total} new finding{total === 1 ? '' : 's'} in {alert.projectName}
              </p>
              <p className="text-xs text-[#94A3B8]">
                {alert.newCritical} critical, {alert.newHigh} high · {new Date(alert.createdAt).toLocaleDateString()}
              </p>
              <ul className="mt-2 space-y-1 text-xs">
                {alert.findings.slice(0, 3).map((f, i) => (
                  <li key={`${alert.id}-${i}`} className="truncate text-[#D4D4D8]">
                    <span className={f.severity === 'CRITICAL' ? 'font-mono font-bold text-red-400' : 'font-mono font-bold text-orange-400'}>
                      {f.severity}
                    </span>{' '}
                    {f.title} <span className="font-mono text-[#71717A]">{f.filePath}</span>
                  </li>
                ))}
              </ul>
            </div>
            <button
              type="button"
              aria-label={`Dismiss alert for ${alert.projectName}`}
              onClick={() => dismiss(alert.id)}
              className="shrink-0 rounded-lg p-1.5 text-gray-400 hover:bg-white/10 hover:text-white"
            >
              <X size={16} aria-hidden="true" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
