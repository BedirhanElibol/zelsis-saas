'use server';

import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';
import { logger } from '@/lib/logger';

export interface ProjectAlertSettings {
  weeklyRescanEnabled: boolean;
  alertNewCvesEnabled: boolean;
}

export type ProjectAlertSettingsResult =
  | { status: 'success'; settings: ProjectAlertSettings }
  | { status: 'error'; message: string };

const ProjectIdSchema = z.string().uuid();
const SettingsSchema = z.object({
  weeklyRescanEnabled: z.boolean(),
  alertNewCvesEnabled: z.boolean(),
});

// The caller's own client: RLS on projects limits reads and writes to the owner.
function userClient(accessToken: string) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anonKey || !accessToken) return null;
  return createClient(url, anonKey, {
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
    auth: { persistSession: false },
  });
}

export async function getProjectAlertSettings(
  projectId: string,
  accessToken: string
): Promise<ProjectAlertSettingsResult> {
  const id = ProjectIdSchema.safeParse(projectId);
  const supabase = userClient(accessToken);
  if (!id.success || !supabase) return { status: 'error', message: 'Sign in to manage alerts for this project.' };

  const { data, error } = await supabase
    .from('projects')
    .select('weekly_rescan_enabled, alert_new_cves_enabled')
    .eq('id', id.data)
    .maybeSingle();
  if (error || !data) return { status: 'error', message: 'Project not found.' };

  return {
    status: 'success',
    settings: { weeklyRescanEnabled: data.weekly_rescan_enabled, alertNewCvesEnabled: data.alert_new_cves_enabled },
  };
}

export async function updateProjectAlertSettings(
  projectId: string,
  settings: ProjectAlertSettings,
  accessToken: string
): Promise<ProjectAlertSettingsResult> {
  const id = ProjectIdSchema.safeParse(projectId);
  const parsed = SettingsSchema.safeParse(settings);
  const supabase = userClient(accessToken);
  if (!id.success || !parsed.success || !supabase) return { status: 'error', message: 'Invalid alert settings.' };

  const { data, error } = await supabase
    .from('projects')
    .update({
      weekly_rescan_enabled: parsed.data.weeklyRescanEnabled,
      alert_new_cves_enabled: parsed.data.alertNewCvesEnabled,
    })
    .eq('id', id.data)
    .select('id')
    .maybeSingle();

  if (error || !data) {
    logger.warn('[Alerts] Failed to update project alert settings:', error);
    return { status: 'error', message: 'Could not save alert settings.' };
  }
  return { status: 'success', settings: parsed.data };
}

export interface RescanAlert {
  id: string;
  projectId: string;
  projectName: string;
  newCritical: number;
  newHigh: number;
  createdAt: string;
  findings: { title: string; severity: string; filePath: string }[];
}

export type RescanAlertsResult =
  | { status: 'success'; alerts: RescanAlert[] }
  | { status: 'error'; message: string };

export async function listUnreadRescanAlerts(accessToken: string): Promise<RescanAlertsResult> {
  const supabase = userClient(accessToken);
  if (!supabase) return { status: 'error', message: 'Not signed in.' };

  const { data, error } = await supabase
    .from('project_alerts')
    .select('id, project_id, new_critical, new_high, findings, created_at, projects(name)')
    .is('read_at', null)
    .order('created_at', { ascending: false })
    .limit(5);
  if (error || !data) return { status: 'error', message: 'Could not load alerts.' };

  return {
    status: 'success',
    alerts: data.map((row) => {
      const project = row.projects as { name?: string } | { name?: string }[] | null;
      const projectName = (Array.isArray(project) ? project[0]?.name : project?.name) ?? 'Project';
      return {
        id: row.id,
        projectId: row.project_id,
        projectName,
        newCritical: row.new_critical,
        newHigh: row.new_high,
        createdAt: row.created_at,
        findings: Array.isArray(row.findings) ? row.findings : [],
      };
    }),
  };
}

export async function markRescanAlertRead(
  alertId: string,
  accessToken: string
): Promise<{ status: 'success' } | { status: 'error'; message: string }> {
  const id = ProjectIdSchema.safeParse(alertId);
  const supabase = userClient(accessToken);
  if (!id.success || !supabase) return { status: 'error', message: 'Invalid alert.' };

  const { error } = await supabase
    .from('project_alerts')
    .update({ read_at: new Date().toISOString() })
    .eq('id', id.data);
  return error ? { status: 'error', message: 'Could not dismiss the alert.' } : { status: 'success' };
}
