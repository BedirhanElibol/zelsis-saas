'use server';

import { createClient } from '@supabase/supabase-js';

export async function updateProjectNotifications(
  projectId: string,
  data: {
    slackWebhookUrl?: string | null;
    discordWebhookUrl?: string | null;
    weeklyRescanEnabled?: boolean;
    alertNewCvesEnabled?: boolean;
  },
  accessToken: string
) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anonKey) {
    return { status: 'error', message: 'Missing Supabase environment variables' };
  }
  
  // We use the authenticated user's client, since RLS should protect the projects table
  const supabase = createClient(url, anonKey, {
    global: {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  });

  const { error } = await supabase
    .from('projects')
    .update({
      slack_webhook_url: data.slackWebhookUrl,
      discord_webhook_url: data.discordWebhookUrl,
      weekly_rescan_enabled: data.weeklyRescanEnabled,
      alert_new_cves_enabled: data.alertNewCvesEnabled,
    })
    .eq('id', projectId);

  if (error) {
    console.error('Failed to update project notifications:', error);
    return { status: 'error', message: error.message };
  }

  return { status: 'success', message: 'Settings saved successfully' };
}
