-- Migration to add scheduled rescans and notification settings
ALTER TABLE public.projects 
ADD COLUMN IF NOT EXISTS slack_webhook_url TEXT,
ADD COLUMN IF NOT EXISTS discord_webhook_url TEXT,
ADD COLUMN IF NOT EXISTS weekly_rescan_enabled BOOLEAN DEFAULT true NOT NULL,
ADD COLUMN IF NOT EXISTS alert_new_cves_enabled BOOLEAN DEFAULT true NOT NULL;
