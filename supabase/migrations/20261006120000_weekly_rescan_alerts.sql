-- Weekly rescans and new-finding alerts.
-- Carries the columns from 20261004124000 (never applied to production) and makes
-- the weekly rescan opt-in, so existing projects are not rescanned without consent.
ALTER TABLE public.projects
ADD COLUMN IF NOT EXISTS slack_webhook_url TEXT,
ADD COLUMN IF NOT EXISTS discord_webhook_url TEXT,
ADD COLUMN IF NOT EXISTS weekly_rescan_enabled BOOLEAN DEFAULT false NOT NULL,
ADD COLUMN IF NOT EXISTS alert_new_cves_enabled BOOLEAN DEFAULT true NOT NULL;

ALTER TABLE public.projects ALTER COLUMN weekly_rescan_enabled SET DEFAULT false;

-- One row per scheduled rescan that found new CRITICAL/HIGH findings.
CREATE TABLE IF NOT EXISTS public.project_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
    scan_job_id UUID REFERENCES public.scan_jobs(id) ON DELETE SET NULL,
    new_critical INTEGER NOT NULL DEFAULT 0,
    new_high INTEGER NOT NULL DEFAULT 0,
    findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    emailed BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS project_alerts_user_unread_idx
    ON public.project_alerts (user_id, created_at DESC) WHERE read_at IS NULL;

ALTER TABLE public.project_alerts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "project_alerts_select_own" ON public.project_alerts;
CREATE POLICY "project_alerts_select_own" ON public.project_alerts
    FOR SELECT TO authenticated USING ((select auth.uid()) = user_id);

DROP POLICY IF EXISTS "project_alerts_update_own" ON public.project_alerts;
CREATE POLICY "project_alerts_update_own" ON public.project_alerts
    FOR UPDATE TO authenticated
    USING ((select auth.uid()) = user_id)
    WITH CHECK ((select auth.uid()) = user_id);

-- Rows are written by the service role only; users may only mark them read.
REVOKE ALL ON public.project_alerts FROM anon, authenticated;
GRANT SELECT ON public.project_alerts TO authenticated;
GRANT UPDATE (read_at) ON public.project_alerts TO authenticated;
