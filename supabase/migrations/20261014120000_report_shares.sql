-- ==============================================================================
-- Migration: 20261014120000_report_shares.sql
-- Description: Read-only report links. The owner of a completed scan job creates
-- a link (/r/<token>) that shows its score, gate and findings without code
-- snippets or fix prompts, and can revoke it at any time.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.report_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    job_id UUID REFERENCES public.scan_jobs(id) ON DELETE CASCADE NOT NULL,
    -- 32 random bytes, base64url: the link itself is the only credential
    token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    revoked_at TIMESTAMPTZ
);

-- RLS: owners read their own links. Links are created, revoked and read for the
-- public page only by the server (service role), so users get no write policy.
ALTER TABLE public.report_shares ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own report shares"
    ON public.report_shares
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Service role can manage all report shares"
    ON public.report_shares
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_report_shares_user_id ON public.report_shares(user_id);
CREATE INDEX IF NOT EXISTS idx_report_shares_job_id ON public.report_shares(job_id);
