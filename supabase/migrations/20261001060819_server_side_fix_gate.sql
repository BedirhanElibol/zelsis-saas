-- Server-side Pro gate for fix guidance
-- 1. Free-tier scan results are stored in scan_jobs.result_data without fix text
--    (remediation prompts and diff patches). The full fix text lives in
--    scan_job_fixes, which only the service role can read.
-- 2. subscriptions.fix_prompts_used counts the lifetime Free trial reveals,
--    so the trial can no longer be reset by clearing browser storage.

ALTER TABLE public.subscriptions
    ADD COLUMN IF NOT EXISTS fix_prompts_used INT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS public.scan_job_fixes (
    job_id UUID PRIMARY KEY REFERENCES public.scan_jobs(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    fixes JSONB NOT NULL,
    revealed_finding_ids TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_job_fixes_user ON public.scan_job_fixes(user_id);

-- Service role only: clients must go through /api/v1/scans/fix
ALTER TABLE public.scan_job_fixes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "No direct client access to scan job fixes" ON public.scan_job_fixes;
CREATE POLICY "No direct client access to scan job fixes" ON public.scan_job_fixes
    FOR ALL TO anon, authenticated
    USING (false)
    WITH CHECK (false);

REVOKE ALL ON public.scan_job_fixes FROM anon, authenticated;
