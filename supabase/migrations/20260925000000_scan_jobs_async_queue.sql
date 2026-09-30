-- ==============================================================================
-- ZELSIS AI RELEASE GATE SAAS - ASYNC SCAN JOBS & QUEUE PIPELINE MIGRATION
-- Migration: 20260925000000_scan_jobs_async_queue.sql
-- Resolves: Audit v2 Section 9 (Scan Data Model & Async Execution)
-- ==============================================================================

-- 1. Create scan_jobs Table for Serverless Async Execution
CREATE TABLE IF NOT EXISTS public.scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES public.projects(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    commit_sha TEXT,
    repo_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'QUEUED' CHECK (
        status IN ('QUEUED', 'FETCHING', 'INDEXING', 'ANALYZING', 'AGGREGATING', 'COMPLETED', 'FAILED', 'CANCELLED')
    ),
    progress_percent INT NOT NULL DEFAULT 0 CHECK (progress_percent >= 0 AND progress_percent <= 100),
    current_phase TEXT NOT NULL DEFAULT 'QUEUED',
    current_file TEXT,
    total_files INT NOT NULL DEFAULT 0,
    processed_files INT NOT NULL DEFAULT 0,
    findings_count INT NOT NULL DEFAULT 0,
    readiness_score INT,
    gate_status TEXT CHECK (gate_status IN ('PASSED', 'FAILED', 'WARNING', NULL)),
    scan_id UUID REFERENCES public.scans(id) ON DELETE SET NULL,
    result_data JSONB,
    error_message TEXT,
    lease_until TIMESTAMPTZ,
    retry_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Performance Indexes for Queue Processing and User Lookups
CREATE INDEX IF NOT EXISTS idx_scan_jobs_user_status ON public.scan_jobs(user_id, status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_project_created ON public.scan_jobs(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status_lease ON public.scan_jobs(status, lease_until);

-- 3. Row Level Security (RLS) Multi-Tenant Hardening
ALTER TABLE public.scan_jobs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own scan jobs" ON public.scan_jobs;
CREATE POLICY "Users can view own scan jobs" ON public.scan_jobs
    FOR SELECT TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can create own scan jobs" ON public.scan_jobs;
CREATE POLICY "Users can create own scan jobs" ON public.scan_jobs
    FOR INSERT TO authenticated
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can cancel own scan jobs" ON public.scan_jobs;
CREATE POLICY "Users can cancel own scan jobs" ON public.scan_jobs
    FOR UPDATE TO authenticated
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

-- 4. Automatic Timestamp Update Trigger (search_path Hardened)
CREATE OR REPLACE FUNCTION public.handle_scan_job_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_scan_jobs_updated_at ON public.scan_jobs;
CREATE TRIGGER trg_scan_jobs_updated_at
    BEFORE UPDATE ON public.scan_jobs
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_scan_job_updated_at();

-- 5. Realtime Publication for Live Web UI Progress Streaming
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.scan_jobs;
    END IF;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- 6. Deterministic Queue Job Dequeue & Lease Acquisition Helper (Resolves PG-05 Deadlocks)
-- Enforces deterministic primary key ordering (ORDER BY id ASC) before acquiring row locks
CREATE OR REPLACE FUNCTION public.dequeue_next_scan_job(p_worker_id TEXT DEFAULT 'worker-1', p_lease_seconds INT DEFAULT 300)
RETURNS SETOF public.scan_jobs
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_job_id UUID;
BEGIN
    SELECT id INTO v_job_id
    FROM public.scan_jobs
    WHERE status = 'QUEUED'
       OR (status = 'FETCHING' AND lease_until < NOW())
    ORDER BY id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1;

    IF v_job_id IS NOT NULL THEN
        RETURN QUERY
        UPDATE public.scan_jobs
        SET status = 'FETCHING',
            lease_until = NOW() + (p_lease_seconds || ' seconds')::INTERVAL,
            updated_at = NOW()
        WHERE id = v_job_id
        RETURNING *;
    END IF;
END;
$$;

