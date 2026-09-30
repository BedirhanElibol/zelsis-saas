-- Zelsis v3.0 Production Database Schema & Row Level Security (RLS) Migration
-- Target Engine: PostgreSQL / Supabase DB

-- 1. Create Custom Enum Types
CREATE TYPE severity_level AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'PASSED');
CREATE TYPE status_level AS ENUM ('OPEN', 'ACCEPTED_RISK', 'RESOLVED');
CREATE TYPE gate_status_level AS ENUM ('PASSED', 'FAILED', 'WARNING');
CREATE TYPE pillar_type AS ENUM ('SECURITY', 'VIBEPOLISH', 'VIBECARE');

-- 2. Create Projects Table
CREATE TABLE IF NOT EXISTS public.projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    repo_url TEXT NOT NULL,
    github_token TEXT,
    preview_url TEXT,
    framework TEXT NOT NULL DEFAULT 'Next.js 15',
    providers TEXT[] DEFAULT ARRAY['Vercel', 'GitHub'],
    last_scan_at TIMESTAMPTZ DEFAULT NOW(),
    readiness_score INT NOT NULL DEFAULT 100 CHECK (readiness_score BETWEEN 0 AND 100),
    gate_status gate_status_level NOT NULL DEFAULT 'PASSED',
    critical_count INT NOT NULL DEFAULT 0,
    high_count INT NOT NULL DEFAULT 0,
    medium_count INT NOT NULL DEFAULT 0,
    low_count INT NOT NULL DEFAULT 0,
    ui_cliche_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Create Findings Table
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
    rule_id INT NOT NULL,
    type pillar_type NOT NULL DEFAULT 'SECURITY',
    title TEXT NOT NULL,
    severity severity_level NOT NULL DEFAULT 'MEDIUM',
    category TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_range TEXT NOT NULL,
    snippet TEXT NOT NULL,
    reproduction_steps TEXT[] DEFAULT ARRAY[]::TEXT[],
    remediation_prompt TEXT NOT NULL,
    status status_level NOT NULL DEFAULT 'OPEN',
    owner TEXT DEFAULT 'Security Team',
    false_positive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Create Performance Indexes
CREATE INDEX IF NOT EXISTS idx_projects_user_id ON public.projects(user_id);
CREATE INDEX IF NOT EXISTS idx_findings_project_id ON public.findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_status_severity ON public.findings(status, severity);

-- 5. Enable Row Level Security (RLS)
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

-- 6. Strict RLS Policies for Projects
CREATE POLICY "Users can only view their own projects"
    ON public.projects FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can only insert their own projects"
    ON public.projects FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can only update their own projects"
    ON public.projects FOR UPDATE
    USING (auth.uid() = user_id);

CREATE POLICY "Users can only delete their own projects"
    ON public.projects FOR DELETE
    USING (auth.uid() = user_id);

-- 7. Strict RLS Policies for Findings (Inherited via project ownership)
CREATE POLICY "Users can view findings for their own projects"
    ON public.findings FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.projects
            WHERE projects.id = findings.project_id
            AND projects.user_id = auth.uid()
            ORDER BY projects.id ASC
        )
    );

CREATE POLICY "Users can modify findings for their own projects"
    ON public.findings FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM public.projects
            WHERE projects.id = findings.project_id
            AND projects.user_id = auth.uid()
            ORDER BY projects.id ASC
        )
    );

-- 8. Deterministic Transactional Locking Helper (Resolves PG-05 Deadlocks)
-- Enforces deterministic primary key ordering (ORDER BY id ASC) before acquiring row locks
CREATE OR REPLACE FUNCTION public.lock_findings_for_update(p_project_id UUID)
RETURNS SETOF UUID
LANGUAGE sql
SECURITY DEFINER
AS $$
    SELECT id FROM public.findings
    WHERE project_id = p_project_id
    ORDER BY id ASC
    FOR UPDATE;
$$;
