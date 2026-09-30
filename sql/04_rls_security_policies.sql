-- ==============================================================================
-- ZELSIS B2B SAAS - MULTI-TENANT ROW LEVEL SECURITY (RLS) POLICIES
-- File: sql/04_rls_security_policies.sql
-- ==============================================================================

-- 1. ENABLE ROW LEVEL SECURITY ON ALL TABLES
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- 2. PROFILES POLICIES
DROP POLICY IF EXISTS "Users can view their own profile" ON public.profiles;
CREATE POLICY "Users can view their own profile" ON public.profiles FOR SELECT USING (auth.uid() = id);

DROP POLICY IF EXISTS "Users can update their own profile" ON public.profiles;
CREATE POLICY "Users can update their own profile" ON public.profiles 
FOR UPDATE 
USING (auth.uid() = id)
WITH CHECK (
    auth.uid() = id 
    AND (
        (auth.jwt() ->> 'role') = 'service_role' 
        OR (
            tier IS NOT DISTINCT FROM (SELECT p.tier FROM public.profiles p WHERE p.id = auth.uid() ORDER BY p.id ASC) 
            AND role IS NOT DISTINCT FROM (SELECT p.role FROM public.profiles p WHERE p.id = auth.uid() ORDER BY p.id ASC)
        )
    )
);

-- 3. SUBSCRIPTIONS POLICIES
DROP POLICY IF EXISTS "Users can view their own subscription" ON public.subscriptions;
CREATE POLICY "Users can view their own subscription" ON public.subscriptions FOR SELECT USING (auth.uid() = user_id);

-- 4. PROJECTS POLICIES
DROP POLICY IF EXISTS "Users can view their own projects" ON public.projects;
CREATE POLICY "Users can view their own projects" ON public.projects FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can create their own projects" ON public.projects;
CREATE POLICY "Users can create their own projects" ON public.projects FOR INSERT WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can update their own projects" ON public.projects;
CREATE POLICY "Users can update their own projects" ON public.projects FOR UPDATE USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can delete their own projects" ON public.projects;
CREATE POLICY "Users can delete their own projects" ON public.projects FOR DELETE USING (auth.uid() = user_id);

-- 5. SCANS POLICIES
DROP POLICY IF EXISTS "Users can view their own scans" ON public.scans;
CREATE POLICY "Users can view their own scans" ON public.scans FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can insert their own scans" ON public.scans;
CREATE POLICY "Users can insert their own scans" ON public.scans FOR INSERT WITH CHECK (auth.uid() = user_id);

-- 6. FINDINGS POLICIES
DROP POLICY IF EXISTS "Users can view findings for their own projects" ON public.findings;
CREATE POLICY "Users can view findings for their own projects" ON public.findings
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM public.projects WHERE public.projects.id = public.findings.project_id AND public.projects.user_id = auth.uid() ORDER BY public.projects.id ASC
        )
    );

DROP POLICY IF EXISTS "Users can update findings for their own projects" ON public.findings;
CREATE POLICY "Users can update findings for their own projects" ON public.findings
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM public.projects WHERE public.projects.id = public.findings.project_id AND public.projects.user_id = auth.uid() ORDER BY public.projects.id ASC
        )
    );

-- 7. API KEYS POLICIES
DROP POLICY IF EXISTS "Users can manage their own API keys" ON public.api_keys;
CREATE POLICY "Users can manage their own API keys" ON public.api_keys FOR ALL USING (auth.uid() = user_id);

-- 8. AUDIT LOGS POLICIES
DROP POLICY IF EXISTS "Users can view their own audit logs" ON public.audit_logs;
CREATE POLICY "Users can view their own audit logs" ON public.audit_logs FOR SELECT USING (auth.uid() = user_id);

-- 9. DETERMINISTIC TRANSACTIONAL LOCKING HELPER (PG-05)
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

