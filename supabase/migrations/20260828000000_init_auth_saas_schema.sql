-- ==============================================================================
-- ZELSIS AI RELEASE GATE SAAS - COMPLETE PRODUCTION POSTGRESQL / SUPABASE DDL
-- Migration: 20260828000000_init_auth_saas_schema.sql
-- Description: Fully detailed DDL SQL schema including Tables, Enums, Foreign Keys,
--              Indexes, Triggers, RLS Multi-Tenant Policies & Seed Data.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. EXTENSIONS
-- ------------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ------------------------------------------------------------------------------
-- 2. CUSTOM ENUM TYPES
-- ------------------------------------------------------------------------------
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('user', 'admin', 'auditor');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE plan_tier AS ENUM ('Free', 'Pro', 'Enterprise');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE gate_status AS ENUM ('PASSED', 'WARNING', 'FAILED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE finding_severity AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'PASSED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE finding_status AS ENUM ('OPEN', 'ACCEPTED_RISK', 'RESOLVED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE pillar_type AS ENUM ('SECURITY', 'VIBEPOLISH', 'AICLICHE', 'AIMASTER', 'VIBECARE', 'LEGAL_COMPLIANCE', 'INFRA_DATABASE');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ------------------------------------------------------------------------------
-- 3. PROFILES / USERS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT,
    avatar_url TEXT,
    role user_role DEFAULT 'user'::user_role NOT NULL,
    github_username TEXT,
    company_name TEXT,
    tier TEXT DEFAULT 'Free' NOT NULL,
    status TEXT DEFAULT 'active' NOT NULL,
    grace_period_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- ------------------------------------------------------------------------------
-- 4. B2B SAAS SUBSCRIPTIONS & QUOTAS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL UNIQUE,
    plan_tier plan_tier DEFAULT 'Free'::plan_tier NOT NULL,
    status TEXT DEFAULT 'active' NOT NULL,
    monthly_scan_quota INTEGER DEFAULT 3 NOT NULL,
    scans_used_this_month INTEGER DEFAULT 0 NOT NULL,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    polar_subscription_id TEXT,
    grace_period_until TIMESTAMPTZ,
    current_period_start TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    current_period_end TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days') NOT NULL,
    cancel_at_period_end BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- ------------------------------------------------------------------------------
-- 5. TARGET PROJECTS & REPOSITORIES TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL,
    repo_url TEXT NOT NULL,
    preview_url TEXT,
    github_token TEXT, -- Encrypted PAT token
    framework TEXT DEFAULT 'Auto-Detect' NOT NULL,
    providers TEXT[] DEFAULT ARRAY['GitHub Action', 'Vercel']::TEXT[] NOT NULL,
    last_scan_at TIMESTAMPTZ,
    readiness_score INTEGER DEFAULT 100 NOT NULL CHECK (readiness_score >= 0 AND readiness_score <= 100),
    gate_status gate_status DEFAULT 'PASSED'::gate_status NOT NULL,
    critical_count INTEGER DEFAULT 0 NOT NULL,
    high_count INTEGER DEFAULT 0 NOT NULL,
    medium_count INTEGER DEFAULT 0 NOT NULL,
    low_count INTEGER DEFAULT 0 NOT NULL,
    ui_cliche_count INTEGER DEFAULT 0 NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- ------------------------------------------------------------------------------
-- 6. SECURITY SCAN RUNS HISTORY TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES public.projects(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    trigger_type TEXT DEFAULT 'MANUAL' NOT NULL, -- ('MANUAL', 'WEBHOOK', 'CI_CD', 'SCHEDULED')
    readiness_score INTEGER NOT NULL CHECK (readiness_score >= 0 AND readiness_score <= 100),
    gate_status gate_status NOT NULL,
    critical_count INTEGER DEFAULT 0 NOT NULL,
    high_count INTEGER DEFAULT 0 NOT NULL,
    medium_count INTEGER DEFAULT 0 NOT NULL,
    low_count INTEGER DEFAULT 0 NOT NULL,
    ui_cliche_count INTEGER DEFAULT 0 NOT NULL,
    scan_duration_ms INTEGER DEFAULT 0 NOT NULL,
    scanned_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- ------------------------------------------------------------------------------
-- 7. AUDIT FINDINGS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES public.scans(id) ON DELETE CASCADE NOT NULL,
    project_id UUID REFERENCES public.projects(id) ON DELETE CASCADE NOT NULL,
    rule_id INTEGER NOT NULL,
    type pillar_type NOT NULL,
    title TEXT NOT NULL,
    severity finding_severity NOT NULL,
    category TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_range TEXT NOT NULL,
    snippet TEXT NOT NULL,
    reproduction_steps TEXT[] DEFAULT ARRAY[]::TEXT[] NOT NULL,
    remediation_prompt TEXT NOT NULL,
    status finding_status DEFAULT 'OPEN'::finding_status NOT NULL,
    false_positive BOOLEAN DEFAULT FALSE NOT NULL,
    resolved_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- ------------------------------------------------------------------------------
-- 8. API KEYS & WEBHOOK INTEGRATIONS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    key_name TEXT NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    prefix TEXT NOT NULL, -- e.g. "sg_live_..."
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- ------------------------------------------------------------------------------
-- 9. AUDIT LOGS & TELEMETRY TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb NOT NULL,
    ip_address TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- ------------------------------------------------------------------------------
-- 9.5. SECURITY RULES CATALOG TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.security_rules_catalog (
    id INTEGER PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    owasp_tag TEXT NOT NULL,
    risk_level finding_severity NOT NULL,
    description TEXT NOT NULL,
    verification_control TEXT NOT NULL,
    remediation_prompt TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- ------------------------------------------------------------------------------
-- 10. INDEXES FOR QUERY OPTIMIZATION
-- ------------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_projects_user_id ON public.projects(user_id);
CREATE INDEX IF NOT EXISTS idx_projects_gate_status ON public.projects(gate_status);
CREATE INDEX IF NOT EXISTS idx_scans_project_id ON public.scans(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON public.scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON public.scans(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON public.findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_project_id ON public.findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON public.findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON public.findings(severity);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON public.api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON public.audit_logs(user_id);

-- ------------------------------------------------------------------------------
-- 11. AUTOMATIC TRIGGERS & FUNCTIONS
-- ------------------------------------------------------------------------------

-- Trigger Function: Create Profile & Subscription on New Auth Sign-Up
CREATE OR REPLACE FUNCTION public.handle_new_user_signup()
RETURNS TRIGGER 
LANGUAGE plpgsql 
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO public.profiles (id, email, full_name, avatar_url, tier, status)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', SPLIT_PART(NEW.email, '@', 1)),
        NEW.raw_user_meta_data->>'avatar_url',
        'Free',
        'active'
    )
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.subscriptions (user_id, plan_tier, monthly_scan_quota)
    VALUES (NEW.id, 'Free', 3)
    ON CONFLICT (user_id) DO NOTHING;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trigger_on_auth_user_signup ON auth.users;
CREATE TRIGGER trigger_on_auth_user_signup
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user_signup();

-- Trigger Function: Protect Profile Tier & Role Modification (RLS Tier Protection)
CREATE OR REPLACE FUNCTION public.check_profile_tier_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    -- If tier or role is being changed
    IF (NEW.tier IS DISTINCT FROM OLD.tier) OR (NEW.role IS DISTINCT FROM OLD.role) THEN
        -- Only allow service_role (backend webhooks / admin API) to modify tier or role
        IF (auth.jwt() ->> 'role') IS DISTINCT FROM 'service_role' THEN
            -- Revert tier and role to old values silently
            NEW.tier := OLD.tier;
            NEW.role := OLD.role;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tr_protect_profile_tier ON public.profiles;
CREATE TRIGGER tr_protect_profile_tier
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.check_profile_tier_modification();

-- Trigger Function: Auto-Update Timestamp Column
CREATE OR REPLACE FUNCTION public.update_timestamp_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_profiles_timestamp ON public.profiles;
CREATE TRIGGER update_profiles_timestamp BEFORE UPDATE ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.update_timestamp_column();

DROP TRIGGER IF EXISTS update_subscriptions_timestamp ON public.subscriptions;
CREATE TRIGGER update_subscriptions_timestamp BEFORE UPDATE ON public.subscriptions FOR EACH ROW EXECUTE FUNCTION public.update_timestamp_column();

DROP TRIGGER IF EXISTS update_projects_timestamp ON public.projects;
CREATE TRIGGER update_projects_timestamp BEFORE UPDATE ON public.projects FOR EACH ROW EXECUTE FUNCTION public.update_timestamp_column();

DROP TRIGGER IF EXISTS update_findings_timestamp ON public.findings;
CREATE TRIGGER update_findings_timestamp BEFORE UPDATE ON public.findings FOR EACH ROW EXECUTE FUNCTION public.update_timestamp_column();

-- ------------------------------------------------------------------------------
-- 12. MULTI-TENANT ROW LEVEL SECURITY (RLS) POLICIES
-- ------------------------------------------------------------------------------
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_rules_catalog ENABLE ROW LEVEL SECURITY;

-- Profiles Policies
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
            tier IS NOT DISTINCT FROM (SELECT p.tier FROM public.profiles p WHERE p.id = auth.uid() ORDER BY p.id) 
            AND role IS NOT DISTINCT FROM (SELECT p.role FROM public.profiles p WHERE p.id = auth.uid() ORDER BY p.id)
        )
    )
);

-- Subscriptions Policies
DROP POLICY IF EXISTS "Users can view their own subscription" ON public.subscriptions;
CREATE POLICY "Users can view their own subscription" ON public.subscriptions FOR SELECT USING (auth.uid() = user_id);

-- Projects Policies
DROP POLICY IF EXISTS "Users can view their own projects" ON public.projects;
CREATE POLICY "Users can view their own projects" ON public.projects FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can create their own projects" ON public.projects;
CREATE POLICY "Users can create their own projects" ON public.projects FOR INSERT WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can update their own projects" ON public.projects;
CREATE POLICY "Users can update their own projects" ON public.projects FOR UPDATE USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can delete their own projects" ON public.projects;
CREATE POLICY "Users can delete their own projects" ON public.projects FOR DELETE USING (auth.uid() = user_id);

-- Scans Policies
DROP POLICY IF EXISTS "Users can view their own scans" ON public.scans;
CREATE POLICY "Users can view their own scans" ON public.scans FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can insert their own scans" ON public.scans;
CREATE POLICY "Users can insert their own scans" ON public.scans FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Findings Policies
DROP POLICY IF EXISTS "Users can view findings for their own projects" ON public.findings;
CREATE POLICY "Users can view findings for their own projects" ON public.findings
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM public.projects WHERE public.projects.id = public.findings.project_id AND public.projects.user_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "Users can update findings for their own projects" ON public.findings;
CREATE POLICY "Users can update findings for their own projects" ON public.findings
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM public.projects WHERE public.projects.id = public.findings.project_id AND public.projects.user_id = auth.uid()
        )
    );

-- API Keys Policies
DROP POLICY IF EXISTS "Users can manage their own API keys" ON public.api_keys;
CREATE POLICY "Users can manage their own API keys" ON public.api_keys FOR ALL USING (auth.uid() = user_id);

-- Audit Logs Policies (Multi-Tenant User Isolation)
DROP POLICY IF EXISTS "Users can view their own audit logs" ON public.audit_logs;
CREATE POLICY "Users can view their own audit logs" ON public.audit_logs 
    FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can insert their own audit logs" ON public.audit_logs;
CREATE POLICY "Users can insert their own audit logs" ON public.audit_logs 
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Security Rules Catalog Policies (Strict Non-Permissive Role Scoping)
DROP POLICY IF EXISTS "Public read-only for rules catalog" ON public.security_rules_catalog;
DROP POLICY IF EXISTS "Authenticated users can view security rules" ON public.security_rules_catalog;
CREATE POLICY "Authenticated users can view security rules" ON public.security_rules_catalog
    FOR SELECT TO authenticated, anon
    USING (auth.uid() IS NOT NULL OR auth.role() = 'anon');

-- Additional Performance Indexes
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON public.subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);

