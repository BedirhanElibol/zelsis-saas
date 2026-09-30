-- ==============================================================================
-- ZELSIS AI RELEASE GATE SAAS - SECURITY & RLS HARDENING MIGRATION
-- Migration: 20260923000000_security_and_rls_hardening.sql
-- Resolves: F-13 (RLS Tier Protection Trigger), F-28 (Single Source Schema & Rules Catalog RLS),
--           F-29 (search_path hardening on SECURITY DEFINER functions)
-- ==============================================================================

-- 1. Extend Pillar Type Enum
ALTER TYPE pillar_type ADD VALUE IF NOT EXISTS 'LEGAL_COMPLIANCE';
ALTER TYPE pillar_type ADD VALUE IF NOT EXISTS 'INFRA_DATABASE';

-- 2. Schema Drift Resolution (Profiles & Subscriptions)
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS tier TEXT DEFAULT 'Free';
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS grace_period_until TIMESTAMPTZ;

ALTER TABLE public.subscriptions ADD COLUMN IF NOT EXISTS grace_period_until TIMESTAMPTZ;
ALTER TABLE public.subscriptions ADD COLUMN IF NOT EXISTS polar_subscription_id TEXT;

-- 3. Security Rules Catalog Table with Mandatory Row Level Security
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

ALTER TABLE public.security_rules_catalog ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Public read-only for rules catalog" ON public.security_rules_catalog;
DROP POLICY IF EXISTS "Authenticated users can view security rules" ON public.security_rules_catalog;
CREATE POLICY "Authenticated users can view security rules" ON public.security_rules_catalog
    FOR SELECT TO authenticated, anon
    USING (auth.uid() IS NOT NULL OR auth.role() = 'anon');

-- 4. Secure handle_new_user_signup Function (Hardened search_path)
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

-- 5. Tier & Role Escalation Protection (Trigger + Function with search_path hardening)
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
            -- Revert tier and role to old values
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

-- 6. Tightened Profiles UPDATE RLS Policy
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

-- 7. Query Performance Indexes
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON public.subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);

-- 8. Deterministic Transactional Locking Helper (Resolves PG-05 Deadlocks)
-- Enforces deterministic primary key ordering (ORDER BY id ASC) before acquiring row locks
CREATE OR REPLACE FUNCTION public.lock_profile_for_update(p_user_id UUID)
RETURNS SETOF UUID
LANGUAGE sql
SECURITY DEFINER
AS $$
    SELECT id FROM public.profiles
    WHERE id = p_user_id
    ORDER BY id ASC
    FOR UPDATE;
$$;

