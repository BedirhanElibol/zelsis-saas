-- ==============================================================================
-- Migration: Enterprise RBAC, Atomic Quota Reservation & Webhook Idempotency
-- File: sql/09_enterprise_rbac_and_webhook_idempotency.sql
-- ==============================================================================

-- 1. Webhook Events Table (Durable Replay Prevention)
CREATE TABLE IF NOT EXISTS public.webhook_events (
    event_id TEXT PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'polar',
    payload_hash TEXT,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS on webhook_events
ALTER TABLE public.webhook_events ENABLE ROW LEVEL SECURITY;

-- Only service_role can read/write webhook_events
DROP POLICY IF EXISTS "Service role manages webhook events" ON public.webhook_events;
CREATE POLICY "Service role manages webhook events" ON public.webhook_events
    FOR ALL TO service_role
    USING (current_user = 'service_role')
    WITH CHECK (current_user = 'service_role');

-- 2. Enterprise RBAC Roles on Profiles
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'app_role') THEN
        CREATE TYPE app_role AS ENUM ('member', 'auditor', 'security_lead', 'admin', 'super_admin');
    END IF;
END $$;

ALTER TABLE public.profiles
ADD COLUMN IF NOT EXISTS role app_role NOT NULL DEFAULT 'member';

CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);

-- Helper function to check if caller is an administrator via database role
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = auth.uid()
        AND role IN ('admin', 'super_admin')
    );
$$;

-- 3. Atomic Scan Quota Reservation Function (Concurrency Safe)
CREATE OR REPLACE FUNCTION public.reserve_scan_quota(p_user_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tier TEXT;
    v_quota INT;
    v_used INT;
BEGIN
    SELECT plan_tier, monthly_scan_quota, scans_used_this_month
    INTO v_tier, v_quota, v_used
    FROM public.subscriptions
    WHERE user_id = p_user_id
    ORDER BY user_id
    FOR UPDATE; -- Row-level lock prevents race conditions

    IF NOT FOUND THEN
        -- If no subscription row exists, default to Free tier (3 scans)
        RETURN jsonb_build_object('allowed', true, 'used', 1, 'quota', 3, 'tier', 'Free');
    END IF;

    IF v_tier = 'Free' AND v_used >= v_quota THEN
        RETURN jsonb_build_object(
            'allowed', false,
            'reason', 'Monthly free tier scan quota exceeded. Upgrade to Pro for unlimited scans.',
            'used', v_used,
            'quota', v_quota,
            'tier', v_tier
        );
    END IF;

    UPDATE public.subscriptions
    SET scans_used_this_month = scans_used_this_month + 1,
        updated_at = NOW()
    WHERE user_id = p_user_id;

    RETURN jsonb_build_object(
        'allowed', true,
        'used', v_used + 1,
        'quota', v_quota,
        'tier', v_tier
    );
END;
$$;
