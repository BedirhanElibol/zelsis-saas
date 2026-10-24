-- ==============================================================================
-- Migration: 20261012120000_site_verifications.sql
-- Description: Proof that a user controls a website domain. Deep live probes
-- (dump / credential / admin-console paths) only run against verified domains.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.site_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    hostname TEXT NOT NULL,
    token TEXT NOT NULL,
    verified_at TIMESTAMPTZ,
    verified_method TEXT CHECK (verified_method IN ('file', 'dns')),
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    UNIQUE (user_id, hostname)
);

-- RLS: users read and remove their own rows. Tokens are issued and verified_at is set only by the
-- server (service role), so there is deliberately no INSERT / UPDATE policy for users.
ALTER TABLE public.site_verifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own site verifications"
    ON public.site_verifications
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own site verifications"
    ON public.site_verifications
    FOR DELETE
    USING (auth.uid() = user_id);

CREATE POLICY "Service role can manage all site verifications"
    ON public.site_verifications
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_site_verifications_user_id ON public.site_verifications(user_id);
