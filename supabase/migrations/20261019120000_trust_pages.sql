-- ==============================================================================
-- Migration: 20261019120000_trust_pages.sql
-- Description: Public trust pages (/verified/<slug>). The owner of a project turns
-- one on; the page shows the latest scan's date, gate and counts by risk, never
-- findings, files or code. Only the server (service role) creates, revokes and
-- reads pages for the public route.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.trust_pages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    project_id UUID REFERENCES public.projects(id) ON DELETE CASCADE NOT NULL,
    slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{2,62}$'),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 80),
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    revoked_at TIMESTAMPTZ
);

-- One active page per project
CREATE UNIQUE INDEX IF NOT EXISTS idx_trust_pages_active_project
    ON public.trust_pages(project_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_trust_pages_user_id ON public.trust_pages(user_id);

-- RLS: owners read their own pages; writes and public reads go through the service role.
ALTER TABLE public.trust_pages ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own trust pages"
    ON public.trust_pages
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Service role can manage all trust pages"
    ON public.trust_pages
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
