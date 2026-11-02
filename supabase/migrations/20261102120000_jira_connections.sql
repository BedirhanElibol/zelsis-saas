-- ==============================================================================
-- Migration: 20261102120000_jira_connections.sql
-- Description: One Jira Cloud connection per user, used to open an issue from a
-- finding. The API token is stored encrypted (AES-256-GCM, key outside the
-- database in INTEGRATION_ENCRYPTION_KEY).
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.jira_connections (
    user_id UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
    site_url TEXT NOT NULL,
    email TEXT NOT NULL,
    project_key TEXT NOT NULL,
    issue_type TEXT NOT NULL DEFAULT 'Task',
    token_ciphertext TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- RLS: only the server (service role) reads or writes rows. Users get no policy,
-- so even the encrypted token never reaches a browser client.
ALTER TABLE public.jira_connections ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role can manage all jira connections"
    ON public.jira_connections
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
