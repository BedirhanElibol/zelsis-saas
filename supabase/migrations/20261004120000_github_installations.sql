-- ==============================================================================
-- Migration: 20261004120000_github_installations.sql
-- Description: Table to link GitHub App installations to Zelsis users
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.github_installations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    installation_id BIGINT UNIQUE NOT NULL,
    account_login TEXT NOT NULL,
    account_type TEXT NOT NULL,
    repository_selection TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- RLS
ALTER TABLE public.github_installations ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own github installations"
    ON public.github_installations
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own github installations"
    ON public.github_installations
    FOR DELETE
    USING (auth.uid() = user_id);

CREATE POLICY "Service role can manage all github installations"
    ON public.github_installations
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- Indexing for quick lookups
CREATE INDEX idx_github_installations_user_id ON public.github_installations(user_id);
CREATE INDEX idx_github_installations_installation_id ON public.github_installations(installation_id);

-- Optional: update trigger
CREATE OR REPLACE FUNCTION update_github_installations_modtime()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_github_installations_updated_at
BEFORE UPDATE ON public.github_installations
FOR EACH ROW EXECUTE FUNCTION update_github_installations_modtime();
