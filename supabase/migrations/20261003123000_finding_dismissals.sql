-- ==============================================================================
-- ZELSIS AI RELEASE GATE SAAS - FINDING DISMISSALS
-- Migration: 20261003123000_finding_dismissals.sql
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.finding_dismissals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    rule_id integer NOT NULL,
    file_path text NOT NULL,
    line integer,
    reason text NOT NULL,
    note text,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Unique constraint so the same finding cannot be dismissed multiple times
CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_dismissals_unique
    ON public.finding_dismissals (project_id, rule_id, file_path, COALESCE(line, 0));

ALTER TABLE public.finding_dismissals ENABLE ROW LEVEL SECURITY;

-- Users can read dismissals for their own projects
CREATE POLICY "Users can view dismissals for their own projects" 
    ON public.finding_dismissals
    FOR SELECT 
    USING (
        user_id = auth.uid() OR
        EXISTS (
            SELECT 1 FROM public.projects p 
            WHERE p.id = finding_dismissals.project_id AND p.user_id = auth.uid()
        )
    );

-- Users can create dismissals for their own projects
CREATE POLICY "Users can create dismissals for their own projects" 
    ON public.finding_dismissals
    FOR INSERT 
    WITH CHECK (
        user_id = auth.uid() AND
        EXISTS (
            SELECT 1 FROM public.projects p 
            WHERE p.id = finding_dismissals.project_id AND p.user_id = auth.uid()
        )
    );

-- Users can delete dismissals for their own projects
CREATE POLICY "Users can delete dismissals for their own projects" 
    ON public.finding_dismissals
    FOR DELETE 
    USING (
        user_id = auth.uid() OR
        EXISTS (
            SELECT 1 FROM public.projects p 
            WHERE p.id = finding_dismissals.project_id AND p.user_id = auth.uid()
        )
    );

