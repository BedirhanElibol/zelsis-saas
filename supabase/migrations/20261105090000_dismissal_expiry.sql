-- Reasoned, time-limited acceptance of findings.
-- Readers already filter on status = 'ACTIVE', a column the table never had, so dismissals were ignored.
-- expires_at: when an accepted risk stops being accepted and the finding opens again (NULL = no end date).
ALTER TABLE public.finding_dismissals
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN IF NOT EXISTS expires_at timestamptz;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'finding_dismissals_status_check') THEN
        ALTER TABLE public.finding_dismissals
            ADD CONSTRAINT finding_dismissals_status_check CHECK (status IN ('ACTIVE', 'REVOKED'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_finding_dismissals_project_active
    ON public.finding_dismissals (project_id) WHERE status = 'ACTIVE';
