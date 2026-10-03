-- Code snippet retention: erase stored source excerpts after 90 days.
-- Backs the public statement in lib/data-retention.ts (CODE_SNIPPET_RETENTION_DAYS).
-- Finding metadata (rule, file, line, severity, status) is kept for plan history;
-- only the parts that contain source code are cleared. No tables or columns are dropped.

CREATE EXTENSION IF NOT EXISTS pg_cron;

CREATE INDEX IF NOT EXISTS idx_findings_snippet_created
    ON public.findings (created_at)
    WHERE snippet <> '';

CREATE OR REPLACE FUNCTION public.purge_expired_code_snippets()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    cutoff timestamptz := now() - interval '90 days';
BEGIN
    -- 1. Persisted findings: snippet is NOT NULL, so blank it
    UPDATE public.findings
    SET snippet = '', updated_at = now()
    WHERE created_at < cutoff
      AND snippet <> '';

    -- 2. Stored scan results: blank each finding's snippet, drop the optional diffPatch
    UPDATE public.scan_jobs j
    SET result_data = jsonb_set(
            j.result_data,
            '{findings}',
            (
                SELECT COALESCE(
                    jsonb_agg(
                        CASE WHEN jsonb_typeof(f) = 'object'
                             THEN (f - 'diffPatch') || jsonb_build_object('snippet', '')
                             ELSE f
                        END
                        ORDER BY ord
                    ),
                    '[]'::jsonb
                )
                FROM jsonb_array_elements(j.result_data -> 'findings') WITH ORDINALITY AS t(f, ord)
            )
        )
    WHERE j.created_at < cutoff
      AND jsonb_typeof(j.result_data -> 'findings') = 'array'
      AND (
          jsonb_path_exists(j.result_data, '$.findings[*] ? (@.snippet != "")')
          OR jsonb_path_exists(j.result_data, '$.findings[*].diffPatch')
      );

    -- 3. Locked fix text for Free results (remediation prompts and diff patches)
    DELETE FROM public.scan_job_fixes
    WHERE created_at < cutoff;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.purge_expired_code_snippets() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.purge_expired_code_snippets() TO service_role;

-- Daily at 03:17 UTC; cron.schedule upserts by job name, so re-running is safe
SELECT cron.schedule(
    'purge-expired-code-snippets',
    '17 3 * * *',
    $$SELECT public.purge_expired_code_snippets()$$
);
