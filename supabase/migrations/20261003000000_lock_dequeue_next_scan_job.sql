-- dequeue_next_scan_job (20260925000000) is SECURITY DEFINER, returns scan_jobs rows and was executable by
-- anon/authenticated through supabase.rpc, so anyone with the public key could read and lease other users'
-- scan jobs. No app code calls it; only a service-role worker may. Lock it down wherever it exists.
DO $$
BEGIN
    IF to_regprocedure('public.dequeue_next_scan_job(text, integer)') IS NOT NULL THEN
        ALTER FUNCTION public.dequeue_next_scan_job(text, integer) SET search_path = '';
        REVOKE EXECUTE ON FUNCTION public.dequeue_next_scan_job(text, integer) FROM PUBLIC, anon, authenticated;
        GRANT EXECUTE ON FUNCTION public.dequeue_next_scan_job(text, integer) TO service_role;
    END IF;
END $$;
