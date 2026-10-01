-- Harden SECURITY DEFINER functions (Supabase database lints 0011, 0028, 0029).
-- Applied to project newday on 2026-10-01; found by Zelsis rule SAAS-03 and the Supabase security advisor.

-- 1. Pin search_path so callers cannot shadow objects (bodies are fully schema-qualified).
ALTER FUNCTION public.is_admin() SET search_path = '';
ALTER FUNCTION public.reserve_scan_quota(uuid) SET search_path = '';
ALTER FUNCTION public.update_timestamp_column() SET search_path = '';

-- 2. reserve_scan_quota(p_user_id) consumes any user's quota: server-side (service_role) only.
REVOKE EXECUTE ON FUNCTION public.reserve_scan_quota(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.reserve_scan_quota(uuid) TO service_role;

-- 3. is_admin() only reports the caller's own role: signed-in users only.
REVOKE EXECUTE ON FUNCTION public.is_admin() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated, service_role;

-- 4. Trigger / event-trigger functions are never called through the REST API.
--    EXECUTE is checked when a trigger is created, not when it fires, so triggers keep working.
REVOKE EXECUTE ON FUNCTION public.check_profile_tier_modification() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.handle_new_user_signup() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.handle_scan_job_updated_at() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.sync_profile_tier_from_subscription() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.sync_subscription_quota_on_tier_change() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.rls_auto_enable() FROM PUBLIC, anon, authenticated;
