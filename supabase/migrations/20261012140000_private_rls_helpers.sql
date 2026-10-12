-- ==============================================================================
-- Migration: 20261012140000_private_rls_helpers.sql
-- Description: Move the SECURITY DEFINER helpers used by RLS policies out of the
-- API-exposed public schema (Supabase advisor 0029). They only ever answered
-- questions about the caller, but in public they were callable as
-- /rest/v1/rpc/<name>. In the private schema (not exposed by PostgREST) policies
-- can still call them; the REST API cannot.
-- public.org_team_projects stays in public: the app calls it via RPC.
-- ==============================================================================

CREATE SCHEMA IF NOT EXISTS private;
REVOKE ALL ON SCHEMA private FROM PUBLIC;
GRANT USAGE ON SCHEMA private TO authenticated, service_role;

CREATE OR REPLACE FUNCTION private.current_user_org_id()
RETURNS uuid
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO ''
AS $$
  SELECT m.org_id FROM public.organization_members m WHERE m.user_id = auth.uid();
$$;

CREATE OR REPLACE FUNCTION private.is_current_user_org_admin(p_org_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO ''
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members m
    WHERE m.org_id = p_org_id AND m.user_id = auth.uid() AND m.role IN ('owner', 'admin')
  );
$$;

CREATE OR REPLACE FUNCTION private.is_admin()
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO ''
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid()
    AND role::TEXT IN ('admin', 'super_admin')
  );
$$;

REVOKE ALL ON FUNCTION private.current_user_org_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION private.is_current_user_org_admin(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.is_admin() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.current_user_org_id() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION private.is_current_user_org_admin(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION private.is_admin() TO authenticated, service_role;

-- Policies now call the private copies (same expressions, same roles and commands)
ALTER POLICY "Members can view their organization" ON public.organizations
    USING (id = private.current_user_org_id());
ALTER POLICY "Members can view their organization roster" ON public.organization_members
    USING (org_id = private.current_user_org_id());
ALTER POLICY "Admins can view pending invites" ON public.organization_invites
    USING (private.is_current_user_org_admin(org_id));

CREATE OR REPLACE FUNCTION public.org_team_projects()
RETURNS TABLE(id uuid, owner_id uuid, owner_email text, name text, repo_url text, preview_url text, framework text, last_scan_at timestamp with time zone, readiness_score integer, gate_status gate_status, critical_count integer, high_count integer, medium_count integer, low_count integer, updated_at timestamp with time zone)
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO ''
AS $$
  SELECT p.id, p.user_id, pr.email, p.name, p.repo_url, p.preview_url, p.framework, p.last_scan_at,
         p.readiness_score, p.gate_status, p.critical_count, p.high_count, p.medium_count,
         p.low_count, p.updated_at
  FROM public.projects p
  JOIN public.organization_members m ON m.user_id = p.user_id
  JOIN public.profiles pr ON pr.id = p.user_id
  WHERE m.org_id = private.current_user_org_id()
    AND p.user_id <> auth.uid()
  ORDER BY p.updated_at DESC
  LIMIT 200;
$$;

-- Without CASCADE: fails (and rolls everything back) if anything still depends on the public copies
DROP FUNCTION public.current_user_org_id();
DROP FUNCTION public.is_current_user_org_admin(uuid);
DROP FUNCTION public.is_admin();
