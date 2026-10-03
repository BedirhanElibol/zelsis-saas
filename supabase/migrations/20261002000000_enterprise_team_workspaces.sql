-- Enterprise team workspaces: organizations, members (owner / admin / member), invite links,
-- an organization gate policy (.zelsisrc format) and white-label report branding.
-- Clients may only READ through RLS; every write goes through server actions using the
-- service role after an explicit authorization check.

-- 1. Tables ---------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 80),
  owner_id uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  -- Organization gate policy in .zelsisrc.json shape; applied to every member's scans.
  policy jsonb NOT NULL DEFAULT '{}'::jsonb,
  brand_name text CHECK (brand_name IS NULL OR char_length(brand_name) <= 80),
  brand_logo_url text CHECK (brand_logo_url IS NULL OR (char_length(brand_logo_url) <= 500 AND brand_logo_url ~ '^https://')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.organization_members (
  org_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  joined_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id),
  -- One workspace per user keeps entitlement resolution unambiguous.
  CONSTRAINT organization_members_one_org_per_user UNIQUE (user_id)
);

CREATE TABLE IF NOT EXISTS public.organization_invites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  -- SHA-256 of the invite token; the raw token only ever exists in the invite link.
  token_hash text NOT NULL UNIQUE,
  role text NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
  created_by uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '7 days'),
  used_at timestamptz,
  used_by uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS organization_invites_org_id_idx ON public.organization_invites (org_id);
CREATE INDEX IF NOT EXISTS organizations_owner_id_idx ON public.organizations (owner_id);

CREATE TRIGGER organizations_updated_at
  BEFORE UPDATE ON public.organizations
  FOR EACH ROW EXECUTE FUNCTION public.update_timestamp_column();

-- 2. Helpers (SECURITY DEFINER so policies on organization_members do not recurse) -----------

CREATE OR REPLACE FUNCTION public.current_user_org_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT m.org_id FROM public.organization_members m WHERE m.user_id = auth.uid();
$$;

CREATE OR REPLACE FUNCTION public.is_current_user_org_admin(p_org_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members m
    WHERE m.org_id = p_org_id AND m.user_id = auth.uid() AND m.role IN ('owner', 'admin')
  );
$$;

-- Teammates' project summaries. Deliberately excludes projects.github_token, which a
-- row-level SELECT policy on projects would expose to the whole organization.
CREATE OR REPLACE FUNCTION public.org_team_projects()
RETURNS TABLE (
  id uuid,
  owner_id uuid,
  owner_email text,
  name text,
  repo_url text,
  preview_url text,
  framework text,
  last_scan_at timestamptz,
  readiness_score integer,
  gate_status public.gate_status,
  critical_count integer,
  high_count integer,
  medium_count integer,
  low_count integer,
  updated_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT p.id, p.user_id, pr.email, p.name, p.repo_url, p.preview_url, p.framework, p.last_scan_at,
         p.readiness_score, p.gate_status, p.critical_count, p.high_count, p.medium_count,
         p.low_count, p.updated_at
  FROM public.projects p
  JOIN public.organization_members m ON m.user_id = p.user_id
  JOIN public.profiles pr ON pr.id = p.user_id
  WHERE m.org_id = public.current_user_org_id()
    AND p.user_id <> auth.uid()
  ORDER BY p.updated_at DESC
  LIMIT 200;
$$;

REVOKE EXECUTE ON FUNCTION public.current_user_org_id() FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.is_current_user_org_admin(uuid) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.org_team_projects() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.current_user_org_id() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.is_current_user_org_admin(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.org_team_projects() TO authenticated, service_role;

-- 3. RLS: read-only for clients ---------------------------------------------------------------

ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_invites ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Members can view their organization" ON public.organizations
  FOR SELECT TO authenticated
  USING (id = public.current_user_org_id());

CREATE POLICY "Members can view their organization roster" ON public.organization_members
  FOR SELECT TO authenticated
  USING (org_id = public.current_user_org_id());

CREATE POLICY "Admins can view pending invites" ON public.organization_invites
  FOR SELECT TO authenticated
  USING (public.is_current_user_org_admin(org_id));

-- No INSERT / UPDATE / DELETE policies: writes are server-side only (service role bypasses RLS).
