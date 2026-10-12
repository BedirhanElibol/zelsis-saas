-- ==============================================================================
-- Migration: 20261012130000_email_bound_invites.sql
-- Description: Workspace invites are bound to the invited email address. Only a
-- signed-in user with that (confirmed) email can accept, so a forwarded or leaked
-- link cannot be used by someone else. The table was empty when this was added.
-- ==============================================================================

ALTER TABLE public.organization_invites
    ADD COLUMN IF NOT EXISTS email TEXT NOT NULL CHECK (email = lower(email) AND position('@' IN email) > 1);
