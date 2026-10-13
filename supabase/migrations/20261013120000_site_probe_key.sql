-- ==============================================================================
-- Migration: 20261013120000_site_probe_key.sql
-- Description: Secret per verified domain that the scanner sends as the
-- x-zelsis-probe header on exposure probes, so the owner can add a firewall
-- rule that lets those requests through instead of challenging them. Unlike the
-- verification token (public in DNS / the well-known file) it is never published.
-- Existing RLS covers it: users read only their own rows, only the service role writes.
-- ==============================================================================

ALTER TABLE public.site_verifications ADD COLUMN IF NOT EXISTS probe_key TEXT;
