-- ==============================================================================
-- Migration: 20261102180000_site_events_section.sql
-- Description: Count which landing page sections visitors reach ("section"
-- events), so the section order can follow real behaviour. Same anonymous daily
-- counts as page views; only the allowed kinds widen.
-- ==============================================================================

ALTER TABLE public.site_events DROP CONSTRAINT IF EXISTS site_events_kind_check;
ALTER TABLE public.site_events ADD CONSTRAINT site_events_kind_check CHECK (kind IN ('view', 'cta', 'section'));
