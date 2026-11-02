-- ==============================================================================
-- Migration: 20261102200000_testimonials.sql
-- Description: Quotes users send from the dashboard about what Zelsis caught.
-- One per user. Only rows with consent and status 'approved' are shown on the
-- landing page; approval is a manual review by the owner.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.testimonials (
    user_id UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
    quote TEXT NOT NULL CHECK (char_length(quote) BETWEEN 10 AND 280),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 80),
    role TEXT CHECK (role IS NULL OR char_length(role) <= 80),
    consent BOOLEAN NOT NULL CHECK (consent),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- RLS: users read their own quote; the server (service role) writes and reads
-- approved quotes for the landing page.
ALTER TABLE public.testimonials ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own testimonial"
    ON public.testimonials
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Service role can manage all testimonials"
    ON public.testimonials
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_testimonials_approved ON public.testimonials(updated_at DESC) WHERE status = 'approved';
