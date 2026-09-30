-- Waitlist table for early access registrations
CREATE TABLE IF NOT EXISTS public.waitlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID DEFAULT auth.uid(),
    email TEXT NOT NULL UNIQUE,
    framework_interest TEXT, -- e.g., 'nextjs', 'django', 'go'
    source TEXT, -- e.g., 'reddit', 'x', 'direct'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS
ALTER TABLE public.waitlist ENABLE ROW LEVEL SECURITY;

-- Scoped RLS Policies with explicit user ownership checks (SEC-45 / SEC-03)
DROP POLICY IF EXISTS "Allow public insert to waitlist" ON public.waitlist;
DROP POLICY IF EXISTS "Users can insert into waitlist" ON public.waitlist;
CREATE POLICY "Users can insert into waitlist" 
    ON public.waitlist 
    FOR INSERT 
    WITH CHECK (auth.uid() = user_id);

-- Only users can view their own waitlist entry
DROP POLICY IF EXISTS "Allow authenticated to view waitlist" ON public.waitlist;
DROP POLICY IF EXISTS "Users can view own waitlist entry" ON public.waitlist;
CREATE POLICY "Users can view own waitlist entry" 
    ON public.waitlist 
    FOR SELECT 
    USING (auth.uid() = user_id);
