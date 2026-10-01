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

-- Allow anyone to submit an email to the waitlist (public lead capture)
DROP POLICY IF EXISTS "Allow public insert to waitlist" ON public.waitlist;
DROP POLICY IF EXISTS "Users can insert into waitlist" ON public.waitlist;
CREATE POLICY "Allow public insert to waitlist" 
    ON public.waitlist 
    FOR INSERT 
    WITH CHECK (email IS NOT NULL AND length(email) > 3);

-- Only authenticated users can view their own waitlist entry (zero public enumeration)
DROP POLICY IF EXISTS "Allow authenticated to view waitlist" ON public.waitlist;
DROP POLICY IF EXISTS "Users can view own waitlist entry" ON public.waitlist;
CREATE POLICY "Users can view own waitlist entry" 
    ON public.waitlist 
    FOR SELECT 
    USING (auth.uid() IS NOT NULL AND auth.uid() = user_id);
