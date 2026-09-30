-- Waitlist table for early access registrations
CREATE TABLE IF NOT EXISTS public.waitlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    framework_interest TEXT, -- e.g., 'nextjs', 'django', 'go'
    source TEXT, -- e.g., 'reddit', 'x', 'direct'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS
ALTER TABLE public.waitlist ENABLE ROW LEVEL SECURITY;

-- Allow anyone to insert into the waitlist (public endpoint)
DROP POLICY IF EXISTS "Allow public insert to waitlist" ON public.waitlist;
CREATE POLICY "Allow public insert to waitlist" 
    ON public.waitlist 
    FOR INSERT 
    WITH CHECK (true);

-- Only authenticated admins or service role can view the waitlist
DROP POLICY IF EXISTS "Allow authenticated to view waitlist" ON public.waitlist;
CREATE POLICY "Allow authenticated to view waitlist" 
    ON public.waitlist 
    FOR SELECT 
    USING (auth.role() = 'authenticated');
