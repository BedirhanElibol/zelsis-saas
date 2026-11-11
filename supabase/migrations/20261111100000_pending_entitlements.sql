-- Paid before signing up: the Polar webhook could not find an account for the payer's email, so the
-- payment was taken and no plan was granted. Keep the entitlement by email and apply it at signup.

CREATE TABLE IF NOT EXISTS public.pending_entitlements (
    email TEXT PRIMARY KEY CHECK (email = lower(email)),
    plan_tier TEXT NOT NULL CHECK (plan_tier IN ('Pro', 'Enterprise')),
    status TEXT NOT NULL,
    current_period_end TIMESTAMPTZ NOT NULL,
    billing_cycle TEXT,
    polar_subscription_id TEXT,
    source_event TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Written by the webhook with the service role only. RLS on and no policies: clients cannot read or write it.
ALTER TABLE public.pending_entitlements ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.pending_entitlements FROM anon, authenticated;

-- Same signup trigger as before. When an unexpired pending entitlement exists for the email, the new
-- profile and subscription rows are inserted with that plan instead of Free. Inserting (not updating)
-- keeps tr_protect_profile_tier intact: it only blocks tier UPDATEs outside the service role.
CREATE OR REPLACE FUNCTION public.handle_new_user_signup()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO ''
AS $function$
DECLARE
    pending public.pending_entitlements%ROWTYPE;
BEGIN
    SELECT * INTO pending
    FROM public.pending_entitlements
    WHERE email = lower(NEW.email) AND current_period_end > now();

    IF FOUND THEN
        INSERT INTO public.profiles (id, email, full_name, avatar_url, tier, status)
        VALUES (
            NEW.id,
            NEW.email,
            COALESCE(NEW.raw_user_meta_data->>'full_name', SPLIT_PART(NEW.email, '@', 1)),
            NEW.raw_user_meta_data->>'avatar_url',
            pending.plan_tier,
            pending.status
        )
        ON CONFLICT (id) DO NOTHING;

        INSERT INTO public.subscriptions (user_id, plan_tier, monthly_scan_quota, status, current_period_end, polar_subscription_id, cancel_at_period_end)
        VALUES (
            NEW.id,
            pending.plan_tier::public.plan_tier,
            3,
            pending.status,
            pending.current_period_end,
            pending.polar_subscription_id,
            pending.status = 'canceled'
        )
        ON CONFLICT (user_id) DO NOTHING;

        DELETE FROM public.pending_entitlements WHERE email = pending.email;
    ELSE
        INSERT INTO public.profiles (id, email, full_name, avatar_url, tier, status)
        VALUES (
            NEW.id,
            NEW.email,
            COALESCE(NEW.raw_user_meta_data->>'full_name', SPLIT_PART(NEW.email, '@', 1)),
            NEW.raw_user_meta_data->>'avatar_url',
            'Free',
            'active'
        )
        ON CONFLICT (id) DO NOTHING;

        INSERT INTO public.subscriptions (user_id, plan_tier, monthly_scan_quota)
        VALUES (NEW.id, 'Free', 3)
        ON CONFLICT (user_id) DO NOTHING;
    END IF;

    RETURN NEW;
END;
$function$;
