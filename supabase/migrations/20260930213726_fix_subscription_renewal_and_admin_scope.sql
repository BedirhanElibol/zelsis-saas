-- Fix subscription lifecycle & admin scope
-- 1. Paid plans no longer auto-extend 30 days when current_period_end elapses.
--    Renewals must come from the Polar webhook (which writes the new period end).
--    Expired paid plans are downgraded to Free; Free plans roll over monthly.
-- 2. Only the founder account keeps admin role / Enterprise founder grant.

CREATE OR REPLACE FUNCTION public.sync_subscription_quota_on_tier_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO ''
AS $function$
BEGIN
    -- Paid period elapsed without a webhook renewal: downgrade to Free
    IF NEW.plan_tier IN ('Pro', 'Enterprise') AND NEW.current_period_end < NOW() THEN
        NEW.plan_tier := 'Free';
        NEW.status := 'canceled';
    END IF;

    IF NEW.plan_tier = 'Free' THEN
        NEW.monthly_scan_quota := 3;
    ELSIF NEW.plan_tier IN ('Pro', 'Enterprise') THEN
        NEW.monthly_scan_quota := -1; -- -1 represents Unlimited
        NEW.scans_used_this_month := 0;
    END IF;

    -- Free monthly billing cycle rollover
    IF NEW.current_period_end < NOW() THEN
        NEW.current_period_start := NOW();
        NEW.current_period_end := NOW() + INTERVAL '30 days';
        NEW.scans_used_this_month := 0;
    END IF;

    RETURN NEW;
END;
$function$;

-- tr_protect_profile_tier only lets service_role change tier/role
SELECT set_config('request.jwt.claims', '{"role":"service_role"}', true);

-- Revoke founder grant from every account other than the founder
UPDATE public.subscriptions s
SET plan_tier = 'Free',
    status = 'active',
    current_period_start = NOW(),
    current_period_end = NOW() + INTERVAL '30 days',
    updated_at = NOW()
FROM public.profiles p
WHERE p.id = s.user_id
  AND lower(p.email) <> 'bedirelibol7@gmail.com'
  AND s.polar_subscription_id IS NULL
  AND s.current_period_end > NOW() + INTERVAL '5 years';

UPDATE public.profiles
SET role = 'user'
WHERE lower(email) <> 'bedirelibol7@gmail.com'
  AND role IN ('admin', 'super_admin');

UPDATE auth.users
SET raw_user_meta_data = raw_user_meta_data
    || jsonb_build_object('tier', 'Free', 'expiresAt', NULL, 'subscriptionStatus', 'canceled')
WHERE lower(email) <> 'bedirelibol7@gmail.com'
  AND (raw_user_meta_data->>'expiresAt' LIKE '2099%' OR raw_user_meta_data->>'tier' = 'Enterprise')
  AND NOT EXISTS (
    SELECT 1 FROM public.subscriptions s
    WHERE s.user_id = auth.users.id AND s.polar_subscription_id IS NOT NULL
  );
