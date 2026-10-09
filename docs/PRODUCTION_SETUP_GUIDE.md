# 🚀 Zelsis SaaS - Production Infrastructure & Panel Setup Guide

This guide details the exact, step-by-step configuration required across **Supabase**, **Polar**, and **Vercel** to fully activate live commercial operations.

---

## 1. Supabase Cloud Configuration (1 Minute)

### Step A: Apply Schema Patch
1. Navigate to your Supabase SQL Editor:  
   👉 **[Supabase SQL Editor](https://supabase.com/dashboard/project/_/sql/new)** (Select your project)
2. Copy and paste the contents of `sql/06_production_patch.sql`:
   ```sql
   ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS tier TEXT DEFAULT 'Free';
   ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
   ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS grace_period_until TIMESTAMPTZ;

   ALTER TABLE public.subscriptions ADD COLUMN IF NOT EXISTS grace_period_until TIMESTAMPTZ;
   ALTER TABLE public.subscriptions ADD COLUMN IF NOT EXISTS polar_subscription_id TEXT;

   CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON public.subscriptions(user_id);
   CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON public.subscriptions(status);
   CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
   ```
3. Click **Run** (green button).

### Step B: Configure OAuth Redirect URLs
1. Navigate to **Authentication -> URL Configuration** in your Supabase project:  
   👉 **Supabase Dashboard -> Authentication -> URL Configuration**
2. Set **Site URL** to:
   ```text
   https://zelsis.com
   ```
3. In **Redirect URLs**, add:
   ```text
   https://zelsis.com/**
   https://zelsis.com/auth/callback
   http://localhost:3000/auth/callback
   ```
4. Click **Save**.

### Step C: Copy Service Role Secret
1. Navigate to **Project Settings -> API** in your Supabase project:  
   👉 **Supabase Dashboard -> Project Settings -> API**
2. Under **Project API keys**, find `service_role` (Secret).
3. Click **Reveal** and copy the key (starts with `eyJhbGci...`). You will paste this into Vercel.

---

## 2. Polar.sh Merchant-of-Record Setup (2 Minutes)

### Step A: Add Webhook Endpoint
1. Navigate to your Polar Developer Settings:  
   👉 **[Polar Webhooks Settings](https://polar.sh/dashboard/_/settings)** (Developers -> Webhooks)
2. Click **Add Endpoint**.
3. Set **Endpoint URL** to:
   ```text
   https://zelsis.com/api/v1/polar-webhook
   ```
4. Select all of the following events:
   - `subscription.created`
   - `subscription.updated`
   - `subscription.past_due`
   - `subscription.canceled`
   - `subscription.revoked`
   - `subscription.uncanceled`
   - `order.created`
   - `order.refunded`
5. Click **Create**.
6. Copy the generated **Webhook Secret** (`polar_whsec_...`).

### Step B: Generate Polar Access Token
1. In Polar Settings, go to **Developers -> Personal Access Tokens**.
2. Click **New Token** (Name: `Zelsis Production Sync`).
3. Select scopes:
   - `orders:read`
   - `subscriptions:read`
   - `checkouts:read`
4. Click **Create** and copy the token (`polar_at_...`).

---

## 3. Vercel Production Environment Variables (2 Minutes)

1. Navigate to your Vercel Project Settings:  
   👉 **Vercel Dashboard -> shipguard-saas -> Settings -> Environment Variables**
2. Add or verify the following variables for the **Production** environment:

| Variable Name | Value | Purpose |
| :--- | :--- | :--- |
| `NEXT_PUBLIC_APP_URL` | `https://zelsis.com` | Canonical app URL |
| `NEXT_PUBLIC_SUPABASE_URL` | `https://<your-project-id>.supabase.co` | Supabase endpoint |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | `eyJhbGciOiJIUzI1NiIsInR5cCI...` | Supabase Anon Key |
| `SUPABASE_SERVICE_ROLE_KEY` | *(Copied from Supabase Step 1C)* | Server-side user & sub management |
| `POLAR_WEBHOOK_SECRET` | *(Copied from Polar Step 2A)* | HMAC signature verification |
| `POLAR_ACCESS_TOKEN` | *(Copied from Polar Step 2B)* | 12h background subscription sync |
| `NODE_ENV` | `production` | Production optimizations |

3. After saving, trigger a **Redeploy** on Vercel so all environment variables take immediate effect.
