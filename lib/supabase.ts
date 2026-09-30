import { createClient, SupabaseClient, Session } from '@supabase/supabase-js';
import { UserProfile } from '@/components/auth/AuthModal';
import type { Project } from '@/data/schema';
import { isPlatformAdminEmail, isFounderGrantExpiry } from '@/lib/subscription-utils';

export { isPlatformAdminEmail };

export const CANONICAL_SUPABASE_URL = 'https://afzpaydfkmycrwuxmzkk.supabase.co';
export const CANONICAL_SUPABASE_ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFmenBheWRma215Y3J3dXhtemtrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODc5MTc5NzEsImV4cCI6MjEwMzQ5Mzk3MX0.MNtKjLI3mNmGIRmcirzwnGknw0VJy58A2noAnEZZKZA';

export const getEffectiveSupabaseUrl = (): string => {
  const envUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
  if (envUrl && !envUrl.includes('sb-project.supabase.co') && !envUrl.includes('placeholder')) {
    return envUrl;
  }
  return CANONICAL_SUPABASE_URL;
};

export const getEffectiveSupabaseAnonKey = (): string => {
  const envKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
  if (envKey && !envKey.includes('placeholder') && envKey.length > 20) {
    return envKey;
  }
  return CANONICAL_SUPABASE_ANON_KEY;
};

let supabaseInstance: SupabaseClient | null = null;

export const isSupabaseConfigured = (): boolean => {
  const url = getEffectiveSupabaseUrl();
  const anonKey = getEffectiveSupabaseAnonKey();
  return Boolean(
    url &&
    anonKey &&
    !url.includes('sb-project.supabase.co') &&
    !url.includes('placeholder')
  );
};

export const getSupabase = (): SupabaseClient | null => {
  if (!supabaseInstance) {
    const url = getEffectiveSupabaseUrl();
    const anonKey = getEffectiveSupabaseAnonKey();
    if (!url || !anonKey) return null;
    try {
      supabaseInstance = createClient(url, anonKey, {
        auth: {
          persistSession: true,
          autoRefreshToken: true,
          detectSessionInUrl: true,
        }
      });
    } catch (err) {
      console.warn('[Zelsis Supabase] Failed to initialize Supabase client:', err);
    }
  }
  return supabaseInstance;
};

// Authentication Helpers
export async function supabaseSignIn(email: string, password: string): Promise<{ user: UserProfile | null; error: string | null }> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return {
      user: null,
      error: 'Authentication service is momentarily unavailable. Please check your network connection and try again.'
    };
  }

  try {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return { user: null, error: error.message };

    if (data.user) {
      const userProfile = mapSupabaseUserToProfile(data.user);
      return { user: userProfile, error: null };
    }
    return { user: null, error: 'User not found' };
  } catch (err: unknown) {
    return { user: null, error: err instanceof Error ? err.message : 'Authentication error occurred.' };
  }
}



export async function supabaseSignUp(email: string, password: string, name: string): Promise<{ user: UserProfile | null; error: string | null; requiresVerification?: boolean }> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return {
      user: null,
      error: 'Authentication service is momentarily unavailable. Please check your network connection and try again.',
      requiresVerification: false
    };
  }

  try {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: name,
          tier: isPlatformAdminEmail(email) ? 'Enterprise' : 'Free'
        }
      }
    });

    if (error) return { user: null, error: error.message };

    if (data.user) {
      const userProfile = mapSupabaseUserToProfile(data.user);
      return { user: userProfile, error: null, requiresVerification: !data.user.email_confirmed_at };
    }
    return { user: null, error: 'Registration completed but user state could not be verified.' };
  } catch (err: unknown) {
    return { user: null, error: err instanceof Error ? err.message : 'Sign up error occurred.' };
  }
}

export async function supabaseResetPassword(email: string): Promise<{ success: boolean; message: string }> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return {
      success: false,
      message: 'Authentication service is momentarily unavailable. Please check your network connection and try again.'
    };
  }

  try {
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/dashboard`
    });
    if (error) return { success: false, message: error.message };
    return {
      success: true,
      message: `Password reset instruction email successfully sent to ${email}.`
    };
  } catch (err: unknown) {
    return { success: false, message: err instanceof Error ? err.message : 'Password reset request failed.' };
  }
}

export async function supabaseSignOut(): Promise<void> {
  const supabase = getSupabase();
  if (supabase && isSupabaseConfigured()) {
    try {
      await supabase.auth.signOut();
    } catch (err) {
      console.warn('[Zelsis Auth] Supabase sign out error:', err);
    }
  }
}

export function mapSupabaseUserToProfile(supabaseUser: {
  email?: string;
  user_metadata?: Record<string, unknown>;
  app_metadata?: Record<string, unknown>;
  email_confirmed_at?: string | null;
}): UserProfile {
  const metadata = supabaseUser?.user_metadata || {};
  const userEmailNorm = (supabaseUser?.email || '').toLowerCase().trim();
  const rawName = (metadata.full_name as string) || (metadata.name as string) || (metadata.user_name as string) || (userEmailNorm ? userEmailNorm.split('@')[0] : 'User');
  const avatar = (metadata.avatar_url as string) || (metadata.picture as string) || (metadata.user_name ? `https://github.com/${metadata.user_name}.png` : undefined);
  // Founder & Platform Administrator Detection (Configured via server-only ADMIN_EMAILS)
  const isPlatformAdmin = isPlatformAdminEmail(userEmailNorm);

  let tier: 'Free' | 'Pro' | 'Enterprise' = 'Free';
  let expiresAt: string | undefined = undefined;
  let status: 'active' | 'past_due' | 'canceled' | 'trialing' = 'active';
  let billingCycle: 'monthly' | 'annual' | undefined = undefined;

  if (isPlatformAdmin) {
    tier = 'Enterprise';
    expiresAt = '2099-12-31T23:59:59.999Z';
    status = 'active';
    billingCycle = 'annual';
  } else {
    // Non-founder: strictly validate tier and reject tainted founder 2099 dates
    const rawTier = metadata.tier as 'Free' | 'Pro' | 'Enterprise' | undefined;
    const rawExpiresAt = metadata.expiresAt as string | undefined;

    const isTaintedDate = isFounderGrantExpiry(rawExpiresAt);

    if (isTaintedDate || !rawTier || rawTier === 'Free') {
      tier = 'Free';
      expiresAt = undefined;
      status = 'canceled';
      billingCycle = undefined;
    } else {
      const expiryTime = rawExpiresAt ? new Date(rawExpiresAt).getTime() : 0;
      if (!isNaN(expiryTime) && expiryTime > Date.now()) {
        tier = rawTier;
        expiresAt = rawExpiresAt;
        status = (metadata.subscriptionStatus as any) || 'active';
        billingCycle = (metadata.billingCycle as any) || 'monthly';
      } else {
        tier = 'Free';
        expiresAt = undefined;
        status = 'canceled';
        billingCycle = undefined;
      }
    }
  }

  return {
    name: rawName || 'User',
    email: supabaseUser?.email || '',
    avatarUrl: avatar,
    tier,
    isLoggedIn: true,
    emailVerified: Boolean(
      supabaseUser?.email_confirmed_at != null ||
      supabaseUser?.app_metadata?.provider === 'github' ||
      supabaseUser?.app_metadata?.provider === 'google' ||
      metadata.email_verified === true
    ),
    expiresAt,
    status,
    gracePeriodUntil: undefined,
    billingCycle
  };
}

export async function syncUserProfileToSupabase(user: Partial<UserProfile>): Promise<boolean> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) return false;
  try {
    // F-02 Remediation: Strictly prevent client-side escalation of tier, expiresAt, or subscription status.
    // Client is only permitted to update profile display properties (full_name).
    // Paid tiers and subscriptions are managed exclusively by server webhooks and admin APIs.
    const { error } = await supabase.auth.updateUser({
      data: {
        ...(user.name ? { full_name: user.name } : {}),
      }
    });
    if (error) {
      console.warn('[Zelsis Auth] Failed to sync profile to Supabase metadata:', error.message);
      return false;
    }
    return true;
  } catch (err) {
    console.warn('[Zelsis Auth] syncUserProfileToSupabase error:', err);
    return false;
  }
}

export async function supabaseSignInWithOAuth(
  provider: 'github' | 'google',
  redirectTo?: string
): Promise<{ url?: string | null; error: string | null }> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return { error: 'Authentication service is momentarily unavailable. Please try again in a moment.' };
  }

  try {
    const defaultOrigin = typeof window !== 'undefined' ? window.location.origin : 'https://zelsis.com';
    const finalRedirect = redirectTo || `${defaultOrigin}/auth/callback`;

    const { data, error } = await supabase.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: finalRedirect,
        scopes: provider === 'github' ? 'read:user user:email' : undefined,
        queryParams: provider === 'google' ? {
          prompt: 'select_account',
          access_type: 'offline'
        } : undefined
      }
    });

    if (error) return { error: error.message };
    return { url: data?.url, error: null };
  } catch (err: unknown) {
    return { error: err instanceof Error ? err.message : 'OAuth initialization failed' };
  }
}

export async function supabaseGetSession(): Promise<{ user: UserProfile | null; session: Session | null; error: string | null }> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return { user: null, session: null, error: null };
  }

  try {
    // Use getUser() for server-side JWT verification instead of getSession()
    // getSession() reads from unverified local storage and can be forged
    const { data: { user: verifiedUser }, error: userError } = await supabase.auth.getUser();
    if (userError || !verifiedUser) {
      return { user: null, session: null, error: userError?.message || null };
    }

    const { data: { session } } = await supabase.auth.getSession();
    const profile = mapSupabaseUserToProfile(verifiedUser);
    return { user: profile, session, error: null };
  } catch (err: unknown) {
    return { user: null, session: null, error: err instanceof Error ? err.message : 'Failed to fetch session' };
  }
}

/**
 * Resolves the signed-in user from a server-verified Supabase session.
 * Cached localStorage profiles are never trusted on their own: without a
 * verified session the caller must treat the visitor as signed out.
 * A network failure keeps the locally stored session so offline reloads work.
 */
export async function resolveVerifiedSession(): Promise<{
  status: 'authenticated' | 'unauthenticated';
  user: UserProfile | null;
  session: Session | null;
}> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return { status: 'unauthenticated', user: null, session: null };
  }

  try {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session?.user) {
      return { status: 'unauthenticated', user: null, session: null };
    }

    const { data: { user: verifiedUser }, error } = await supabase.auth.getUser();
    if (verifiedUser) {
      return { status: 'authenticated', user: mapSupabaseUserToProfile(verifiedUser), session };
    }

    const isNetworkFailure = Boolean(error && (error.name === 'AuthRetryableFetchError' || error.status === 0));
    if (isNetworkFailure) {
      return { status: 'authenticated', user: mapSupabaseUserToProfile(session.user), session };
    }

    // Revoked / expired / deleted account: drop the stale local session
    await supabase.auth.signOut({ scope: 'local' }).catch(() => {});
    return { status: 'unauthenticated', user: null, session: null };
  } catch {
    return { status: 'unauthenticated', user: null, session: null };
  }
}

/**
 * Loads the signed-in user's saved projects (repositories and live sites) from the cloud database.
 * RLS restricts the result to rows owned by the current user.
 */
export async function fetchCloudProjects(): Promise<Project[]> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) return [];

  const { data, error } = await supabase
    .from('projects')
    .select('id, name, repo_url, preview_url, framework, providers, last_scan_at, readiness_score, gate_status, critical_count, high_count, medium_count, low_count, ui_cliche_count')
    .order('updated_at', { ascending: false })
    .limit(100);

  if (error || !Array.isArray(data)) {
    if (error) console.warn('[Zelsis Supabase] Could not load cloud projects:', error.message);
    return [];
  }

  return data.map((row) => ({
    id: row.id,
    name: row.name,
    repoUrl: row.repo_url,
    previewUrl: row.preview_url || undefined,
    framework: row.framework || 'Auto-Detect',
    providers: Array.isArray(row.providers) ? row.providers : [],
    lastScanAt: row.last_scan_at ? new Date(row.last_scan_at).toLocaleString() : 'Never audited',
    readinessScore: row.readiness_score ?? 100,
    gateStatus: row.gate_status || 'PASSED',
    criticalCount: row.critical_count ?? 0,
    highCount: row.high_count ?? 0,
    mediumCount: row.medium_count ?? 0,
    lowCount: row.low_count ?? 0,
    uiClicheCount: row.ui_cliche_count ?? 0,
    findings: [],
  }));
}
