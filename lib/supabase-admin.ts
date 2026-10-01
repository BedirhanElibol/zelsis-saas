import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { getEffectiveSupabaseUrl, getEffectiveSupabaseAnonKey, CANONICAL_SUPABASE_URL } from '@/lib/supabase';

export { getEffectiveSupabaseUrl, getEffectiveSupabaseAnonKey, CANONICAL_SUPABASE_URL };

/**
 * Service role key from the server environment only. It bypasses RLS, so it must never be
 * committed or given a fallback: a missing key returns '' and callers answer 500.
 */
export function getEffectiveSupabaseServiceRoleKey(): string {
  const envKey = process.env.SUPABASE_SERVICE_ROLE_KEY?.trim();
  return envKey && !envKey.includes('placeholder') && envKey.length > 20 ? envKey : '';
}

let adminInstance: SupabaseClient | null = null;

/** Service-role client, or null when SUPABASE_SERVICE_ROLE_KEY is not configured. */
export function getSupabaseAdmin(): SupabaseClient | null {
  if (!adminInstance) {
    const serviceRoleKey = getEffectiveSupabaseServiceRoleKey();
    if (!serviceRoleKey) {
      console.error('[Supabase Admin] SUPABASE_SERVICE_ROLE_KEY is not configured');
      return null;
    }
    adminInstance = createClient(getEffectiveSupabaseUrl(), serviceRoleKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      }
    });
  }
  return adminInstance;
}
