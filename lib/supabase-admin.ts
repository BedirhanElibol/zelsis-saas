import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { getEffectiveSupabaseUrl, getEffectiveSupabaseAnonKey, CANONICAL_SUPABASE_URL } from '@/lib/supabase';

export { getEffectiveSupabaseUrl, getEffectiveSupabaseAnonKey, CANONICAL_SUPABASE_URL };

export const CANONICAL_SUPABASE_SERVICE_ROLE_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFmenBheWRma215Y3J3dXhtemtrIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4NzkxNzk3MSwiZXhwIjoyMTAzNDkzOTcxfQ.kLBj4jziP5PUzok82b62Cw2Hunpv90DtqNHs1RjieT0';

export function getEffectiveSupabaseServiceRoleKey(): string {
  const envKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (envKey && !envKey.includes('placeholder') && envKey.length > 20) {
    return envKey;
  }
  return CANONICAL_SUPABASE_SERVICE_ROLE_KEY;
}

let adminInstance: SupabaseClient | null = null;

export function getSupabaseAdmin(): SupabaseClient {
  if (!adminInstance) {
    const url = getEffectiveSupabaseUrl();
    const serviceRoleKey = getEffectiveSupabaseServiceRoleKey();
    adminInstance = createClient(url, serviceRoleKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      }
    });
  }
  return adminInstance;
}
