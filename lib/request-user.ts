import { createClient } from '@supabase/supabase-js';
import { getEffectiveSupabaseAnonKey, getEffectiveSupabaseUrl } from '@/lib/supabase-admin';

/** The signed-in user behind a request's "Authorization: Bearer <supabase access token>", or null. */
export async function getRequestUserId(req: Request): Promise<string | null> {
  const token = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  const url = getEffectiveSupabaseUrl();
  const anon = getEffectiveSupabaseAnonKey();
  if (!token || !url || !anon) return null;
  try {
    const client = createClient(url, anon, { auth: { persistSession: false } });
    const { data, error } = await client.auth.getUser(token);
    return error || !data?.user ? null : data.user.id;
  } catch {
    return null;
  }
}
