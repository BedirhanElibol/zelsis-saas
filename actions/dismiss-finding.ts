'use server';

import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import { z } from 'zod';
import { logger } from '@/lib/logger';

export interface ActionState {
  status: 'idle' | 'success' | 'error';
  message: string;
}

interface ActionContext {
  admin: SupabaseClient;
  user: User;
}

const fail = (message: string): ActionState => ({ status: 'error', message });
const ok = (message: string): ActionState => ({ status: 'success', message });

async function authenticate(accessToken: string): Promise<ActionContext | null> {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !anonKey || !serviceRoleKey) return null;
  const authClient = createClient(url, anonKey, { auth: { persistSession: false } });
  const { data, error } = await authClient.auth.getUser(accessToken);
  if (error || !data?.user) return null;
  return { admin: createClient(url, serviceRoleKey, { auth: { persistSession: false } }), user: data.user };
}

function parseForm<S extends z.ZodTypeAny>(schema: S, formData: FormData): z.infer<S> | null {
  const raw: Record<string, unknown> = {};
  formData.forEach((value, key) => {
    if (typeof value === 'string') raw[key] = value;
  });
  const parsed = schema.safeParse(raw);
  return parsed.success ? parsed.data : null;
}

const DismissFindingSchema = z.object({
  accessToken: z.string().min(1),
  projectId: z.string().uuid(),
  ruleId: z.string(), // We will parse to int if needed
  filePath: z.string().min(1),
  reason: z.enum(['false_positive', 'accepted_risk', 'test_code']),
  note: z.string().optional(),
});

export async function dismissFinding(_prev: ActionState, formData: FormData): Promise<ActionState> {
  const input = parseForm(DismissFindingSchema, formData);
  if (!input) return fail('Invalid request data.');
  
  const ctx = await authenticate(input.accessToken);
  if (!ctx) return fail('Please sign in again.');

  // Check project ownership
  const { data: project, error: projError } = await ctx.admin
    .from('projects')
    .select('user_id')
    .eq('id', input.projectId)
    .single();

  if (projError || !project) {
    return fail('Project not found.');
  }

  // If the user does not own the project, reject
  if (project.user_id !== ctx.user.id) {
    return fail('You do not have permission to modify this project.');
  }

  // Insert dismissal
  const { error } = await ctx.admin
    .from('finding_dismissals')
    .insert({
      project_id: input.projectId,
      user_id: ctx.user.id,
      rule_id: parseInt(input.ruleId, 10),
      file_path: input.filePath,
      reason: input.reason,
      note: input.note || null,
    });

  if (error) {
    logger.error('[DismissFinding] Insert failed:', error.message);
    if (error.code === '23505') { // Unique violation
      return fail('This finding is already dismissed.');
    }
    return fail('Failed to dismiss finding. Please try again.');
  }

  return ok('Finding dismissed successfully. It will be excluded from future scans.');
}
