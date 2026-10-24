import { NextResponse } from 'next/server';
import { getInstallationDetails, verifyInstallState } from '@/lib/github/installations';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { getConfiguredAppUrl } from '@/lib/app-url';
import { logger } from '@/lib/logger';

/**
 * GitHub App "Setup URL": GitHub sends the user here after they install (or change) the app.
 * The signed state proves which Zelsis user started the install; the installation's account comes from GitHub.
 */
export async function GET(req: Request) {
  const url = new URL(req.url);
  const back = (status: string) => NextResponse.redirect(`${getConfiguredAppUrl()}/dashboard?nav=projects&github=${status}`);

  const installationId = Number(url.searchParams.get('installation_id'));
  const userId = verifyInstallState(url.searchParams.get('state') || '');
  if (!Number.isSafeInteger(installationId) || installationId <= 0 || !userId) return back('error');

  try {
    const details = await getInstallationDetails(installationId);
    const admin = getSupabaseAdmin();
    if (!details?.accountLogin || !admin) return back('error');
    const { error } = await admin.from('github_installations').upsert(
      {
        user_id: userId,
        installation_id: installationId,
        account_login: details.accountLogin,
        account_type: details.accountType,
        repository_selection: details.repositorySelection,
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'installation_id' }
    );
    if (error) {
      logger.warn('[GitHub App] Could not save installation:', error.message);
      return back('error');
    }
    return back('connected');
  } catch (err) {
    logger.warn('[GitHub App] Setup failed:', err instanceof Error ? err.message : String(err));
    return back('error');
  }
}
