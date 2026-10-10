import { createHmac, timingSafeEqual } from 'crypto';
import { createAppAuth } from '@octokit/auth-app';
import { Octokit } from '@octokit/rest';
import { getSupabaseAdmin } from '@/lib/supabase-admin';
import { logger } from '@/lib/logger';

/**
 * "Connect GitHub" through the Zelsis GitHub App: users install the app on the repositories they choose, and the
 * server mints short-lived read tokens for scans instead of asking for a personal access token.
 * Everything here is server-only (it uses the app private key and the service-role client).
 */

const appCredentials = () => {
  const appId = process.env.GITHUB_APP_ID;
  const privateKey = process.env.GITHUB_APP_PRIVATE_KEY?.replace(/\\n/g, '\n');
  return appId && privateKey ? { appId, privateKey } : null;
};

/** Public slug of the app (github.com/apps/<slug>); the connect button is hidden when the app is not configured. */
export const githubAppSlug = (): string | null => process.env.NEXT_PUBLIC_GITHUB_APP_SLUG?.trim() || null;
export const isGithubAppConfigured = (): boolean => Boolean(appCredentials() && githubAppSlug() && stateSecret());

const stateSecret = () => process.env.GITHUB_APP_WEBHOOK_SECRET || process.env.INTERNAL_API_SECRET || '';

/** Signed, expiring state that ties the GitHub install redirect back to the signed-in Zelsis user. */
export function signInstallState(userId: string, now = Date.now()): string {
  const payload = `${userId}.${now}`;
  const sig = createHmac('sha256', stateSecret()).update(payload).digest('base64url');
  return Buffer.from(`${payload}.${sig}`).toString('base64url');
}

export function verifyInstallState(state: string, now = Date.now(), maxAgeMs = 60 * 60 * 1000): string | null {
  try {
    const [userId, ts, sig] = Buffer.from(state, 'base64url').toString('utf8').split('.');
    if (!userId || !ts || !sig || !stateSecret()) return null;
    const expected = createHmac('sha256', stateSecret()).update(`${userId}.${ts}`).digest('base64url');
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
    if (now - Number(ts) > maxAgeMs || Number(ts) > now + 60_000) return null;
    return userId;
  } catch {
    return null;
  }
}

/** App-level client (JWT) for reading installation details. */
function appOctokit(): Octokit | null {
  const creds = appCredentials();
  return creds ? new Octokit({ authStrategy: createAppAuth, auth: creds }) : null;
}

export async function getInstallationDetails(installationId: number) {
  const octokit = appOctokit();
  if (!octokit) return null;
  const { data } = await octokit.rest.apps.getInstallation({ installation_id: installationId });
  const account = data.account as { login?: string; slug?: string; type?: string } | null;
  return {
    accountLogin: account?.login || account?.slug || '',
    accountType: account?.type || 'Organization',
    repositorySelection: data.repository_selection,
  };
}

/** Installation ids the user connected (newest first). */
export async function getUserInstallations(userId: string): Promise<{ installationId: number; accountLogin: string }[]> {
  const admin = getSupabaseAdmin();
  if (!admin) return [];
  const { data } = await admin
    .from('github_installations')
    .select('installation_id, account_login')
    .eq('user_id', userId)
    .order('created_at', { ascending: false });
  return (data || []).map((r) => ({ installationId: Number(r.installation_id), accountLogin: String(r.account_login) }));
}

/** A one-hour, read-only installation token for the owner's repositories, when the user connected that account. */
export async function installationTokenForRepo(userId: string, owner: string): Promise<string | null> {
  const creds = appCredentials();
  if (!creds) return null;
  try {
    const install = (await getUserInstallations(userId)).find((i) => i.accountLogin.toLowerCase() === owner.toLowerCase());
    if (!install) return null;
    const auth = createAppAuth({ ...creds, installationId: install.installationId });
    const { token } = await auth({ type: 'installation', permissions: { contents: 'read', metadata: 'read' } });
    return token;
  } catch (err) {
    logger.warn('[GitHub App] Could not mint an installation token:', err instanceof Error ? err.message : String(err));
    return null;
  }
}

/** Repositories the user gave the app access to, across all their installations. */
export async function listConnectedRepos(userId: string): Promise<{ repos: { fullName: string; private: boolean; url: string }[]; errors: string[] }> {
  const creds = appCredentials();
  if (!creds) return { repos: [], errors: ['GitHub App credentials are not configured'] };
  const out: { fullName: string; private: boolean; url: string }[] = [];
  // Error messages (never secrets) go back to the caller, so a misconfigured key shows up instead of an empty list
  const errors: string[] = [];
  for (const install of await getUserInstallations(userId)) {
    try {
      const octokit = new Octokit({ authStrategy: createAppAuth, auth: { ...creds, installationId: install.installationId } });
      const repos = await octokit.paginate(octokit.rest.apps.listReposAccessibleToInstallation, { per_page: 100 });
      for (const r of repos as unknown as { full_name: string; private: boolean; html_url: string }[]) {
        out.push({ fullName: r.full_name, private: r.private, url: r.html_url });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      errors.push(message.slice(0, 200));
      logger.warn('[GitHub App] Could not list installation repositories:', message);
    }
  }
  return { repos: out.slice(0, 500), errors };
}

/** OAuth client of the GitHub App ("Request user authorization during installation"), needed to link existing installations. */
const oauthClient = () => {
  const id = process.env.GITHUB_APP_CLIENT_ID?.trim();
  const secret = process.env.GITHUB_APP_CLIENT_SECRET?.trim();
  return id && secret ? { id, secret } : null;
};
export const isGithubOAuthConfigured = (): boolean => Boolean(oauthClient() && appCredentials());

/**
 * Links every installation of this app the GitHub user can access to the signed-in Zelsis user.
 * GitHub sends an OAuth code after install and after "Save" on an existing installation, so this also covers
 * reconnecting from another browser or account, where the signed install state is not available.
 */
export async function linkInstallationsFromOAuthCode(userId: string, code: string): Promise<number> {
  const client = oauthClient();
  const creds = appCredentials();
  const admin = getSupabaseAdmin();
  if (!client || !creds || !admin) return 0;

  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: client.id, client_secret: client.secret, code }),
    signal: AbortSignal.timeout(10_000),
  });
  const tokenJson = (await tokenRes.json().catch(() => ({}))) as { access_token?: string };
  if (!tokenJson.access_token) return 0;

  const res = await fetch('https://api.github.com/user/installations?per_page=100', {
    headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${tokenJson.access_token}`, 'X-GitHub-Api-Version': '2022-11-28' },
    signal: AbortSignal.timeout(10_000),
  });
  const data = (await res.json().catch(() => ({}))) as {
    installations?: { id: number; app_id: number; repository_selection: string; account: { login?: string; type?: string } | null }[];
  };
  const mine = (data.installations || []).filter((i) => String(i.app_id) === String(creds.appId));
  let linked = 0;
  for (const i of mine) {
    const { error } = await admin.from('github_installations').upsert(
      {
        user_id: userId,
        installation_id: i.id,
        account_login: i.account?.login || '',
        account_type: i.account?.type || 'User',
        repository_selection: i.repository_selection,
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'installation_id' }
    );
    if (!error) linked++;
    else logger.warn('[GitHub App] Could not link installation:', error.message);
  }
  return linked;
}
