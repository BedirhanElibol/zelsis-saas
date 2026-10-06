import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

// AST-09: modelled on Zelsis's own createFixPR (fixed in PR #50): a Server Action with the service-role
// client, a caller-chosen project id and no session check, opening a PR through a GitHub App client.

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29309], name: 'AST-09 Server Action opens a PR for a caller-chosen project with no auth',
    detects: f('app/actions/auto-fix.ts', `'use server';
import { createClient } from '@supabase/supabase-js';
import { createGitHubAppClient } from '@/lib/github/app';

export async function createFixPR(projectId: string, patch: string) {
  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
  const { data: project } = await admin.from('projects').select('repo_url, installation_id').eq('id', projectId).single();
  const octokit = await createGitHubAppClient(project.installation_id);
  const [owner, repo] = project.repo_url.split('/').slice(-2);
  await octokit.rest.git.createRef({ owner, repo, ref: 'refs/heads/fix', sha: 'abc' });
  const { data: pr } = await octokit.rest.pulls.create({ owner, repo, head: 'fix', base: 'main', title: 'fix', body: patch });
  return pr.html_url;
}
`),
    ignores: f('app/actions/auto-fix.ts', `'use server';
import { createClient } from '@supabase/supabase-js';
import { createGitHubAppClient } from '@/lib/github/app';

export async function createFixPR(projectId: string, patch: string, accessToken: string) {
  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
  const { data: auth } = await admin.auth.getUser(accessToken);
  if (!auth?.user) return null;
  const { data: project } = await admin.from('projects').select('repo_url, installation_id').eq('id', projectId).eq('user_id', auth.user.id).single();
  const octokit = await createGitHubAppClient(project.installation_id);
  const [owner, repo] = project.repo_url.split('/').slice(-2);
  const { data: pr } = await octokit.rest.pulls.create({ owner, repo, head: 'fix', base: 'main', title: 'fix', body: patch });
  return pr.html_url;
}
`),
  },
  {
    ruleIds: [29309], name: 'AST-09 route handler creates a GitHub issue in a repo named by the request',
    detects: f('app/api/report/route.ts', `import { Octokit } from '@octokit/rest';
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

export async function POST(req: Request) {
  const { owner, repo, title } = await req.json();
  await octokit.rest.issues.create({ owner, repo, title });
  return Response.json({ ok: true });
}
`),
    ignores: f('app/api/report/route.ts', `import { Octokit } from '@octokit/rest';
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

export async function GET() {
  const { data } = await octokit.rest.repos.get({ owner: 'acme', repo: 'site' });
  return Response.json({ stars: data.stargazers_count });
}
`),
  },
];
