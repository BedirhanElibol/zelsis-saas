'use server';

import { createGitHubAppClient } from '@/lib/github/app';
import { createClient } from '@supabase/supabase-js';
import { Finding } from '@/data/schema';
import { revalidatePath } from 'next/cache';

export async function createFixPR(projectId: string, finding: Finding): Promise<{ success: boolean; prUrl?: string; error?: string }> {
  // Try to authenticate
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !serviceRoleKey) throw new Error('Missing Supabase credentials');
  
  const adminClient = createClient(url, serviceRoleKey, { auth: { persistSession: false } });

  const { data: projectData } = await adminClient
    .from('projects')
    .select('user_id, repo_url')
    .eq('id', projectId)
    .single();

  if (!projectData) throw new Error('Project not found');
  const { user_id, repo_url } = projectData;

  const { data: installData } = await adminClient
    .from('github_installations')
    .select('installation_id')
    .eq('user_id', user_id)
    .limit(1);

  if (!installData || installData.length === 0 || !installData[0].installation_id) {
    throw new Error('GitHub App is not installed for this user.');
  }

  const installationId = installData[0].installation_id;
  const octokit = await createGitHubAppClient(installationId);

  // Parse repo owner and name
  const match = repo_url.match(/github\.com\/([^\/]+)\/([^\/]+)/);
  if (!match) throw new Error('Invalid GitHub repo URL');
  const owner = match[1];
  const repo = match[2].replace('.git', '');

  // Fetch the default branch SHA
  const { data: repoInfo } = await octokit.rest.repos.get({ owner, repo });
  const defaultBranch = repoInfo.default_branch;
  const { data: refData } = await octokit.rest.git.getRef({ owner, repo, ref: `heads/${defaultBranch}` });
  const baseSha = refData.object.sha;

  // Create a new branch
  const branchName = `fix/zelsis-auto-fix-${finding.ruleId}-${Date.now()}`;
  await octokit.rest.git.createRef({
    owner,
    repo,
    ref: `refs/heads/${branchName}`,
    sha: baseSha
  });

  // Fetch the file content
  const filePath = finding.filePath;
  const { data: fileData } = await octokit.rest.repos.getContent({
    owner,
    repo,
    path: filePath,
    ref: branchName
  });

  if (Array.isArray(fileData) || fileData.type !== 'file' || !fileData.content) {
    throw new Error('Target file is not valid');
  }

  const originalContent = Buffer.from(fileData.content, 'base64').toString('utf8');
  let newContent = originalContent;

  // Apply deterministic fix
  if (finding.ruleId === 101 || finding.ruleId === 102 || finding.ruleId === 103 || finding.ruleId === 104) {
    // Missing headers in next.config / vercel.json
    if (filePath.endsWith('vercel.json')) {
      const parsed = JSON.parse(originalContent);
      if (!parsed.headers) parsed.headers = [];
      const routeHeader = parsed.headers.find((h: { source?: string; key?: string }) => h.source === '/(.*)');
      if (!routeHeader) {
        parsed.headers.push({
          source: '/(.*)',
          headers: []
        });
      }
      const targetRoute = parsed.headers.find((h: { source?: string; key?: string }) => h.source === '/(.*)');
      const targetHeaders = targetRoute.headers;
      
      const setIfMissing = (key: string, val: string) => {
        if (!targetHeaders.some((h: { source?: string; key?: string }) => h.key?.toLowerCase() === key.toLowerCase())) {
          targetHeaders.push({ key, value: val });
        }
      };
      
      if (finding.ruleId === 101) setIfMissing('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none';");
      if (finding.ruleId === 102) setIfMissing('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
      if (finding.ruleId === 103) setIfMissing('X-Frame-Options', 'DENY');
      if (finding.ruleId === 104) setIfMissing('X-Content-Type-Options', 'nosniff');
      
      newContent = JSON.stringify(parsed, null, 2) + '\n';
    } else if (filePath.endsWith('next.config.mjs') || filePath.endsWith('next.config.js')) {
      if (newContent.includes('const nextConfig = {')) {
        const headerStr = `
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
          { key: 'Content-Security-Policy', value: "default-src 'self'; frame-ancestors 'none';" }
        ]
      }
    ];
  },`;
        newContent = newContent.replace('const nextConfig = {', 'const nextConfig = {' + headerStr);
      } else {
        throw new Error('Could not deterministically fix next.config. Please fix manually.');
      }
    }
  } else if (finding.ruleId === 3 || finding.ruleId === 4) { 
    // Append ENABLE ROW LEVEL SECURITY
    const tableMatch = originalContent.match(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(?:public\.)?"?([a-zA-Z0-9_]+)"?/i);
    const tableName = tableMatch ? tableMatch[1] : 'unknown_table';
    if (!originalContent.includes('ENABLE ROW LEVEL SECURITY')) {
      newContent = originalContent + `\n\nALTER TABLE "${tableName}" ENABLE ROW LEVEL SECURITY;\n`;
    }
  } else if (finding.category?.toLowerCase().includes('dependency') || finding.type === 'SECURITY') {
    // Assuming OSV finding ID mapping, or ruleId matches OSV.
    if (filePath.endsWith('package.json')) {
      // e.g. "Upgrade `lodash` to version `4.17.21`"
      const match = finding.remediationPrompt?.match(/Upgrade `([^`]+)` to version `([^`]+)`/);
      if (match) {
        const pkgName = match[1];
        const safeVersion = match[2];
        const parsed = JSON.parse(originalContent);
        if (parsed.dependencies && parsed.dependencies[pkgName]) parsed.dependencies[pkgName] = `^${safeVersion}`;
        if (parsed.devDependencies && parsed.devDependencies[pkgName]) parsed.devDependencies[pkgName] = `^${safeVersion}`;
        newContent = JSON.stringify(parsed, null, 2) + '\n';
      } else {
        throw new Error('Could not parse target version from finding.');
      }
    }
  }

  if (newContent === originalContent) {
    throw new Error('No changes were made. The file might already be fixed or fix format unrecognized.');
  }

  // Update file
  await octokit.rest.repos.createOrUpdateFileContents({
    owner,
    repo,
    path: filePath,
    message: `fix: auto-remediate Zelsis finding ${finding.ruleId}`,
    content: Buffer.from(newContent).toString('base64'),
    sha: fileData.sha,
    branch: branchName
  });

  // Create PR
  const prBody = `This PR was automatically generated by Zelsis to remediate a security finding.

### Finding
**${finding.title}**
${finding.category}

### Fix Applied
Deterministic patch applied for \`${filePath}\`.

> **Risk Note:** Please review the changes before merging. Automated fixes should be verified in your CI/CD pipeline.
`;

  const { data: pr } = await octokit.rest.pulls.create({
    owner,
    repo,
    title: `fix: auto-remediate finding ${finding.ruleId}`,
    head: branchName,
    base: defaultBranch,
    body: prBody
  });

  revalidatePath('/dashboard');
  return { success: true, prUrl: pr.html_url };
}
