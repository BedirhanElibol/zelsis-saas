import { NextResponse } from 'next/server';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { createGitHubAppClient, createCheckRun, updateCheckRun, postOrUpdatePRComment } from '@/lib/github/app';
import { fetchGithubRepositoryData } from '@/lib/github-api';
import { runStaticCodeScan } from '@/lib/scanner-engine';
import { calculateGateStatus, gatingFindings, calculateReadinessScore } from '@/lib/scanner/scoring';
import { getOrgPolicy } from '@/lib/organization';

export const maxDuration = 300; // Allow 5 minutes for scan processing

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';


// Verify GitHub webhook signature
export function verifySignature(reqBody: string, signature: string | null): boolean {
  const secret = process.env.GITHUB_APP_WEBHOOK_SECRET || '';
  if (!signature || !secret) return false;
  
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(reqBody);
  const expectedSignature = `sha256=${hmac.digest('hex')}`;
  
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  } catch (e) {
    return false;
  }
}

export async function POST(req: Request) {
  try {
    const signature = req.headers.get('x-hub-signature-256');
    const event = req.headers.get('x-github-event');
    const deliveryId = req.headers.get('x-github-delivery');
    
    if (!signature || !event || !deliveryId) {
      return NextResponse.json({ error: 'Missing required headers' }, { status: 400 });
    }

    const rawBody = await req.text();

    if (!verifySignature(rawBody, signature)) {
      return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
    }

    const payload = JSON.parse(rawBody);
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // Idempotency check
    const { data: existingEvent } = await supabase
      .from('webhook_events')
      .select('id')
      .eq('event_id', deliveryId)
      .eq('source', 'github')
      .single();

    if (existingEvent) {
      return NextResponse.json({ message: 'Event already processed' });
    }

    // Process event
    if (event === 'installation') {
      await handleInstallation(payload, supabase);
    } else if (event === 'pull_request') {
      await handlePullRequest(payload, supabase);
    }

    // Record event
    await supabase
      .from('webhook_events')
      .insert({
        event_id: deliveryId,
        source: 'github',
        processed_at: new Date().toISOString()
      });

    return NextResponse.json({ success: true });
  } catch (error: any) {
    console.error('GitHub Webhook Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}

async function handleInstallation(payload: any, supabase: any) {
  const { action, installation } = payload;
  
  if (action === 'created') {
    const senderLogin = payload.sender.login;
    
    const { data: user } = await supabase
      .from('profiles')
      .select('id')
      .eq('github_username', senderLogin)
      .single();

    if (user) {
      await supabase
        .from('github_installations')
        .insert({
          user_id: user.id,
          installation_id: installation.id,
          account_login: installation.account.login,
          account_type: installation.account.type,
          repository_selection: installation.repository_selection
        });
    }
  } else if (action === 'deleted') {
    await supabase
      .from('github_installations')
      .delete()
      .eq('installation_id', installation.id);
  }
}

async function handlePullRequest(payload: any, supabase: any) {
  const { action, pull_request, repository, installation } = payload;
  
  if (!installation) return; // Only process if installed as App
  
  if (action === 'opened' || action === 'synchronize') {
    const owner = repository.owner.login;
    const repo = repository.name;
    const headSha = pull_request.head.sha;
    const baseSha = pull_request.base.sha;
    const repoUrl = repository.html_url;

    // Get an octokit client authenticated for this installation
    const octokit = await createGitHubAppClient(installation.id);

    // Create Check Run indicating 'in_progress'
    const checkRun = await createCheckRun(octokit, owner, repo, headSha, 'Zelsis Security Gate');

    try {
      // Find user via installation to apply their policy
      const { data: installData } = await supabase
        .from('github_installations')
        .select('user_id')
        .eq('installation_id', installation.id)
        .single();
        
      const userId = installData?.user_id;
      let orgPolicy = null;
      let dismissals = [];

      if (userId) {
        orgPolicy = await getOrgPolicy(supabase, userId);
        const { data: dbDismissals } = await supabase
          .from('finding_dismissals')
          .select('rule_id, file_path')
          .eq('user_id', userId)
          .eq('status', 'ACTIVE');
        if (dbDismissals) {
          dismissals = dbDismissals.map((d: any) => ({ ruleId: d.rule_id, filePath: d.file_path }));
        }
      }

      // Fetch repo contents including changedFiles list
      const tokenAuth = await (octokit.auth as any)({ type: 'installation' });
      const token = tokenAuth.token;
      
      const repoData = await fetchGithubRepositoryData(repoUrl, token, undefined, undefined, headSha, baseSha);
      
      if (!repoData || !repoData.files || repoData.files.length === 0) {
        await updateCheckRun(octokit, owner, repo, checkRun.id, 'completed', 'skipped', {
          title: 'Scan Skipped',
          summary: 'No scannable files found in this repository.',
        });
        return;
      }

      const filesToScan = repoData.files;
      const changedFiles = repoData.changedFiles || [];

      // Run code scan
      const scanResult = await runStaticCodeScan(filesToScan, repository.full_name, { 
        dependencyAudit: false, 
        orgPolicy, 
        dismissals 
      });

      const { newFindings, existingFindings } = splitFindings(scanResult.findings, changedFiles);
      const annotations = generateAnnotations(newFindings);

      const gFindings = gatingFindings(newFindings);
      const gateStatus = calculateGateStatus(gFindings);

      const readinessScore = calculateReadinessScore(scanResult.findings);

      const isSuccess = gateStatus === 'PASSED' || gateStatus === 'WARNING';
      const conclusion = isSuccess ? 'success' : 'failure';

      // Complete Check Run
      await updateCheckRun(octokit, owner, repo, checkRun.id, 'completed', conclusion, {
        title: `${readinessScore}/100 Readiness Score`,
        summary: `### Zelsis Security Gate: **${gateStatus}**\n\n- **New Findings in PR:** ${newFindings.length}\n- **Existing Findings:** ${existingFindings.length}\n\n*Review annotations for details on new issues.*`,
        annotations
      });

      // Post/Update PR Comment
      const commentBody = `### Zelsis PR Gate Results\n\n` +
        `**Status:** ${gateStatus === 'PASSED' ? '✅ PASSED' : gateStatus === 'WARNING' ? '⚠️ WARNING' : '❌ FAILED'}\n` +
        `**Readiness Score:** ${readinessScore}/100\n\n` +
        `#### PR Findings Summary\n` +
        `- 🛑 **Critical:** ${gFindings.filter(f => f.severity === 'CRITICAL').length}\n` +
        `- 🚨 **High:** ${gFindings.filter(f => f.severity === 'HIGH').length}\n` +
        `- ⚠️ **Medium:** ${gFindings.filter(f => f.severity === 'MEDIUM').length}\n` +
        `- ℹ️ **Low:** ${gFindings.filter(f => f.severity === 'LOW').length}\n\n` +
        `_Scan includes ${newFindings.length} new issues and detected ${existingFindings.length} pre-existing issues._\n\n` +
        `[View full report on Zelsis](https://shipguard-saas.vercel.app/dashboard)`;
      
      await postOrUpdatePRComment(octokit, owner, repo, pull_request.number, commentBody);

    } catch (scanError: any) {
      console.error('PR Scan Error:', scanError);
      await updateCheckRun(octokit, owner, repo, checkRun.id, 'completed', 'failure', {
        title: 'Scan Error',
        summary: 'An error occurred during the Zelsis code scan. ' + (scanError.message || ''),
      });
    }
  }
}

export function splitFindings(findings: any[], changedFiles: string[]) {
  const newFindings = findings.filter(f => changedFiles.includes(f.filePath));
  const existingFindings = findings.filter(f => !changedFiles.includes(f.filePath));
  return { newFindings, existingFindings };
}

export function generateAnnotations(findings: any[]) {
  return findings.map(f => {
    let startLine = 1;
    let endLine = 1;
    if (f.lineRange && f.lineRange.includes('-')) {
      const parts = f.lineRange.split('-');
      startLine = parseInt(parts[0], 10) || 1;
      endLine = parseInt(parts[1], 10) || startLine;
    } else if (f.lineRange) {
      startLine = parseInt(f.lineRange, 10) || 1;
      endLine = startLine;
    }

    let annotationLevel: 'notice' | 'warning' | 'failure' = 'notice';
    if (f.severity === 'CRITICAL' || f.severity === 'HIGH') annotationLevel = 'failure';
    else if (f.severity === 'MEDIUM') annotationLevel = 'warning';

    return {
      path: f.filePath,
      start_line: startLine,
      end_line: endLine,
      annotation_level: annotationLevel,
      message: `${f.severity}: ${f.title}\n\n${f.category}`,
      title: `Zelsis: ${f.title}`
    };
  });
}
