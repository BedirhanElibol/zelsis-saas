import { createAppAuth } from '@octokit/auth-app';
import { normalizePrivateKey } from './private-key';
import { Octokit } from '@octokit/rest';

export async function createGitHubAppClient(installationId: number) {
  const appId = process.env.GITHUB_APP_ID;
  const privateKey = normalizePrivateKey(process.env.GITHUB_APP_PRIVATE_KEY);

  if (!appId || !privateKey) {
    throw new Error('Missing GitHub App credentials');
  }

  const octokit = new Octokit({
    authStrategy: createAppAuth,
    auth: {
      appId,
      privateKey,
      installationId,
    },
  });

  return octokit;
}

/** Check run and PR comment name shown on pull requests. */
export const CHECK_NAME = 'Zelsis Release Check';
const COMMENT_MARKER = '<!-- Zelsis Release Check -->';
// Comments posted before the rename carry this marker; match it so they are updated, not duplicated
const LEGACY_COMMENT_MARKER = '<!-- Zelsis Security Gate -->';

export async function createCheckRun(
  octokit: Octokit,
  owner: string,
  repo: string,
  headSha: string,
  checkName: string = CHECK_NAME
) {
  const { data: checkRun } = await octokit.rest.checks.create({
    owner,
    repo,
    name: checkName,
    head_sha: headSha,
    status: 'in_progress',
  });

  return checkRun;
}

export async function updateCheckRun(
  octokit: Octokit,
  owner: string,
  repo: string,
  checkRunId: number,
  status: 'in_progress' | 'completed',
  conclusion: 'success' | 'failure' | 'neutral' | 'action_required' | 'cancelled' | 'timed_out' | 'skipped' | null,
  output: {
    title: string;
    summary: string;
    text?: string;
    annotations?: Array<{
      path: string;
      start_line: number;
      end_line: number;
      annotation_level: 'notice' | 'warning' | 'failure';
      message: string;
      title?: string;
      raw_details?: string;
    }>;
  }
) {
  let annotations = output.annotations || [];
  
  // GitHub allows a max of 50 annotations per check run update.
  if (annotations.length <= 50) {
    await octokit.rest.checks.update({
      owner,
      repo,
      check_run_id: checkRunId,
      status,
      conclusion: conclusion as any,
      output,
    });
  } else {
    // Batch annotations
    const batches = [];
    for (let i = 0; i < annotations.length; i += 50) {
      batches.push(annotations.slice(i, i + 50));
    }
    
    for (let i = 0; i < batches.length; i++) {
      const isLast = i === batches.length - 1;
      await octokit.rest.checks.update({
        owner,
        repo,
        check_run_id: checkRunId,
        status: isLast ? status : 'in_progress',
        conclusion: isLast ? conclusion as any : undefined,
        output: {
          title: output.title,
          summary: output.summary,
          text: output.text,
          annotations: batches[i],
        },
      });
    }
  }
}

export async function postOrUpdatePRComment(
  octokit: Octokit,
  owner: string,
  repo: string,
  issueNumber: number,
  body: string
) {
  // Find if we already commented
  const { data: comments } = await octokit.rest.issues.listComments({
    owner,
    repo,
    issue_number: issueNumber,
  });

  const zelsisComment = comments.find((c: any) => c.body?.includes(COMMENT_MARKER) || c.body?.includes(LEGACY_COMMENT_MARKER));

  const finalBody = `<!-- Zelsis Security Gate -->\n${body}`;

  if (zelsisComment) {
    await octokit.rest.issues.updateComment({
      owner,
      repo,
      comment_id: zelsisComment.id,
      body: finalBody,
    });
  } else {
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: issueNumber,
      body: finalBody,
    });
  }
}
