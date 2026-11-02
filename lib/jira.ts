/**
 * Jira Cloud issue creation for findings. Only https://<site>.atlassian.net is accepted, so a stored
 * connection cannot point the server at an internal address.
 */

export interface JiraConnection {
  site: string;
  email: string;
  projectKey: string;
  issueType: string;
}

export interface JiraFinding {
  title: string;
  severity: string;
  category?: string;
  filePath?: string;
  lineRange?: string;
  remediationPrompt?: string;
  cweId?: string;
}

/** `https://acme.atlassian.net` from what a user may paste (`acme`, `acme.atlassian.net/jira/...`), or null. */
export function normalizeJiraSite(input: string): string | null {
  const value = input.trim().toLowerCase();
  const host = /^[a-z0-9][a-z0-9-]{0,62}$/.test(value)
    ? `${value}.atlassian.net`
    : value.replace(/^https?:\/\//, '').split(/[/?#]/)[0];
  return /^[a-z0-9][a-z0-9-]{0,62}\.atlassian\.net$/.test(host) ? `https://${host}` : null;
}

const text = (value: string) => ({ type: 'text', text: value });
const paragraph = (value: string) => ({ type: 'paragraph', content: [text(value)] });

/** Issue fields in Atlassian Document Format. */
export function buildIssue(finding: JiraFinding, conn: Pick<JiraConnection, 'projectKey' | 'issueType'>) {
  const location = finding.filePath ? `${finding.filePath}${finding.lineRange ? ` (${finding.lineRange})` : ''}` : undefined;
  const content = [
    paragraph(`Severity: ${finding.severity}${finding.category ? ` · ${finding.category}` : ''}${finding.cweId ? ` · ${finding.cweId}` : ''}`),
    ...(location ? [paragraph(`Location: ${location}`)] : []),
    ...(finding.remediationPrompt ? [{ type: 'heading', attrs: { level: 3 }, content: [text('How to fix')] }, paragraph(finding.remediationPrompt)] : []),
    paragraph('Created from a Zelsis finding.'),
  ];
  return {
    fields: {
      project: { key: conn.projectKey },
      issuetype: { name: conn.issueType },
      summary: `[${finding.severity}] ${finding.title}`.slice(0, 254),
      description: { type: 'doc', version: 1, content },
      labels: ['zelsis'],
    },
  };
}

const authHeader = (email: string, token: string) => `Basic ${Buffer.from(`${email}:${token}`).toString('base64')}`;

async function jiraFetch(conn: Pick<JiraConnection, 'site' | 'email'>, token: string, path: string, init: RequestInit = {}) {
  return fetch(`${conn.site}${path}`, {
    ...init,
    redirect: 'error',
    signal: AbortSignal.timeout(10_000),
    headers: { Authorization: authHeader(conn.email, token), Accept: 'application/json', 'Content-Type': 'application/json', ...init.headers },
  });
}

/** Checks the credentials and the project before a connection is saved. Returns an error sentence or null. */
export async function verifyJiraConnection(conn: JiraConnection, token: string): Promise<string | null> {
  const me = await jiraFetch(conn, token, '/rest/api/3/myself');
  if (me.status === 401 || me.status === 403) return 'Jira rejected the e-mail and API token.';
  if (!me.ok) return `Jira answered HTTP ${me.status}. Check the site address.`;
  const project = await jiraFetch(conn, token, `/rest/api/3/project/${encodeURIComponent(conn.projectKey)}`);
  if (project.status === 404) return `Project ${conn.projectKey} was not found or this account cannot see it.`;
  if (!project.ok) return `Jira answered HTTP ${project.status} for the project.`;
  return null;
}

/** Creates the issue and returns its browse URL, or throws with Jira's own message. */
export async function createJiraIssue(conn: JiraConnection, token: string, finding: JiraFinding): Promise<{ key: string; url: string }> {
  const res = await jiraFetch(conn, token, '/rest/api/3/issue', { method: 'POST', body: JSON.stringify(buildIssue(finding, conn)) });
  const body = await res.json().catch(() => null) as { key?: string; errorMessages?: string[]; errors?: Record<string, string> } | null;
  if (!res.ok || !body?.key) {
    const reason = [...(body?.errorMessages ?? []), ...Object.values(body?.errors ?? {})].join(' ') || `HTTP ${res.status}`;
    throw new Error(`Jira did not create the issue: ${reason}`);
  }
  return { key: body.key, url: `${conn.site}/browse/${body.key}` };
}
