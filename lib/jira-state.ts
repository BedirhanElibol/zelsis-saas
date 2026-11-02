/** Result of the Jira server actions in app/actions/jira.ts. */
export interface JiraActionState {
  status: 'idle' | 'success' | 'error';
  message: string;
  /** Browse URL of the issue after a successful create. */
  issueUrl?: string;
}

export const initialJiraState: JiraActionState = { status: 'idle', message: '' };

/** A saved connection as the browser sees it: never the token. */
export interface JiraConnectionSummary {
  site: string;
  email: string;
  projectKey: string;
  issueType: string;
}
