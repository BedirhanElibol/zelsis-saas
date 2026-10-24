/** Result of the report-share server actions in app/actions/report-share.ts. */
export interface ReportShareActionState {
  status: 'idle' | 'success' | 'error';
  message: string;
  /** The public link after a successful create. */
  url?: string;
  token?: string;
}

export const initialReportShareState: ReportShareActionState = { status: 'idle', message: '' };
