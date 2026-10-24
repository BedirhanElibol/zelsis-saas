/** Result of the trust-page server actions in app/actions/trust-page.ts. */
export interface TrustPageActionState {
  status: 'idle' | 'success' | 'error';
  message: string;
  /** The public page after a successful enable. */
  url?: string;
  /** Open CRITICAL / HIGH findings on the latest scan (the page shows "verified" only at 0). */
  blockers?: number;
}

export const initialTrustPageState: TrustPageActionState = { status: 'idle', message: '' };
