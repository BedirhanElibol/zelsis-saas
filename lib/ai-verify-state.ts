/** Result of setAiVerify in app/actions/ai-verify.ts. */
export interface AiVerifyActionState {
  status: 'idle' | 'success' | 'error';
  message: string;
}

export const initialAiVerifyState: AiVerifyActionState = { status: 'idle', message: '' };

export interface AiVerifySettings {
  enabled: boolean;
  /** Pro or Team (own plan or workspace). */
  eligible: boolean;
  /** The server has an AI key configured. */
  available: boolean;
}
