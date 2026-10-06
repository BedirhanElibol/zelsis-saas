/** Result of the API key server actions in app/actions/api-keys.ts. */
export interface ApiKeyActionState {
  status: 'idle' | 'success' | 'error';
  message: string;
  /** Present once, right after createApiKey. */
  secret?: string;
}

export const initialApiKeyState: ApiKeyActionState = { status: 'idle', message: '' };

export interface ApiKeySummary {
  id: string;
  name: string;
  prefix: string;
  lastUsedAt: string | null;
  createdAt: string;
}
