/** Result of the domain ownership server actions in app/actions/site-verification.ts. */
export interface SiteVerificationActionState {
  status: 'idle' | 'success' | 'error';
  message: string;
}

export const initialSiteVerificationState: SiteVerificationActionState = { status: 'idle', message: '' };

export interface SiteDomainSummary {
  hostname: string;
  token: string;
  verifiedAt: string | null;
  verifiedMethod: 'file' | 'dns' | null;
  /** Where to publish the token: the well-known file URL and the DNS TXT record value. */
  fileUrl: string;
  dnsValue: string;
}
