/** Result of the domain ownership server actions in app/actions/site-verification.ts. */
export interface SiteVerificationActionState {
  status: 'idle' | 'success' | 'error';
  message: string;
}

/** Header the scanner sends on exposure probes to verified domains; owners allow it in their firewall. */
export const PROBE_HEADER = 'x-zelsis-probe';

export const initialSiteVerificationState: SiteVerificationActionState = { status: 'idle', message: '' };

export interface SiteDomainSummary {
  hostname: string;
  token: string;
  verifiedAt: string | null;
  verifiedMethod: 'file' | 'dns' | null;
  /** Where to publish the token: the well-known file URL and the DNS TXT record value. */
  fileUrl: string;
  dnsValue: string;
  /** Secret the scanner sends as the x-zelsis-probe header; null until the domain is verified. */
  probeKey: string | null;
}
