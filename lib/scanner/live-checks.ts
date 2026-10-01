import type { Finding } from '@/data/schema';
import { validateSafeTargetUrl } from '@/lib/ssrf-guard';

/**
 * Live deployment probes: files that should never be served (.env, .git), TLS certificate health,
 * HTTP -> HTTPS redirect and session cookie flags. Every exposure is confirmed from the response body,
 * so SPAs that answer every path with index.html (soft 404) do not produce findings.
 */

export interface ExposedFile {
  path: string;
  kind: 'env' | 'git';
  /** What proved the exposure. Never contains secret values. */
  evidence: string;
}

export interface TlsInfo {
  /** Certificate chain and hostname verified by Node's default CA store. */
  authorized: boolean;
  authorizationError?: string;
  validTo?: string;
}

export interface InsecureCookie {
  name: string;
  missing: ('Secure' | 'HttpOnly')[];
}

export interface LiveProbeResult {
  host: string;
  exposedFiles: ExposedFile[];
  /** null: 443 refused or answered without TLS. Absent: undetermined (timeout), never treated as "no HTTPS". */
  tls?: TlsInfo | null;
  /** How plain http://host/ answers. 'unreachable' (port 80 closed) is fine. */
  plainHttp: 'redirects-to-https' | 'serves-content' | 'unreachable';
  insecureCookies: InsecureCookie[];
}

export interface LiveProbeOptions {
  fetchImpl?: typeof fetch;
  tlsInspect?: (host: string, ip: string | undefined, timeoutMs: number) => Promise<TlsInfo | null | undefined>;
  timeoutMs?: number;
}

const ENV_PATHS = ['/.env', '/.env.local', '/.env.production', '/.env.development'];
const GIT_PATHS = ['/.git/config', '/.git/HEAD'];
const MAX_BODY = 64 * 1024;
const UA = 'Zelsis-Release-Gate-Scanner/3.5';

const ENV_ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;

/** Returns the variable names when the body is a dotenv file, otherwise null. Values are never kept. */
export function parseEnvBody(body: string): string[] | null {
  if (/^\s*</.test(body)) return null;
  const lines = body.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  if (lines.length === 0) return null;
  const names = lines.map((l) => l.match(ENV_ASSIGNMENT)?.[1]).filter((n): n is string => Boolean(n));
  return names.length > 0 && names.length / lines.length >= 0.8 ? names : null;
}

export function isGitConfigBody(body: string): boolean {
  return /^\s*\[core\]/m.test(body) && /repositoryformatversion\s*=/.test(body);
}

export function isGitHeadBody(body: string): boolean {
  return /^(?:ref: refs\/[\w./-]+|[0-9a-f]{40})\s*$/.test(body.trim());
}

const SESSION_COOKIE = /sess|sid|token|auth|jwt|login|remember/i;
/** Cookies meant to be read by client JS: CSRF double-submit tokens and Supabase SSR auth cookies. */
const JS_READABLE_COOKIE = /csrf|xsrf|^sb-[\w-]+-auth-token/i;

export function findInsecureCookies(setCookies: string[], https: boolean): InsecureCookie[] {
  const out: InsecureCookie[] = [];
  for (const raw of setCookies) {
    const [pair, ...attrs] = raw.split(';');
    const name = pair.split('=')[0]?.trim();
    if (!name || !SESSION_COOKIE.test(name)) continue;
    const flags = new Set(attrs.map((a) => a.trim().split('=')[0].toLowerCase()));
    const missing: InsecureCookie['missing'] = [];
    if (https && !flags.has('secure')) missing.push('Secure');
    if (!flags.has('httponly') && !JS_READABLE_COOKIE.test(name)) missing.push('HttpOnly');
    if (missing.length) out.push({ name, missing });
  }
  return out;
}

async function readCapped(res: Response): Promise<string> {
  const text = await res.text();
  return text.slice(0, MAX_BODY);
}

/** One hop, no redirects followed: a redirect means the file is not served at that path. */
async function fetchNoRedirect(url: string, fetchImpl: typeof fetch, timeoutMs: number): Promise<Response | null> {
  const check = await validateSafeTargetUrl(url);
  if (!check.safe) return null;
  try {
    return await fetchImpl(url, { headers: { 'User-Agent': UA }, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  } catch {
    return null;
  }
}

async function probePath(origin: string, path: string, fetchImpl: typeof fetch, timeoutMs: number): Promise<ExposedFile | null> {
  const res = await fetchNoRedirect(`${origin}${path}`, fetchImpl, timeoutMs);
  if (!res || res.status !== 200) return null;
  if ((res.headers.get('content-type') || '').includes('text/html')) return null;
  const body = await readCapped(res);
  if (path.startsWith('/.env')) {
    const names = parseEnvBody(body);
    if (!names) return null;
    const shown = names.slice(0, 8).join(', ') + (names.length > 8 ? ` +${names.length - 8} more` : '');
    return { path, kind: 'env', evidence: `${names.length} variable${names.length === 1 ? '' : 's'}: ${shown} (values not stored)` };
  }
  if (path === '/.git/config' && isGitConfigBody(body)) return { path, kind: 'git', evidence: '[core] section with repositoryformatversion' };
  if (path === '/.git/HEAD' && isGitHeadBody(body)) return { path, kind: 'git', evidence: 'valid HEAD reference' };
  return null;
}

/** Errors that prove 443 does not serve TLS; anything else (timeouts, DNS hiccups) stays undetermined. */
const NO_TLS_ERRORS = new Set(['ECONNREFUSED', 'ECONNRESET', 'EPROTO', 'ERR_SSL_WRONG_VERSION_NUMBER']);

/** Reads the certificate presented on 443 without trusting it, then reports whether Node would trust it. */
export async function inspectTls(host: string, ip: string | undefined, timeoutMs: number): Promise<TlsInfo | null | undefined> {
  const tls = await import('node:tls');
  return new Promise((resolve) => {
    const socket = tls.connect({ host: ip || host, servername: host, port: 443, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      const cert = socket.getPeerCertificate();
      const info: TlsInfo = {
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
        validTo: cert?.valid_to ? new Date(cert.valid_to).toISOString() : undefined
      };
      socket.end();
      resolve(info);
    });
    socket.on('timeout', () => { socket.destroy(); resolve(undefined); });
    socket.on('error', (err: NodeJS.ErrnoException) => resolve(NO_TLS_ERRORS.has(err.code || '') ? null : undefined));
  });
}

export async function probeLiveSite(
  targetUrl: string,
  setCookies: string[],
  { fetchImpl = globalThis.fetch, tlsInspect = inspectTls, timeoutMs = 5000 }: LiveProbeOptions = {}
): Promise<LiveProbeResult> {
  const target = new URL(targetUrl);
  const host = target.hostname;
  const check = await validateSafeTargetUrl(targetUrl);
  const ip = check.safe ? check.resolvedIp : undefined;

  const [exposed, tlsInfo, plain] = await Promise.all([
    Promise.all([...ENV_PATHS, ...GIT_PATHS].map((p) => probePath(target.origin, p, fetchImpl, timeoutMs))),
    // TLS handshakes to distant hosts can take several seconds; give them twice the HTTP budget
    check.safe ? tlsInspect(host, ip, timeoutMs * 2).catch(() => undefined) : Promise.resolve(undefined),
    fetchNoRedirect(`http://${host}/`, fetchImpl, timeoutMs)
  ]);

  let plainHttp: LiveProbeResult['plainHttp'] = 'unreachable';
  if (plain) {
    const location = plain.headers.get('location') || '';
    if (plain.status >= 300 && plain.status < 400) {
      plainHttp = location.startsWith('https://') ? 'redirects-to-https' : 'serves-content';
    } else if (plain.status < 400) {
      plainHttp = 'serves-content';
    }
  }

  return {
    host,
    exposedFiles: exposed.filter((e): e is ExposedFile => e !== null),
    ...(tlsInfo === undefined ? {} : { tls: tlsInfo }),
    plainHttp,
    insecureCookies: findInsecureCookies(setCookies, target.protocol === 'https:')
  };
}

const DAY_MS = 24 * 60 * 60 * 1000;

export function buildLiveFindings(probe: LiveProbeResult, now: Date = new Date()): Finding[] {
  const findings: Finding[] = [];
  const target = `https://${probe.host}`;

  const envFiles = probe.exposedFiles.filter((f) => f.kind === 'env');
  if (envFiles.length) {
    findings.push({
      id: `live-env-${probe.host}`,
      ruleId: 27001,
      type: 'SECURITY',
      title: `LIVE-01: Environment file publicly downloadable (${envFiles.map((f) => f.path).join(', ')})`,
      severity: 'CRITICAL',
      category: 'Exposed Files',
      filePath: `${target}${envFiles[0].path}`,
      lineRange: 'HTTP 200',
      snippet: envFiles.map((f) => `${f.path}: ${f.evidence}`).join('\n'),
      reproductionSteps: [
        ...envFiles.map((f) => `GET ${target}${f.path} returned HTTP 200 with dotenv content (${f.evidence}).`),
        'Anyone can download these values without authentication.'
      ],
      remediationPrompt: `Stop serving ${envFiles.map((f) => f.path).join(', ')} from ${probe.host}: remove the file from the web root / build output and block dotfiles at the server or CDN. Treat every secret in it as leaked and rotate them now.`,
      status: 'OPEN',
      falsePositive: false
    });
  }

  const gitFiles = probe.exposedFiles.filter((f) => f.kind === 'git');
  if (gitFiles.length) {
    findings.push({
      id: `live-git-${probe.host}`,
      ruleId: 27002,
      type: 'SECURITY',
      title: `LIVE-02: Git repository metadata publicly downloadable (${gitFiles.map((f) => f.path).join(', ')})`,
      severity: 'HIGH',
      category: 'Exposed Files',
      filePath: `${target}${gitFiles[0].path}`,
      lineRange: 'HTTP 200',
      snippet: gitFiles.map((f) => `${f.path}: ${f.evidence}`).join('\n'),
      reproductionSteps: [
        ...gitFiles.map((f) => `GET ${target}${f.path} returned HTTP 200 (${f.evidence}).`),
        'With .git exposed, tools like git-dumper can rebuild the source code and its full history, including secrets that were committed and later removed.'
      ],
      remediationPrompt: `Remove the .git directory from the deployed web root on ${probe.host} and deny /.git/ at the server or CDN. Audit the repository history for committed secrets and rotate them.`,
      status: 'OPEN',
      falsePositive: false
    });
  }

  if (probe.tls === null && probe.plainHttp === 'serves-content') {
    findings.push({
      id: `live-nohttps-${probe.host}`,
      ruleId: 27003,
      type: 'SECURITY',
      title: 'LIVE-03: Site is served over plain HTTP only (no HTTPS on port 443)',
      severity: 'HIGH',
      category: 'Network & TLS',
      filePath: `http://${probe.host}/`,
      lineRange: 'TLS',
      snippet: `http://${probe.host}/ answers; no TLS handshake on ${probe.host}:443`,
      reproductionSteps: [`Connected to ${probe.host}:443: no TLS handshake completed.`, `GET http://${probe.host}/ returned content without redirecting to HTTPS.`],
      remediationPrompt: `Enable HTTPS on ${probe.host} (most hosts and CDNs issue a free certificate automatically) and redirect all HTTP traffic to HTTPS.`,
      status: 'OPEN',
      falsePositive: false
    });
  }

  if (probe.tls && !probe.tls.authorized) {
    findings.push({
      id: `live-badcert-${probe.host}`,
      ruleId: 27004,
      type: 'SECURITY',
      title: `LIVE-04: TLS certificate is not trusted (${probe.tls.authorizationError || 'verification failed'})`,
      severity: 'CRITICAL',
      category: 'Network & TLS',
      filePath: `${target}:443`,
      lineRange: 'TLS',
      snippet: `authorizationError: ${probe.tls.authorizationError || 'unknown'}${probe.tls.validTo ? `; valid until ${probe.tls.validTo}` : ''}`,
      reproductionSteps: [`TLS handshake with ${probe.host}:443 using the default CA store failed verification: ${probe.tls.authorizationError || 'unknown error'}.`, 'Browsers show a full-page security warning and API clients refuse to connect.'],
      remediationPrompt: `Install a valid certificate for ${probe.host} that covers this exact hostname and includes the full intermediate chain, then re-check with an SSL tester.`,
      status: 'OPEN',
      falsePositive: false
    });
  } else if (probe.tls?.validTo) {
    const daysLeft = Math.floor((new Date(probe.tls.validTo).getTime() - now.getTime()) / DAY_MS);
    if (daysLeft <= 21) {
      findings.push({
        id: `live-certexpiry-${probe.host}`,
        ruleId: 27005,
        type: 'SECURITY',
        title: `LIVE-05: TLS certificate expires in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`,
        severity: daysLeft <= 7 ? 'HIGH' : 'MEDIUM',
        category: 'Network & TLS',
        filePath: `${target}:443`,
        lineRange: 'TLS',
        snippet: `notAfter: ${probe.tls.validTo}`,
        reproductionSteps: [`Certificate presented by ${probe.host}:443 is valid until ${probe.tls.validTo} (${daysLeft} days from the scan).`, 'Auto-renewal normally replaces certificates about 30 days before expiry, so renewal is likely failing.'],
        remediationPrompt: `Renew the TLS certificate for ${probe.host} and fix the automatic renewal (check DNS / HTTP-01 challenge reachability and the renewal job logs).`,
        status: 'OPEN',
        falsePositive: false
      });
    }
  }

  if (probe.tls?.authorized && probe.plainHttp === 'serves-content') {
    findings.push({
      id: `live-noredirect-${probe.host}`,
      ruleId: 27006,
      type: 'SECURITY',
      title: 'LIVE-06: HTTP requests are not redirected to HTTPS',
      severity: 'MEDIUM',
      category: 'Network & TLS',
      filePath: `http://${probe.host}/`,
      lineRange: 'HTTP',
      snippet: `GET http://${probe.host}/ -> served without redirect to https://`,
      reproductionSteps: [`GET http://${probe.host}/ returned a page instead of a redirect to https://${probe.host}/.`, 'Visitors who type the bare domain stay on an unencrypted connection that can be read or modified in transit.'],
      remediationPrompt: `Redirect all http://${probe.host} requests to HTTPS with a 301/308 at the server or CDN, and send Strict-Transport-Security on HTTPS responses.`,
      status: 'OPEN',
      falsePositive: false
    });
  }

  if (probe.insecureCookies.length) {
    findings.push({
      id: `live-cookies-${probe.host}`,
      ruleId: 27007,
      type: 'SECURITY',
      title: `LIVE-07: Session cookie set without ${[...new Set(probe.insecureCookies.flatMap((c) => c.missing))].join(' / ')}`,
      severity: 'MEDIUM',
      category: 'Session Security',
      filePath: `${target}/`,
      lineRange: 'Set-Cookie',
      snippet: probe.insecureCookies.map((c) => `Set-Cookie: ${c.name}=… (missing ${c.missing.join(', ')})`).join('\n'),
      reproductionSteps: probe.insecureCookies.map((c) => `Cookie "${c.name}" from ${target}/ is missing ${c.missing.join(' and ')}.`),
      remediationPrompt: `Set the Secure and HttpOnly attributes (and SameSite=Lax or Strict) on ${probe.insecureCookies.map((c) => c.name).join(', ')} where they are issued.`,
      status: 'OPEN',
      falsePositive: false
    });
  }

  return findings;
}
