/**
 * Cloud, IaC, Kubernetes and container misconfiguration, research-backed (CLOUD-V2-xx, Rule IDs 28501-28599).
 *
 * Every rule keys on an explicit, insecure setting inside one Terraform resource block, one Kubernetes
 * document or one Dockerfile / Compose instruction (never on the absence of a setting somewhere in the
 * file). Sources: Checkov / Trivy (tfsec) / KICS check catalogs, kube-linter, CIS Docker and Kubernetes
 * benchmarks, Kubernetes Pod Security Standards, hadolint.
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';
import { stripHashComments, isYamlPath, tfResource, hclBlocks, hclLine, attrLineIn, PRINCIPAL_STAR, UNSCOPED_GRANT_EXEMPT, type HclBlock } from './iac-rules';

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; why: string; fix: string }

const DOCKERFILE_PATH = /(?:^|\/)(?:dockerfile|containerfile)(?:\.[\w.-]+)?$|\.dockerfile$/;
const COMPOSE_PATH = /(?:^|\/)(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$/;
const DAEMON_PATH = /\.(?:ya?ml|sh|bash|service|conf|json|tf)$|(?:^|\/)(?:dockerfile|containerfile)(?:\.[\w.-]+)?$|\.dockerfile$/;

/** Does a port spec ("22", "20-30", "*", "0-65535") include one of `ports`? */
function portSpecCovers(spec: string, ports: number[]): boolean {
  const s = spec.trim();
  if (s === '*' || s === '') return true;
  const m = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(s);
  if (!m) return false;
  const lo = Number(m[1]);
  const hi = m[2] ? Number(m[2]) : lo;
  return ports.some((p) => lo <= p && p <= hi);
}

/** Quoted strings of an HCL list attribute (`name = ["a", "b"]`), or null when the attribute is absent. */
function hclList(body: string, name: string): string[] | null {
  const m = new RegExp(`\\b${name}\\s*=\\s*\\[([^\\]]*)\\]`).exec(body);
  if (!m) return null;
  return [...m[1].matchAll(/"([^"]*)"/g)].map((x) => x[1]);
}

/** Kubernetes YAML documents (split on `---`) as [startLine, endLineExclusive] ranges. */
function yamlDocs(L: string[]): [number, number][] {
  const docs: [number, number][] = [];
  let start = 0;
  L.forEach((l, i) => {
    if (/^---\s*$/.test(l)) {
      docs.push([start, i]);
      start = i + 1;
    }
  });
  docs.push([start, L.length]);
  return docs;
}

/** YAML list value for `key` at line i: flow `[a, b]` on the same line or block `- a` items below. */
function yamlListAt(L: string[], i: number, key: string): string[] | null {
  const m = new RegExp(`^\\s*(?:-\\s+)?${key}\\s*:\\s*(.*)$`).exec(L[i]);
  if (!m) return null;
  const rest = m[1].replace(/\s+#.*$/, '').trim();
  const unq = (v: string) => v.trim().replace(/^["']|["']$/g, '');
  if (rest.startsWith('[')) return rest.replace(/^\[|\]$/g, '').split(',').map(unq).filter(Boolean);
  if (rest) return [unq(rest)];
  const out: string[] = [];
  for (let j = i + 1; j < L.length; j++) {
    const item = /^\s*-\s+(.+?)\s*$/.exec(L[j]);
    if (!item || /^[\w.-]+\s*:/.test(item[1])) break;
    out.push(unq(item[1]));
  }
  return out;
}

export function evaluateCloudIacV2Rules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.toLowerCase().replace(/\\/g, '/');
  if (/(?:^|\/)node_modules\//.test(path)) return { findings, logs };

  const isTf = /\.tf$/.test(path);
  const isYaml = isYamlPath(path);
  const isCompose = COMPOSE_PATH.test(path);
  const isDockerfile = DOCKERFILE_PATH.test(path);
  if (!isTf && !isYaml && !isDockerfile && !DAEMON_PATH.test(path)) return { findings, logs };

  const src = stripHashComments(cleanContent);
  const L = src.split('\n');
  const hits: Hit[] = [];
  const find = (re: RegExp, from = 0, to = L.length): number => {
    for (let i = from; i < to; i++) if (re.test(L[i])) return i;
    return -1;
  };

  // ------------------------------------------------------------------ Terraform
  if (isTf) {
    // CLOUD-V2-01: storage encryption explicitly switched off (Checkov CKV_AWS_16/42/74/96/142, Trivy AVD-AWS-0080)
    const enc = [
      attrLineIn(src, hclBlocks(src, tfResource('aws_db_instance|aws_rds_cluster|aws_docdb_cluster|aws_neptune_cluster')), /\bstorage_encrypted\s*=\s*"?false"?/),
      attrLineIn(src, hclBlocks(src, tfResource('aws_efs_file_system|aws_redshift_cluster|aws_instance|aws_launch_template')), /\bencrypted\s*=\s*"?false"?/),
    ].find((l) => l !== -1);
    if (enc !== undefined) {
      hits.push({
        ruleId: 28501, code: 'CLOUD-V2-01', severity: 'MEDIUM', lineIdx: enc,
        title: 'Database or File Storage Encryption Explicitly Disabled',
        why: 'The resource sets its at-rest encryption flag to false, so snapshots, replicas and the underlying volumes are stored unencrypted and cannot be encrypted later without a rebuild.',
        fix: 'Set storage_encrypted = true (RDS/Aurora/DocumentDB/Neptune) or encrypted = true (EFS/Redshift/EC2 block devices), optionally with a customer-managed kms_key_id.'
      });
    }

    // CLOUD-V2-02: Redshift / DMS / Amazon MQ reachable from the internet (CKV_AWS_87, CKV_AWS_89, CKV_AWS_69)
    const pub = attrLineIn(src, hclBlocks(src, tfResource('aws_redshift_cluster|aws_dms_replication_instance|aws_mq_broker')), /\bpublicly_accessible\s*=\s*true\b/);
    if (pub !== -1) {
      hits.push({
        ruleId: 28502, code: 'CLOUD-V2-02', severity: 'HIGH', lineIdx: pub,
        title: 'Managed Data Service Publicly Accessible (publicly_accessible = true)',
        why: 'publicly_accessible = true gives the data warehouse / replication instance / message broker a public endpoint, exposing it to internet-wide credential stuffing and exploit scanning.',
        fix: 'Set publicly_accessible = false and reach the service from inside the VPC (private subnets, VPN, bastion or PrivateLink).'
      });
    }

    // CLOUD-V2-03: IAM role trust policy lets any AWS principal assume the role (Trivy AVD-AWS-0057 family, KICS)
    const trust = (() => {
      const l = attrLineIn(src, hclBlocks(src, tfResource('aws_iam_role')), PRINCIPAL_STAR, (b) => UNSCOPED_GRANT_EXEMPT.test(b.body));
      if (l !== -1) return l;
      for (const doc of hclBlocks(src, /data\s+"aws_iam_policy_document"\s+"([\w-]+)"/)) {
        for (const st of hclBlocks(src, /\bstatement/, doc)) {
          if (!/sts:AssumeRole/.test(st.body) || /\bcondition\s*\{/.test(st.body) || /\beffect\s*=\s*"Deny"/.test(st.body)) continue;
          const anyone = hclBlocks(src, /\bprincipals/, st).find((p) => /\btype\s*=\s*"(?:AWS|\*)"/.test(p.body) && (hclList(p.body, 'identifiers') ?? []).includes('*'));
          if (anyone) return hclLine(src, anyone, /\bidentifiers\s*=/);
        }
      }
      return -1;
    })();
    if (trust !== -1) {
      hits.push({
        ruleId: 28503, code: 'CLOUD-V2-03', severity: 'CRITICAL', lineIdx: trust,
        title: 'IAM Role Trust Policy Allows Any AWS Principal to Assume the Role',
        why: 'A trust policy with Principal "*" (or AWS = "*") and no Condition lets any identity in any AWS account call sts:AssumeRole and receive this role\'s permissions.',
        fix: 'Name the exact trusted principal (account root ARN, role ARN or service principal) and add conditions such as sts:ExternalId or aws:PrincipalOrgID.'
      });
    }

    // CLOUD-V2-04: Lambda resource permission for principal "*" without a source restriction
    const lam = attrLineIn(src, hclBlocks(src, tfResource('aws_lambda_permission')), /\bprincipal\s*=\s*"\*"/, (b) => /\b(?:source_arn|source_account|principal_org_id|function_url_auth_type)\s*=/.test(b.body));
    if (lam !== -1) {
      hits.push({
        ruleId: 28504, code: 'CLOUD-V2-04', severity: 'HIGH', lineIdx: lam,
        title: 'Lambda Permission Lets Any AWS Account Invoke the Function',
        why: 'aws_lambda_permission with principal = "*" and no source_arn / source_account / principal_org_id lets any AWS account invoke the function directly, bypassing the intended trigger.',
        fix: 'Grant the specific service principal (e.g. "s3.amazonaws.com", "apigateway.amazonaws.com") and pin it with source_arn and source_account.'
      });
    }

    // CLOUD-V2-05: resource policies (SQS, SNS, ECR, Secrets Manager, OpenSearch) open to everyone without a Condition
    const rp = attrLineIn(
      src,
      hclBlocks(src, tfResource('aws_sqs_queue_policy|aws_sns_topic_policy|aws_ecr_repository_policy|aws_secretsmanager_secret_policy|aws_opensearch_domain_policy|aws_elasticsearch_domain_policy|aws_sqs_queue|aws_sns_topic|aws_opensearch_domain|aws_elasticsearch_domain')),
      PRINCIPAL_STAR,
      (b) => UNSCOPED_GRANT_EXEMPT.test(b.body),
    );
    if (rp !== -1) {
      hits.push({
        ruleId: 28505, code: 'CLOUD-V2-05', severity: 'HIGH', lineIdx: rp,
        title: 'Resource Policy Grants Access to Everyone (Principal "*") Without a Condition',
        why: 'An Allow statement for Principal "*" with no Condition on a queue, topic, image repository, secret or search domain lets any AWS account (or anonymous caller for OpenSearch) read or write it.',
        fix: 'Replace "*" with the specific account/role/service principals, or add a Condition (aws:SourceArn, aws:SourceAccount, aws:PrincipalOrgID, aws:SourceIp).'
      });
    }

    // CLOUD-V2-06: GCP firewall allowing SSH/RDP from 0.0.0.0/0 (CKV_GCP_2, CKV_GCP_3, Trivy AVD-GCP-0027)
    const gfw = (() => {
      for (const fw of hclBlocks(src, tfResource('google_compute_firewall'))) {
        if (/\bdirection\s*=\s*"EGRESS"/.test(fw.body) || /\bdisabled\s*=\s*true\b/.test(fw.body)) continue;
        const ranges = hclList(fw.body, 'source_ranges') ?? [];
        if (!ranges.some((r) => r === '0.0.0.0/0' || r === '::/0')) continue;
        const open = hclBlocks(src, /\ballow/, fw).some((a) => {
          const proto = /\bprotocol\s*=\s*"(\w+)"/.exec(a.body)?.[1].toLowerCase();
          if (proto === 'all') return true;
          if (proto !== 'tcp') return false;
          const ports = hclList(a.body, 'ports');
          return ports === null || ports.some((p) => portSpecCovers(p, [22, 3389]));
        });
        if (open) return hclLine(src, fw, /\bsource_ranges\s*=/);
      }
      return -1;
    })();
    if (gfw !== -1) {
      hits.push({
        ruleId: 28506, code: 'CLOUD-V2-06', severity: 'HIGH', lineIdx: gfw,
        title: 'GCP Firewall Allows SSH or RDP From the Internet (0.0.0.0/0)',
        why: 'An ingress google_compute_firewall rule with source_ranges 0.0.0.0/0 allows TCP 22/3389 (or all ports) from anywhere, exposing instances to brute force and remote exploits.',
        fix: 'Restrict source_ranges to known admin CIDRs, or use IAP TCP forwarding (35.235.240.0/20) / OS Login instead of public SSH.'
      });
    }

    // CLOUD-V2-07: Azure NSG rule allowing SSH/RDP from the internet (CKV_AZURE_9, CKV_AZURE_10)
    const nsg = (() => {
      const rules: HclBlock[] = [...hclBlocks(src, tfResource('azurerm_network_security_rule'))];
      for (const g of hclBlocks(src, tfResource('azurerm_network_security_group'))) rules.push(...hclBlocks(src, /\bsecurity_rule/, g));
      const world = /^(?:\*|0\.0\.0\.0(?:\/0)?|Internet|Any)$/i;
      for (const r of rules) {
        if (!/\bdirection\s*=\s*"Inbound"/i.test(r.body) || !/\baccess\s*=\s*"Allow"/i.test(r.body)) continue;
        const single = /\bsource_address_prefix\s*=\s*"([^"]*)"/.exec(r.body)?.[1];
        const sources = single !== undefined ? [single] : hclList(r.body, 'source_address_prefixes') ?? [];
        if (!sources.some((s) => world.test(s))) continue;
        const port = /\bdestination_port_range\s*=\s*"([^"]*)"/.exec(r.body)?.[1];
        const ports = port !== undefined ? [port] : hclList(r.body, 'destination_port_ranges') ?? [];
        if (ports.some((p) => portSpecCovers(p, [22, 3389]))) return hclLine(src, r, /\bsource_address_prefix(?:es)?\s*=/);
      }
      return -1;
    })();
    if (nsg !== -1) {
      hits.push({
        ruleId: 28507, code: 'CLOUD-V2-07', severity: 'HIGH', lineIdx: nsg,
        title: 'Azure NSG Rule Allows SSH or RDP From the Internet',
        why: 'An inbound Allow rule from source "*" / "Internet" / 0.0.0.0/0 to port 22 or 3389 exposes VM management ports to internet-wide brute force.',
        fix: 'Limit source_address_prefix to known admin ranges, or use Azure Bastion / Just-in-Time VM access instead of public management ports.'
      });
    }

    // CLOUD-V2-08: Cloud SQL authorized network 0.0.0.0/0 (CKV_GCP_11, Trivy AVD-GCP-0017)
    const sqlNet = (() => {
      for (const inst of hclBlocks(src, tfResource('google_sql_database_instance'))) {
        const net = hclBlocks(src, /\bauthorized_networks/, inst).find((n) => /\bvalue\s*=\s*"0\.0\.0\.0\/0"/.test(n.body));
        if (net) return hclLine(src, net, /\bvalue\s*=/);
      }
      return -1;
    })();
    if (sqlNet !== -1) {
      hits.push({
        ruleId: 28508, code: 'CLOUD-V2-08', severity: 'HIGH', lineIdx: sqlNet,
        title: 'Cloud SQL Instance Authorizes Connections From Any IP (0.0.0.0/0)',
        why: 'An authorized_networks entry of 0.0.0.0/0 lets every internet host reach the database port, leaving only the database password between attackers and the data.',
        fix: 'Remove the 0.0.0.0/0 entry; use private IP (ipv4_enabled = false + private_network) or the Cloud SQL Auth Proxy with IAM authentication.'
      });
    }

    // CLOUD-V2-09: Azure database firewall rule covering the whole IPv4 space (CKV_AZURE_11)
    const azFw = attrLineIn(
      src,
      hclBlocks(src, tfResource('azurerm_(?:mssql|sql|postgresql|postgresql_flexible_server|mysql|mysql_flexible_server|mariadb|synapse|redis)_firewall_rule')),
      /\bend_ip_address\s*=\s*"255\.255\.255\.255"/,
      (b) => !/\bstart_ip_address\s*=\s*"0\.0\.0\.0"/.test(b.body),
    );
    if (azFw !== -1) {
      hits.push({
        ruleId: 28509, code: 'CLOUD-V2-09', severity: 'HIGH', lineIdx: azFw,
        title: 'Azure Database Firewall Rule Allows All IPv4 Addresses (0.0.0.0 - 255.255.255.255)',
        why: 'A firewall rule from 0.0.0.0 to 255.255.255.255 opens the database server to the entire internet.',
        fix: 'Allow only specific client ranges, use private endpoints / VNet integration, or the 0.0.0.0-0.0.0.0 "Azure services" rule when that is what is needed.'
      });
    }

    // CLOUD-V2-10: Azure blob container with anonymous list access (CKV_AZURE_34, Trivy AVD-AZU-0007)
    const cont = attrLineIn(src, hclBlocks(src, tfResource('azurerm_storage_container')), /\bcontainer_access_type\s*=\s*"container"/);
    if (cont !== -1) {
      hits.push({
        ruleId: 28510, code: 'CLOUD-V2-10', severity: 'MEDIUM', lineIdx: cont,
        title: 'Azure Storage Container Allows Anonymous Listing (container_access_type = "container")',
        why: 'Access type "container" lets anyone enumerate and download every blob in the container without credentials, including files never meant to be linked publicly.',
        fix: 'Use container_access_type = "private" and serve files with SAS tokens, or "blob" when individual public files are intended.'
      });
    }

    // CLOUD-V2-11: GCP IAM grants to allUsers / allAuthenticatedUsers (CKV_GCP_28, CKV_GCP_49, Trivy AVD-GCP-0001/0007)
    const gIam = (() => {
      const everyone = /"(?:allUsers|allAuthenticatedUsers)"/;
      const l1 = attrLineIn(src, hclBlocks(src, tfResource('google_(?:project|folder|organization|service_account|secret_manager_secret|kms_crypto_key|kms_key_ring)_iam_(?:member|binding)')), everyone);
      if (l1 !== -1) return l1;
      const l2 = attrLineIn(src, hclBlocks(src, tfResource('google_storage_bucket_iam_(?:member|binding)')), everyone,
        (b) => /\brole\s*=\s*"roles\/storage\.(?:objectViewer|legacyObjectReader|legacyBucketReader)"/.test(b.body));
      if (l2 !== -1) return l2;
      return attrLineIn(src, hclBlocks(src, tfResource('google_storage_bucket_acl|google_storage_default_object_acl')), /"(?:WRITER|OWNER):(?:allUsers|allAuthenticatedUsers)"/);
    })();
    if (gIam !== -1) {
      hits.push({
        ruleId: 28511, code: 'CLOUD-V2-11', severity: 'CRITICAL', lineIdx: gIam,
        title: 'GCP IAM Grants Privileged Access to allUsers / allAuthenticatedUsers',
        why: 'allUsers is anyone on the internet and allAuthenticatedUsers is any Google account; granting them project, service account, secret, KMS or bucket write/admin roles hands that access to the world.',
        fix: 'Grant the role to specific users, groups or service accounts. For public static content use only roles/storage.objectViewer on a dedicated bucket.'
      });
    }

    // CLOUD-V2-12: minimum TLS 1.0 / 1.1 on Azure / GCP resources (CKV_AZURE_44/52/154, Trivy AVD-AZU-0011, AVD-GCP-0039)
    const tls = find(/\b(?:min_tls_version|minimum_tls_version|ssl_minimal_tls_version_enforced)\s*=\s*"(?:TLS_?1_[01]|TLS1\.[01]|1\.[01])"/);
    if (tls !== -1) {
      hits.push({
        ruleId: 28512, code: 'CLOUD-V2-12', severity: 'MEDIUM', lineIdx: tls,
        title: 'Cloud Resource Accepts Deprecated TLS 1.0 / 1.1 Connections',
        why: 'TLS 1.0 and 1.1 are deprecated (RFC 8996); allowing them enables downgrade attacks and weak cipher suites against the storage account, database, cache or load balancer.',
        fix: 'Set the minimum TLS version to 1.2 (e.g. min_tls_version = "TLS1_2", minimum_tls_version = "1.2", min_tls_version = "TLS_1_2").'
      });
    }

    // CLOUD-V2-13: managed Kubernetes without RBAC (GKE legacy ABAC CKV_GCP_7, AKS RBAC disabled CKV_AZURE_5)
    const rbacOff = [
      attrLineIn(src, hclBlocks(src, tfResource('google_container_cluster')), /\benable_legacy_abac\s*=\s*true\b/),
      attrLineIn(src, hclBlocks(src, tfResource('azurerm_kubernetes_cluster')), /\brole_based_access_control_enabled\s*=\s*false\b|\brole_based_access_control\s*\{[^}]*\benabled\s*=\s*false\b/),
    ].find((l) => l !== -1);
    if (rbacOff !== undefined) {
      hits.push({
        ruleId: 28513, code: 'CLOUD-V2-13', severity: 'HIGH', lineIdx: rbacOff,
        title: 'Managed Kubernetes Cluster With RBAC Disabled or Legacy ABAC Enabled',
        why: 'Legacy ABAC (GKE) or disabled RBAC (AKS) gives node and pod service accounts broad, unauditable API permissions, so one compromised pod can control the cluster.',
        fix: 'Set enable_legacy_abac = false on GKE and role_based_access_control_enabled = true on AKS, then grant least-privilege Roles via RoleBindings.'
      });
    }
  }

  // ------------------------------------------------------------------ Kubernetes YAML
  const isK8s = isYaml && !isCompose && /^\s*apiVersion\s*:/m.test(src) && /^\s*kind\s*:/m.test(src);
  if (isK8s) {
    const docs = yamlDocs(L);
    const kindOf = (from: number, to: number) => /^kind\s*:\s*["']?(\w+)/.exec(L.slice(from, to).find((l) => /^kind\s*:/.test(l)) ?? '')?.[1] ?? '';

    // CLOUD-V2-14: RBAC rule granting every verb on every resource (kube-linter wildcard-in-rules, CKV_K8S_49)
    const wild = (() => {
      for (const [a, b] of docs) {
        if (!/^(?:Cluster)?Role$/.test(kindOf(a, b))) continue;
        const starts: number[] = [];
        for (let i = a; i < b; i++) if (/^\s*-\s+(?:apiGroups|resources|verbs|resourceNames|nonResourceURLs)\s*:/.test(L[i])) starts.push(i);
        for (let k = 0; k < starts.length; k++) {
          const end = k + 1 < starts.length ? starts[k + 1] : b;
          let verbs: string[] | null = null;
          let res: string[] | null = null;
          let resLine = -1;
          for (let i = starts[k]; i < end; i++) {
            verbs = verbs ?? yamlListAt(L, i, 'verbs');
            const r = yamlListAt(L, i, 'resources');
            if (r) { res = r; resLine = i; }
          }
          if (verbs?.includes('*') && res?.includes('*')) return resLine;
        }
      }
      return -1;
    })();
    if (wild !== -1) {
      hits.push({
        ruleId: 28514, code: 'CLOUD-V2-14', severity: 'HIGH', lineIdx: wild,
        title: 'Kubernetes RBAC Role Grants All Verbs on All Resources (*)',
        why: 'resources: ["*"] with verbs: ["*"] is equivalent to admin over the API group: the subject can read every Secret, create pods on any node and escalate to cluster-admin.',
        fix: 'List the exact resources and verbs the workload needs (e.g. resources: ["configmaps"], verbs: ["get", "list", "watch"]).'
      });
    }

    // CLOUD-V2-15 / 16: bindings to anonymous users, and cluster-admin bound to a service account
    let anon = -1;
    let saAdmin = -1;
    for (const [a, b] of docs) {
      if (!/^(?:Cluster)?RoleBinding$/.test(kindOf(a, b))) continue;
      const refIdx = find(/^\s*roleRef\s*:/, a, b);
      const roleNameIdx = refIdx === -1 ? -1 : find(/^\s*name\s*:/, refIdx + 1, Math.min(b, refIdx + 5));
      const role = roleNameIdx === -1 ? '' : (/name\s*:\s*["']?([\w:.-]+)/.exec(L[roleNameIdx])?.[1] ?? '');
      const subj = find(/^\s*subjects\s*:/, a, b);
      if (subj === -1) continue;
      const subjEnd = refIdx > subj ? refIdx : b;
      const anonIdx = find(/^\s*(?:-\s+)?name\s*:\s*["']?system:(?:anonymous|unauthenticated)["']?\s*$/, subj, subjEnd);
      const broadIdx = /^(?:cluster-admin|admin|edit)$/.test(role) ? find(/^\s*(?:-\s+)?name\s*:\s*["']?system:(?:authenticated|serviceaccounts)["']?\s*$/, subj, subjEnd) : -1;
      if (anon === -1 && (anonIdx !== -1 || broadIdx !== -1)) anon = anonIdx !== -1 ? anonIdx : broadIdx;
      if (saAdmin === -1 && role === 'cluster-admin' && find(/^\s*(?:-\s+)?kind\s*:\s*["']?ServiceAccount\b/, subj, subjEnd) !== -1) saAdmin = roleNameIdx;
    }
    if (anon !== -1) {
      hits.push({
        ruleId: 28515, code: 'CLOUD-V2-15', severity: 'CRITICAL', lineIdx: anon,
        title: 'Kubernetes RoleBinding Grants Access to Anonymous or All Authenticated Users',
        why: 'Binding a role to system:anonymous / system:unauthenticated, or binding admin roles to system:authenticated / system:serviceaccounts, gives that access to anyone who can reach the API server or any pod in the cluster.',
        fix: 'Bind roles only to named users, groups or specific ServiceAccounts, and keep anonymous auth limited to the default health/discovery endpoints.'
      });
    }
    if (saAdmin !== -1) {
      hits.push({
        ruleId: 28516, code: 'CLOUD-V2-16', severity: 'HIGH', lineIdx: saAdmin,
        title: 'cluster-admin Bound to a Workload ServiceAccount',
        why: 'Any pod running as this ServiceAccount gets an auto-mounted token with full control of the cluster; a single RCE in that workload becomes a cluster takeover (CIS 5.1.1).',
        fix: 'Create a Role/ClusterRole with only the verbs and resources the workload needs and bind that instead of cluster-admin.'
      });
    }

    // CLOUD-V2-17: allowPrivilegeEscalation explicitly true (CKV_K8S_20, Pod Security Standards restricted)
    const ape = find(/^\s*allowPrivilegeEscalation\s*:\s*true\b/);
    if (ape !== -1) {
      hits.push({
        ruleId: 28517, code: 'CLOUD-V2-17', severity: 'MEDIUM', lineIdx: ape,
        title: 'Container Explicitly Allows Privilege Escalation (allowPrivilegeEscalation: true)',
        why: 'With no_new_privs off, setuid binaries and file capabilities inside the image can raise the process to root, turning an app compromise into root in the container.',
        fix: 'Set allowPrivilegeEscalation: false in the container securityContext (required by the restricted Pod Security Standard).'
      });
    }

    // CLOUD-V2-19: plaintext credential in a container env entry (kube-linter env-var-secret, CKV_K8S_35)
    const envSecret = (() => {
      for (let i = 0; i < L.length; i++) {
        if (!/^\s*-\s*name\s*:\s*["']?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|SECRET_KEY|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|TOKEN)["']?\s*$/.test(L[i])) continue;
        for (let j = i + 1; j < Math.min(L.length, i + 4) && !/^\s*-\s/.test(L[j]); j++) {
          const v = /^\s*value\s*:\s*(.*?)\s*$/.exec(L[j]);
          if (!v) continue;
          const val = v[1].replace(/^["']|["']$/g, '');
          if (val.length >= 6 && !/\{\{|\$\(|\$\{/.test(val)) return j;
        }
      }
      return -1;
    })();
    if (envSecret !== -1) {
      hits.push({
        ruleId: 28519, code: 'CLOUD-V2-19', severity: 'MEDIUM', lineIdx: envSecret,
        title: 'Plaintext Credential in Kubernetes Container env Value',
        why: 'The secret is committed to the manifest and visible to anyone with read access to the repo or to the Pod spec (kubectl get pod -o yaml), unlike a Secret reference with RBAC.',
        fix: 'Store the value in a Kubernetes Secret (or External Secrets / Sealed Secrets) and reference it with valueFrom.secretKeyRef.'
      });
    }

    // CLOUD-V2-25: kubelet / API server authorization disabled (CIS Kubernetes 1.2.6, 4.2.1, 4.2.2)
    const kubelet = (() => {
      for (const [a, b] of docs) {
        if (kindOf(a, b) !== 'KubeletConfiguration') continue;
        const anonAt = find(/^\s*anonymous\s*:\s*$/, a, b);
        const en = anonAt === -1 ? -1 : find(/^\s*enabled\s*:\s*true\b/, anonAt + 1, Math.min(b, anonAt + 3));
        if (en !== -1) return en;
        const authz = find(/^\s*authorization\s*:\s*$/, a, b);
        const mode = authz === -1 ? -1 : find(/^\s*mode\s*:\s*["']?AlwaysAllow\b/, authz + 1, Math.min(b, authz + 4));
        if (mode !== -1) return mode;
      }
      return -1;
    })();
    if (kubelet !== -1) {
      hits.push({
        ruleId: 28525, code: 'CLOUD-V2-25', severity: 'CRITICAL', lineIdx: kubelet,
        title: 'Kubernetes Control Plane or Kubelet Authorization Disabled',
        why: 'Anonymous kubelet access or the AlwaysAllow authorizer lets any network peer exec into pods, read logs/secrets or call every API without credentials.',
        fix: 'Set authentication.anonymous.enabled: false and authorization.mode: Webhook on the kubelet; use --authorization-mode=Node,RBAC on the API server.'
      });
    }
  }

  // API server / kubeadm AlwaysAllow flag in any manifest or script
  if (!hits.some((h) => h.ruleId === 28525) && (isYaml || DAEMON_PATH.test(path))) {
    const flag = find(/\bauthorization-mode["']?\s*[:=\s]\s*["']?[\w,]*\bAlwaysAllow\b/);
    if (flag !== -1) {
      hits.push({
        ruleId: 28525, code: 'CLOUD-V2-25', severity: 'CRITICAL', lineIdx: flag,
        title: 'Kubernetes Control Plane or Kubelet Authorization Disabled',
        why: 'The AlwaysAllow authorizer approves every API request, so any authenticated (or anonymous) caller can read Secrets and create privileged pods.',
        fix: 'Use --authorization-mode=Node,RBAC on the API server and Webhook on the kubelet.'
      });
    }
  }

  // CLOUD-V2-18: seccomp / AppArmor / SELinux confinement disabled (K8s PSS baseline, CIS Docker 5.21)
  if (isYaml) {
    const unconfined = (() => {
      if (isCompose) return find(/\b(?:seccomp|apparmor)[:=]["']?unconfined\b|\blabel[:=]["']?disable\b/);
      if (!isK8s) return -1;
      const ann = find(/(?:seccomp\.security\.alpha\.kubernetes\.io\/pod|container\.(?:seccomp|apparmor)\.security\.(?:alpha|beta)\.kubernetes\.io\/[\w.-]+)["']?\s*:\s*["']?unconfined\b/);
      if (ann !== -1) return ann;
      for (let i = 0; i < L.length; i++) {
        if (/^\s*type\s*:\s*["']?Unconfined\b/.test(L[i]) && L.slice(Math.max(0, i - 2), i).some((p) => /^\s*(?:seccompProfile|appArmorProfile)\s*:/.test(p))) return i;
      }
      return -1;
    })();
    if (unconfined !== -1) {
      hits.push({
        ruleId: 28518, code: 'CLOUD-V2-18', severity: 'MEDIUM', lineIdx: unconfined,
        title: 'Container Seccomp / AppArmor / SELinux Confinement Disabled',
        why: 'Running unconfined removes the syscall filter and MAC profile that block common container-escape primitives (mount, keyctl, unshare, ptrace).',
        fix: 'Remove the unconfined setting and use RuntimeDefault (seccompProfile.type: RuntimeDefault) or a custom profile that allows only the needed syscalls.'
      });
    }
  }

  // ------------------------------------------------------------------ Dockerfile
  if (isDockerfile) {
    // Logical RUN instructions (backslash continuations joined)
    const fetchExec = (() => {
      for (let i = 0; i < L.length; i++) {
        if (!/^\s*RUN\s/i.test(L[i])) continue;
        let end = i;
        while (end < L.length - 1 && /\\\s*$/.test(L[end])) end++;
        const segments = L.slice(i, end + 1).join(' ').split(/&&|;|\|\|/);
        for (const seg of segments) {
          if (!/\b(?:curl|wget)\b/.test(seg) || !/\|\s*(?:sudo\s+)?(?:\/(?:usr\/)?bin\/)?(?:ba|z|da|k)?sh\b|\|\s*(?:sudo\s+)?python3?\b/.test(seg)) continue;
          const insecure = /\bhttp:\/\/(?!localhost\b|127\.|0\.0\.0\.0|\[::1\])/.test(seg) || /\bcurl\b[^|]*\s(?:-[a-zA-Z]*k[a-zA-Z]*|--insecure)\b/.test(seg) || /--no-check-certificate\b/.test(seg);
          if (!insecure) continue;
          for (let k = i; k <= end; k++) if (/\b(?:curl|wget)\b/.test(L[k])) return k;
          return i;
        }
        i = end;
      }
      return -1;
    })();
    if (fetchExec !== -1) {
      hits.push({
        ruleId: 28520, code: 'CLOUD-V2-20', severity: 'HIGH', lineIdx: fetchExec,
        title: 'Dockerfile Pipes a Script Fetched Without TLS Verification Into a Shell',
        why: 'The script is downloaded over plain HTTP (or with certificate checks disabled) and executed immediately, so anyone on the network path can inject commands into the image build.',
        fix: 'Download over HTTPS with certificate verification, pin and verify a checksum (sha256sum -c) or signature, then execute the verified file.'
      });
    }

    // CLOUD-V2-21: ADD from a plain-HTTP URL (CIS Docker 4.9, hadolint DL3020 rationale)
    const addHttp = find(/^\s*ADD\s+(?:--[\w-]+(?:=\S+)?\s+)*["']?http:\/\/(?!localhost\b|127\.)/i);
    if (addHttp !== -1) {
      hits.push({
        ruleId: 28521, code: 'CLOUD-V2-21', severity: 'MEDIUM', lineIdx: addHttp,
        title: 'Dockerfile ADD Downloads a Build Input Over Plain HTTP',
        why: 'ADD fetches the file over unencrypted HTTP without integrity checking, so a network attacker can swap the artifact baked into the image.',
        fix: 'Fetch over HTTPS and pin the content: ADD --checksum=sha256:<digest> https://..., or download with curl and verify with sha256sum -c.'
      });
    }
  }

  // ------------------------------------------------------------------ docker-compose
  if (isCompose) {
    // CLOUD-V2-22: pid host namespace (CIS Docker 5.15). ipc: host is left out: Playwright documents it for Chromium in Docker
    const pidHost = find(/^\s*pid\s*:\s*["']?host["']?\s*$/);
    if (pidHost !== -1) {
      hits.push({
        ruleId: 28522, code: 'CLOUD-V2-22', severity: 'HIGH', lineIdx: pidHost,
        title: 'Compose Service Shares the Host PID Namespace',
        why: 'pid: host lets the container see and signal every host process (and ptrace them with matching capabilities).',
        fix: 'Remove pid: host; share namespaces only between cooperating containers (pid: "service:<name>") when required.'
      });
    }

    // CLOUD-V2-23: network_mode host (CIS Docker 5.9)
    const netHost = find(/^\s*network_mode\s*:\s*["']?host["']?\s*$/);
    if (netHost !== -1) {
      hits.push({
        ruleId: 28523, code: 'CLOUD-V2-23', severity: 'MEDIUM', lineIdx: netHost,
        title: 'Compose Service Uses the Host Network Stack (network_mode: host)',
        why: 'The container binds directly on host interfaces, bypassing Docker network isolation and published-port control, and can reach host-only services on localhost.',
        fix: 'Use the default bridge or a user-defined network and publish only the required ports (bind to 127.0.0.1 for local-only services).'
      });
    }
  }

  // CLOUD-V2-24: Docker Engine API exposed on unauthenticated TCP 2375 (CIS Docker 2.6)
  if (isCompose || isDockerfile || DAEMON_PATH.test(path)) {
    const api = (() => {
      for (let i = 0; i < L.length; i++) {
        const l = L[i];
        if (/--tlsverify\b/.test(l)) continue;
        if (/(?:-H|--host)[=\s]+["']?tcp:\/\/(?:0\.0\.0\.0)?:2375\b/.test(l) || /"tcp:\/\/0\.0\.0\.0:2375"/.test(l)) return i;
        if (isCompose && /^\s*-\s*["']?(?:0\.0\.0\.0:)?2375:2375(?:\/tcp)?["']?\s*$/.test(l)) return i;
      }
      return -1;
    })();
    if (api !== -1) {
      hits.push({
        ruleId: 28524, code: 'CLOUD-V2-24', severity: 'CRITICAL', lineIdx: api,
        title: 'Docker Engine API Exposed on Unauthenticated TCP Port 2375',
        why: 'The Docker API on tcp/2375 has no authentication or TLS; anyone who reaches it can start a privileged container that mounts the host filesystem (full host takeover).',
        fix: 'Use the local unix socket, or expose the API only on 2376 with --tlsverify and client certificates, bound to a private interface.'
      });
    }
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `cloudv2${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: 'Cloud Misconfiguration',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [CLOUD V2] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
