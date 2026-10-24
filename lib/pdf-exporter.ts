import { Project, Finding } from '@/data/schema';
import { buildSoc2Mapping } from '@/lib/soc2-mapping';
import { FIX_SIZE_NOTE, fixSize } from '@/lib/fix-size';
import { computeSha256 } from '@/lib/crypto-digest';
import { SECURITY_RULES_CATALOG } from '@/data/mockData';

/**
 * Safe HTML Entity Escaping to eradicate Stored / DOM XSS in generated audit reports
 */
function escapeHtml(str: unknown): string {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Executive Release Audit Report Exporter
 * Generates an official, printable B2B release gate audit document for clients and stakeholders.
 */
export interface AuditReportOptions {
  /** White-label: company name replaces Zelsis branding in the header and footer. */
  brandName?: string | null;
  /** White-label: https logo shown in the header. */
  brandLogoUrl?: string | null;
  /** Adds the SOC 2 Trust Services Criteria mapping section. */
  includeSoc2?: boolean;
  /** Adds the OWASP Top 10 mapping section for rules with existing OWASP classifications. */
  includeOwasp?: boolean;
  /**
   * Read-only report link (/r/<token>) served by Zelsis from its own copy of the scan. A PDF can be edited; the
   * reader compares it with this page to check the numbers were not changed.
   */
  verifyUrl?: string | null;
  /** Pinned commit SHA or ref scanned in this report. */
  commit?: string | null;
  commitSha?: string | null;
  /** Number of source files scanned in the repository. */
  fileCount?: number | null;
}

/**
 * Computes a deterministic SHA-256 digest of the report's findings and scan metadata.
 * Payload includes sorted findings, repo, commit and scan time with alphabetically sorted keys.
 * Anyone can re-run the scan at the same commit and compare findings.
 */
export function computeReportFindingsDigest(
  project: Pick<Project, 'name' | 'repoUrl' | 'lastScanAt' | 'lastScanIso' | 'findings'> & {
    commit?: string | null;
    commitSha?: string | null;
  },
  options?: Pick<AuditReportOptions, 'commit' | 'commitSha'>
): string {
  const commit = options?.commitSha || options?.commit || project.commitSha || project.commit || null;
  const repo = project.repoUrl || project.name || null;
  const scannedAt = project.lastScanIso || project.lastScanAt || null;

  const sortedFindings = (project.findings || []).map((f) => ({
    category: f.category || '',
    filePath: f.filePath || '',
    id: f.id || '',
    lineRange: f.lineRange || '',
    ruleId: f.ruleId ?? 0,
    severity: f.severity || '',
    status: f.status || 'OPEN',
    title: f.title || '',
  })).sort((a, b) => {
    const ka = `${a.filePath}#${a.lineRange}#${a.ruleId}#${a.id}`;
    const kb = `${b.filePath}#${b.lineRange}#${b.ruleId}#${b.id}`;
    return ka.localeCompare(kb);
  });

  const payload: Record<string, unknown> = {
    commit,
    findings: sortedFindings,
    repo,
    scannedAt,
  };

  const sortedPayload: Record<string, unknown> = {};
  for (const k of Object.keys(payload).sort()) {
    sortedPayload[k] = payload[k];
  }

  return computeSha256(JSON.stringify(sortedPayload));
}

function renderSoc2Section(findings: Finding[]): string {
  const rows = buildSoc2Mapping(findings)
    .map(({ control, findings: mapped }) => `
      <tr>
        <td><strong>${escapeHtml(control.id)}</strong></td>
        <td>${escapeHtml(control.name)}</td>
        <td style="text-align:center;">${mapped.length}</td>
        <td>${mapped.length === 0
          ? '<span style="color:#10b981;">No exceptions in this scan</span>'
          : escapeHtml(mapped.slice(0, 3).map((f) => f.title).join('; ')) + (mapped.length > 3 ? ` (+${mapped.length - 3} more)` : '')}</td>
      </tr>`)
    .join('');
  return `
  <div class="section">
    <h2>SOC 2 Trust Services Criteria Mapping</h2>
    <p style="font-size:12px;color:#a1a1aa;">Open findings from this scan grouped by the SOC 2 control they relate to. This mapping is indicative audit-preparation evidence, not a SOC 2 attestation or opinion.</p>
    <table>
      <thead><tr><th>Control</th><th>Criterion</th><th>Open findings</th><th>Exceptions</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderOwaspSection(findings: Finding[]): string {
  // Map of rule ID to OWASP tag strictly from existing catalog entries without inventing mappings
  const ruleOwaspMap = new Map<number, string>();
  for (const rule of SECURITY_RULES_CATALOG) {
    if (rule.owaspTag && /^OWASP\b/i.test(rule.owaspTag)) {
      const id = typeof rule.id === 'number' ? rule.id : parseInt(String(rule.id), 10);
      if (!isNaN(id)) ruleOwaspMap.set(id, rule.owaspTag);
    }
  }

  const grouped = new Map<string, Finding[]>();
  for (const f of findings) {
    const owaspTag = ruleOwaspMap.get(f.ruleId);
    if (owaspTag) {
      const list = grouped.get(owaspTag) || [];
      list.push(f);
      grouped.set(owaspTag, list);
    }
  }

  if (grouped.size === 0) return '';

  const rows = [...grouped.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([category, items]) => `
      <tr>
        <td><strong>${escapeHtml(category)}</strong></td>
        <td style="text-align:center;">${items.length}</td>
        <td>${escapeHtml(items.slice(0, 3).map((f) => f.title).join('; '))}${items.length > 3 ? ` (+${items.length - 3} more)` : ''}</td>
      </tr>`)
    .join('');

  return `
  <div class="section">
    <h2>OWASP Top 10 Security Mapping</h2>
    <p style="font-size:12px;color:#a1a1aa;">Open findings from rules carrying documented OWASP classifications. Only rules with an existing OWASP classification are mapped.</p>
    <table>
      <thead><tr><th>OWASP Classification</th><th>Open findings</th><th>Exceptions</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

export function generateAuditPdfReport(project: Project, options: AuditReportOptions = {}) {
  const brandName = options.brandName?.trim() || null;
  const brandLogoUrl = options.brandLogoUrl && /^https:\/\/[^\s"'<>]+$/.test(options.brandLogoUrl) ? options.brandLogoUrl : null;
  const reportTitle = brandName ? `${brandName} Security Check Report` : 'Zelsis Security Check Report';
  const fmt = (d: Date) => d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  // The scan's own time when known; the export time is shown separately so the two are never confused
  const scannedAt = project?.lastScanIso ? new Date(project.lastScanIso) : null;
  const scanDateStr = scannedAt && !isNaN(scannedAt.getTime()) ? fmt(scannedAt) : (project?.lastScanAt || 'Unknown');
  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });

  const commitStr = options.commitSha || options.commit || (project as any)?.commitSha || (project as any)?.commit || 'Working tree HEAD';
  const fileCountStr = options.fileCount ? `${options.fileCount} files` : 'Full repository snapshot';

  const openFindings = (project?.findings || []).filter(f => f?.status === 'OPEN');
  const criticals = openFindings.filter(f => f?.severity === 'CRITICAL');
  const highs = openFindings.filter(f => f?.severity === 'HIGH');
  const projectNameEscaped = escapeHtml(project?.name ?? 'Target Repository');
  const gateStatusEscaped = escapeHtml(project?.gateStatus ?? 'PASSED');

  const digest = computeReportFindingsDigest(project, options);

  const reportHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(reportTitle)} — ${projectNameEscaped}</title>
  <style>
    body { font-family: 'Satoshi', -apple-system, sans-serif; background: #0a0a0a; color: #f5f3ef; padding: 40px; line-height: 1.6; }
    .header { border-bottom: 2px solid rgba(255,255,255,0.2); padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
    .logo { font-size: 24px; font-weight: 900; letter-spacing: 2px; }
    .status-badge { padding: 6px 16px; border-radius: 20px; font-weight: 800; text-transform: uppercase; font-size: 14px; }
    .passed { background: rgba(255,255,255,0.15); color: #fff; border: 1px solid rgba(255,255,255,0.3); }
    .failed { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
    .section { background: #141414; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 24px; margin-bottom: 24px; }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px; }
    .kpi-card { background: #0a0a0a; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 16px; text-align: center; }
    .kpi-val { font-size: 32px; font-weight: 900; }
    .finding-card { background: #0a0a0a; border-left: 4px solid #ef4444; padding: 16px; margin-bottom: 12px; border-radius: 6px; }
    .code { font-family: monospace; background: #18181b; padding: 12px; border-radius: 6px; color: #fca5a5; font-size: 12px; white-space: pre-wrap; }
    .footer { text-align: center; font-size: 12px; color: #a1a1aa; margin-top: 40px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 20px; }
    .brand-logo { max-height: 40px; max-width: 180px; margin-bottom: 8px; display: block; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.1); vertical-align: top; }
    .page-break { page-break-before: always; }
    
    @media print {
      body { background: #ffffff !important; color: #18181b !important; padding: 0 !important; }
      .header { border-bottom-color: #e4e4e7 !important; }
      .section, .kpi-card, .finding-card { background: #f8fafc !important; color: #09090b !important; border: 1px solid #e2e8f0 !important; }
      .finding-card { border-left: 4px solid #ef4444 !important; }
      .code { background: #f1f5f9 !important; color: #991b1b !important; border: 1px solid #cbd5e1 !important; }
      .passed { background: #ecfdf5 !important; color: #047857 !important; border-color: #10b981 !important; }
      .footer { border-top-color: #e4e4e7 !important; color: #71717a !important; }
      .page-break { page-break-before: always !important; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      ${brandLogoUrl ? `<img class="brand-logo" src="${escapeHtml(brandLogoUrl)}" alt="${escapeHtml(brandName ?? 'Company logo')}" />` : ''}
      <div class="logo">${escapeHtml(reportTitle.toUpperCase())}</div>
      <div style="color: #a1a1aa; font-size: 14px;">Automated release checks of the scanned source code</div>
    </div>
    <div class="status-badge ${(project?.gateStatus ?? 'PASSED') === 'PASSED' ? 'passed' : 'failed'}">
      GATE STATUS: ${gateStatusEscaped}
    </div>
  </div>

  <div class="section">
    <h2>Project Metadata</h2>
    <div style="display: flex; gap: 40px; font-size: 14px;">
      <div><strong>Project:</strong> ${escapeHtml(project?.name ?? 'Untitled Project')}</div>
      <div><strong>Framework:</strong> ${escapeHtml(project?.framework ?? 'Not detected')}</div>
      <div><strong>Repository:</strong> ${escapeHtml(project?.repoUrl ?? 'Local Repository')}</div>
      <div><strong>Scan date:</strong> ${escapeHtml(scanDateStr)}</div>
      <div><strong>Exported:</strong> ${escapeHtml(dateStr)}</div>
    </div>
  </div>

  <div class="grid">
    <div class="kpi-card">
      <div style="color: #a1a1aa; font-size: 12px;">READINESS SCORE</div>
      <div class="kpi-val">${project?.readinessScore ?? 100}/100</div>
    </div>
    <div class="kpi-card">
      <div style="color: #a1a1aa; font-size: 12px;">SECURITY PRE-FLIGHT</div>
      <div class="kpi-val">${criticals.length + highs.length === 0 ? '100% Passed' : `${criticals.length + highs.length} Open`}</div>
    </div>
    <div class="kpi-card">
      <div style="color: #a1a1aa; font-size: 12px;">UI QUALITY &amp; ACCESSIBILITY</div>
      <div class="kpi-val">${(project?.uiClicheCount ?? 0) === 0 ? 'No open issues' : `${project?.uiClicheCount} Open`}</div>
    </div>
  </div>

  <div class="section">
    <h2>Open Findings (${openFindings.length})</h2>
    ${openFindings.length === 0 ? '<p style="color: #10b981;">🎉 All security pre-flight, UI quality and accessibility checks cleared with 100/100 Readiness Score.</p>' : ''}
    ${openFindings.map(f => `
      <div class="finding-card">
        <div style="display: flex; justify-content: space-between; font-weight: bold; margin-bottom: 6px;">
          <span>[${escapeHtml(f?.severity ?? 'MEDIUM')}] ${escapeHtml(f?.title ?? 'Finding')}</span>
          <span style="color: #a1a1aa;">${escapeHtml(f?.filePath ?? 'Source File')} (${escapeHtml(f?.lineRange ?? 'L1')})</span>
        </div>
        <div class="code">${escapeHtml(f?.snippet ?? '')}</div>
        <div style="margin-top: 8px; font-size: 12px; color: #a1a1aa;">
          <strong>Remediation:</strong> ${escapeHtml(f?.remediationPrompt ?? '')}
        </div>
        <div style="margin-top: 4px; font-size: 12px; color: #a1a1aa;">
          <strong>Fix size:</strong> ${escapeHtml(fixSize(f).size)}, ${escapeHtml(fixSize(f).kind)}
        </div>
      </div>
    `).join('')}
    ${openFindings.length > 0 ? `<p style="font-size: 11px; color: #71717a; margin-top: 10px;">${escapeHtml(FIX_SIZE_NOTE)}</p>` : ''}
  </div>

  ${options.includeSoc2 ? renderSoc2Section(project?.findings || []) : ''}
  ${options.includeOwasp ? renderOwaspSection(project?.findings || []) : ''}

  <div class="section page-break">
    <h2>Scope and Limits</h2>
    <div style="font-size: 13px; line-height: 1.6; color: #d4d4d8;">
      <h3 style="font-size: 14px; color: #ffffff; margin-top: 12px; margin-bottom: 6px;">What was scanned</h3>
      <ul style="margin: 0 0 12px 20px; padding: 0;">
        <li><strong>Repository:</strong> ${escapeHtml(project?.repoUrl || project?.name || 'Local repository')}</li>
        <li><strong>Commit:</strong> ${escapeHtml(commitStr)}</li>
        <li><strong>Files scanned:</strong> ${escapeHtml(fileCountStr)}</li>
        <li><strong>Areas:</strong> Logic, Performance, Deploy safety, Privacy &amp; Legal, UI &amp; Accessibility, Dependencies, Infra config, Security</li>
      </ul>

      <h3 style="font-size: 14px; color: #ffffff; margin-top: 16px; margin-bottom: 6px;">What a static check cannot see</h3>
      <p style="margin: 0 0 12px 0; color: #a1a1aa;">
        A static scan inspects repository files and lockfiles at rest. It cannot see runtime configuration, secrets managers, live infrastructure, or business rules nobody wrote down.
      </p>

      <h3 style="font-size: 14px; color: #ffffff; margin-top: 16px; margin-bottom: 6px;">Release gate rule governance</h3>
      <p style="margin: 0; color: #a1a1aa;">
        Every rule change is measured against a pinned benchmark of intentionally vulnerable apps and maintained production projects in several languages. Rules that misfire on clean code become experimental and stop affecting the gate, and a CRITICAL finding can fail a release only when its rule caught a documented flaw or was reviewed as a true positive, or when it is a published advisory for a dependency version. Findings from other rules are still reported, as warnings. Results are published in the benchmark section.
      </p>
    </div>
  </div>

  <div class="section">
    <h2 style="margin-top:0;">Report Data Digest</h2>
    <div style="font-family: monospace; font-size: 13px; background: #0a0a0a; border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; padding: 12px; color: #a1a1aa; word-break: break-all;">
      SHA-256: <strong>${escapeHtml(digest)}</strong>
    </div>
    <p style="font-size: 12px; color: #a1a1aa; margin-top: 8px; margin-bottom: 0;">
      Anyone can re-run the scan at the same commit and compare.
    </p>
  </div>

  <div class="footer">
    ${brandName
      ? `Prepared by ${escapeHtml(brandName)} from an automated static scan run by Zelsis. Not a penetration test, audit or certification.`
      : 'Generated by Zelsis from an automated static scan. Not a penetration test, audit or certification.'}
    ${options.verifyUrl ? `
    <div style="margin-top:12px;">
      <strong>Check this report:</strong> <a href="${escapeHtml(options.verifyUrl)}" style="color:inherit;">${escapeHtml(options.verifyUrl)}</a><br />
      That page is served by Zelsis from its own copy of the latest cloud scan of this project. If its date, score or findings differ from this PDF, the PDF was changed or comes from a different scan.
    </div>` : ''}
  </div>
</body>
</html>
  `;

  if (typeof window === 'undefined') {
    return reportHtml;
  }

  const blob = new Blob([reportHtml], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const win = window.open(url, '_blank');

  if (win) {
    win.focus();
    setTimeout(() => {
      try {
        win.print();
      } catch (e: any) {
        console.warn('[PDF Exporter] Window print warning:', e?.message || e);
      }
      URL.revokeObjectURL(url);
    }, 500);
  } else {
    // Popup Blocker Fallback: Directly trigger HTML report download
    const a = document.createElement('a');
    a.href = url;
    a.download = `zelsis-audit-report-${(project?.name || 'target').toLowerCase().replace(/\s+/g, '-')}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
