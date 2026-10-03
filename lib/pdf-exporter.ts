import { Project, Finding } from '@/data/schema';
import { buildSoc2Mapping } from '@/lib/soc2-mapping';

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

export function generateAuditPdfReport(project: Project, options: AuditReportOptions = {}) {
  const brandName = options.brandName?.trim() || null;
  const brandLogoUrl = options.brandLogoUrl && /^https:\/\/[^\s"'<>]+$/.test(options.brandLogoUrl) ? options.brandLogoUrl : null;
  const reportTitle = brandName ? `${brandName} Security Audit Report` : 'Zelsis Release Audit Report';
  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });

  const openFindings = (project?.findings || []).filter(f => f?.status === 'OPEN');
  const criticals = openFindings.filter(f => f?.severity === 'CRITICAL');
  const highs = openFindings.filter(f => f?.severity === 'HIGH');
  const projectNameEscaped = escapeHtml(project?.name ?? 'Target Repository');
  const gateStatusEscaped = escapeHtml(project?.gateStatus ?? 'PASSED');

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
    
    @media print {
      body { background: #ffffff !important; color: #18181b !important; padding: 0 !important; }
      .header { border-bottom-color: #e4e4e7 !important; }
      .section, .kpi-card, .finding-card { background: #f8fafc !important; color: #09090b !important; border: 1px solid #e2e8f0 !important; }
      .finding-card { border-left: 4px solid #ef4444 !important; }
      .code { background: #f1f5f9 !important; color: #991b1b !important; border: 1px solid #cbd5e1 !important; }
      .passed { background: #ecfdf5 !important; color: #047857 !important; border-color: #10b981 !important; }
      .footer { border-top-color: #e4e4e7 !important; color: #71717a !important; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      ${brandLogoUrl ? `<img class="brand-logo" src="${escapeHtml(brandLogoUrl)}" alt="${escapeHtml(brandName ?? 'Company logo')}" />` : ''}
      <div class="logo">${escapeHtml(reportTitle.toUpperCase())}</div>
      <div style="color: #a1a1aa; font-size: 14px;">Release gate audit of the scanned source code</div>
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
      <div><strong>Audit Date:</strong> ${escapeHtml(dateStr)}</div>
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
    <h2>Audit Findings Inventory (${openFindings.length} Open Issues)</h2>
    ${openFindings.length === 0 ? '<p style="color: #10b981;">🎉 All security pre-flight, UI quality and accessibility checks cleared with 100/100 Readiness Score.</p>' : ''}
    ${openFindings.map(f => `
      <div class="finding-card">
        <div style="display: flex; justify-content: space-between; font-weight: bold; margin-bottom: 6px;">
          <span>[${escapeHtml(f?.severity ?? 'MEDIUM')}] ${escapeHtml(f?.title ?? 'Audit Finding')}</span>
          <span style="color: #a1a1aa;">${escapeHtml(f?.filePath ?? 'Source File')} (${escapeHtml(f?.lineRange ?? 'L1')})</span>
        </div>
        <div class="code">${escapeHtml(f?.snippet ?? '')}</div>
        <div style="margin-top: 8px; font-size: 12px; color: #a1a1aa;">
          <strong>Remediation:</strong> ${escapeHtml(f?.remediationPrompt ?? '')}
        </div>
      </div>
    `).join('')}
  </div>

  ${options.includeSoc2 ? renderSoc2Section(project?.findings || []) : ''}

  <div class="footer">
    ${brandName
      ? `Prepared for ${escapeHtml(brandName)} from an automated static scan.`
      : 'Generated by Zelsis Release Gate from an automated static scan (OWASP-oriented security rules and code-quality checks).'}
  </div>
</body>
</html>
  `;

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
