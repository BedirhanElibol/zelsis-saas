import { Project, Finding } from '@/data/schema';

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
export function generateAuditPdfReport(project: Project) {
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
  <title>Zelsis Release Audit Report — ${projectNameEscaped}</title>
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
      <div class="logo">ZELSIS AUDIT REPORT</div>
      <div style="color: #a1a1aa; font-size: 14px;">Official B2B Production Readiness Certificate</div>
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
      <div style="color: #a1a1aa; font-size: 12px;">VIBEPOLISH UI MATRIX</div>
      <div class="kpi-val">${(project?.uiClicheCount ?? 0) === 0 ? '100% Clean' : `${project?.uiClicheCount} Open`}</div>
    </div>
  </div>

  <div class="section">
    <h2>Audit Findings Inventory (${openFindings.length} Open Issues)</h2>
    ${openFindings.length === 0 ? '<p style="color: #10b981;">🎉 All security pre-flight checks and VibePolish &amp; AI Anti-Pattern rules cleared with 100/100 Readiness Score.</p>' : ''}
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

  <div class="footer">
    Generated by Zelsis Release Gate SaaS v3.0 / Verified against OWASP Security Pre-flight Checks &amp; VibePolish &amp; AI Anti-Pattern Rules.
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
