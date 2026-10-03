import { Finding, Project } from '@/data/schema';

/**
 * Escapes fields for RFC 4180 compliant CSV output.
 */
function escapeCsvField(val: string | number | undefined | null): string {
  if (val === undefined || val === null) return '""';
  const str = String(val);
  // If value contains comma, double quote, or newline, quote it and double any quotes
  if (/[",\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return `"${str}"`;
}

/**
 * Downloads data as a file in the browser.
 */
function downloadFile(content: string, filename: string, mimeType: string) {
  if (typeof window === 'undefined') return;
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Exports findings as an RFC 4180 CSV file suitable for Jira, Linear, or Excel.
 */
export function exportFindingsToCsv(findings: Finding[], projectName: string = 'zelsis-audit'): void {
  const headers = [
    'ID',
    'Severity',
    'Pillar',
    'Category',
    'Title',
    'File Path',
    'Line Range',
    'Status',
    'Owner',
    'Snippet',
    'Remediation Directive'
  ];

  const rows = findings.map((f) => [
    escapeCsvField(f.id),
    escapeCsvField(f.severity),
    escapeCsvField(f.type),
    escapeCsvField(f.category),
    escapeCsvField(f.title),
    escapeCsvField(f.filePath),
    escapeCsvField(f.lineRange),
    escapeCsvField(f.status),
    escapeCsvField(f.owner || 'Security Team'),
    escapeCsvField(f.snippet),
    escapeCsvField(f.remediationPrompt)
  ]);

  const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');
  const safeName = (projectName || 'project').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  const timestamp = new Date().toISOString().slice(0, 10);
  downloadFile(csvContent, `zelsis-findings-${safeName}-${timestamp}.csv`, 'text/csv;charset=utf-8;');
}

/**
 * Exports the complete audit scorecard as a structured JSON artifact for SOC2 / CI auditing.
 */
export function exportScorecardToJson(project: Project): void {
  const auditReport = {
    schemaVersion: '3.0.0',
    generatedAt: new Date().toISOString(),
    auditEngine: 'Zelsis Release Gate SaaS (Production AST)',
    target: {
      id: project.id,
      name: project.name,
      repoUrl: project.repoUrl,
      framework: project.framework,
      providers: project.providers,
      lastScanAt: project.lastScanAt
    },
    executiveSummary: {
      readinessScore: project.readinessScore,
      gateStatus: project.gateStatus,
      statusExplanation:
        project.gateStatus === 'PASSED'
          ? 'Production Audit PASSED. All security and design compliance checks cleared.'
          : project.gateStatus === 'WARNING'
          ? `Release WARNING. Detected ${project.highCount} High and ${project.mediumCount} Medium findings. Review recommended.`
          : `Release BLOCKED. Detected ${project.criticalCount} Critical blocker(s) requiring immediate remediation.`,
      metrics: {
        score: project.readinessScore,
        criticalCount: project.criticalCount,
        highCount: project.highCount,
        mediumCount: project.mediumCount,
        lowCount: project.lowCount,
        uiClicheCount: project.uiClicheCount,
        openFindingsCount: project.findings.filter((f) => f.status === 'OPEN').length
      }
    },
    findings: project.findings.map((f) => ({
      id: f.id,
      ruleId: f.ruleId,
      severity: f.severity,
      pillar: f.type,
      category: f.category,
      title: f.title,
      location: {
        filePath: f.filePath,
        lineRange: f.lineRange
      },
      evidenceSnippet: f.snippet,
      reproductionSteps: f.reproductionSteps,
      remediationDirective: f.remediationPrompt,
      diffPatch: f.diffPatch || null,
      status: f.status,
      owner: f.owner || 'Security Architect'
    }))
  };

  const jsonContent = JSON.stringify(auditReport, null, 2);
  const safeName = (project?.name || 'project').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  const timestamp = new Date().toISOString().slice(0, 10);
  downloadFile(jsonContent, `zelsis-scorecard-${safeName}-${timestamp}.json`, 'application/json');
}

/**
 * Formats a finding into a copy-pasteable Jira / Linear / GitHub Issue Markdown ticket.
 */
export function formatFindingForJira(finding: Finding): string {
  const steps = (finding.reproductionSteps || []).map((s, idx) => `${idx + 1}. ${s}`).join('\n');

  return `## [${finding.severity}] ${finding.title}

* **Pillar:** \`${finding.type}\`
* **Category:** ${finding.category}
* **Affected File:** \`${finding.filePath}:${finding.lineRange}\`
* **Status:** \`${finding.status}\`

### 1. Reproduction Steps & Diagnostic Evidence
${steps || '1. Scanned repository codebase through Zelsis AST inspection.'}

\`\`\`
${finding.snippet}
\`\`\`

### 2. Remediation Directive
${finding.remediationPrompt}

${
  finding.diffPatch
    ? `### 3. Unified Patch
\`\`\`diff
${finding.diffPatch}
\`\`\`
`
    : ''
}
---
*Generated by Zelsis Automated Release Gate*
`;
}

/**
 * Copies Jira ticket markdown to clipboard with navigator fallback.
 */
export async function copyFindingJiraMarkdown(finding: Finding): Promise<boolean> {
  const markdown = formatFindingForJira(finding);
  try {
    await navigator.clipboard.writeText(markdown);
    return true;
  } catch {
    return false;
  }
}
