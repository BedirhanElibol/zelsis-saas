import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { computeReportFindingsDigest, generateAuditPdfReport } from '../../lib/pdf-exporter';
import type { Project, Finding } from '../../data/schema';

describe('PDF report digest and scope page', () => {
  const baseFinding: Finding = {
    id: 'f-1',
    ruleId: 1001,
    type: 'SECURITY',
    title: 'Hardcoded API Key',
    severity: 'CRITICAL',
    category: 'Secrets',
    filePath: 'src/config.ts',
    lineRange: 'L10',
    snippet: 'const key = "sk-live-123";',
    reproductionSteps: ['Check line 10'],
    remediationPrompt: 'Use environment variables',
    status: 'OPEN',
    falsePositive: false,
  };

  const baseFinding2: Finding = {
    id: 'f-2',
    ruleId: 1002,
    type: 'SECURITY',
    title: 'Permissive CORS',
    severity: 'HIGH',
    category: 'Network',
    filePath: 'src/server.ts',
    lineRange: 'L25',
    snippet: 'cors({ origin: "*" })',
    reproductionSteps: ['Check server.ts'],
    remediationPrompt: 'Restrict CORS origin',
    status: 'OPEN',
    falsePositive: false,
  };

  const baseProject: Project = {
    id: 'proj-1',
    name: 'test-app',
    repoUrl: 'https://github.com/example/test-app',
    framework: 'Next.js',
    providers: ['GitHub'],
    lastScanAt: '2026-10-24 12:00',
    lastScanIso: '2026-10-24T12:00:00.000Z',
    readinessScore: 92,
    gateStatus: 'WARNING',
    criticalCount: 1,
    highCount: 1,
    mediumCount: 0,
    lowCount: 0,
    uiClicheCount: 0,
    findings: [baseFinding, baseFinding2],
  };

  it('generates a valid 64-char hex SHA-256 digest', () => {
    const hash = computeReportFindingsDigest(baseProject);
    assert.match(hash, /^[a-f0-9]{64}$/);
  });

  it('same input with shuffled findings produces the exact same hash (stable sorting)', () => {
    const projShuffled: Project = {
      ...baseProject,
      findings: [baseFinding2, baseFinding],
    };
    const hashA = computeReportFindingsDigest(baseProject);
    const hashB = computeReportFindingsDigest(projShuffled);
    assert.equal(hashA, hashB);
  });

  it('any changed finding field produces a different hash', () => {
    const originalHash = computeReportFindingsDigest(baseProject);

    // Change severity
    const changedSeverity: Project = {
      ...baseProject,
      findings: [{ ...baseFinding, severity: 'MEDIUM' }, baseFinding2],
    };
    assert.notEqual(computeReportFindingsDigest(changedSeverity), originalHash);

    // Change filePath
    const changedPath: Project = {
      ...baseProject,
      findings: [{ ...baseFinding, filePath: 'src/other.ts' }, baseFinding2],
    };
    assert.notEqual(computeReportFindingsDigest(changedPath), originalHash);

    // Change status
    const changedStatus: Project = {
      ...baseProject,
      findings: [{ ...baseFinding, status: 'RESOLVED' }, baseFinding2],
    };
    assert.notEqual(computeReportFindingsDigest(changedStatus), originalHash);

    // Change title
    const changedTitle: Project = {
      ...baseProject,
      findings: [{ ...baseFinding, title: 'Different Title' }, baseFinding2],
    };
    assert.notEqual(computeReportFindingsDigest(changedTitle), originalHash);
  });

  it('different commit or repository URL produces a different hash', () => {
    const hash1 = computeReportFindingsDigest(baseProject, { commit: 'abc1234' });
    const hash2 = computeReportFindingsDigest(baseProject, { commit: 'def5678' });
    assert.notEqual(hash1, hash2);

    const diffRepo: Project = {
      ...baseProject,
      repoUrl: 'https://github.com/other/app',
    };
    assert.notEqual(computeReportFindingsDigest(diffRepo), computeReportFindingsDigest(baseProject));
  });

  it('generateAuditPdfReport includes digest, single comparison sentence, and scope & limits page', () => {
    const html = generateAuditPdfReport(baseProject, {
      commit: '9f8e7d6c',
      fileCount: 42,
      includeOwasp: true,
    }) as unknown as string;

    // Must include the digest section
    assert.ok(html.includes('Report Data Digest'), 'contains digest heading');
    assert.ok(html.includes('SHA-256:'), 'contains SHA-256 label');

    // Must include the exact single comparison sentence
    assert.ok(
      html.includes('Anyone can re-run the scan at the same commit and compare.'),
      'contains exact comparison sentence'
    );

    // Must not call the digest a certificate, audit or attestation in that section
    const digestSection = html.slice(html.indexOf('Report Data Digest'), html.indexOf('Report Data Digest') + 400);
    assert.ok(!/certificate|attestation/i.test(digestSection), 'does not call digest certificate or attestation');

    // Scope and limits page
    assert.ok(html.includes('Scope and Limits'), 'contains Scope and Limits heading');
    assert.ok(html.includes('What was scanned'), 'contains What was scanned');
    assert.ok(html.includes('What a static check cannot see'), 'contains What a static check cannot see');
    assert.ok(html.includes('Release gate rule governance'), 'contains Release gate rule governance');
    assert.ok(html.includes('9f8e7d6c'), 'contains commit SHA');
    assert.ok(html.includes('42 files'), 'contains file count');

    // FAQ gate rule governance wording check
    assert.ok(
      html.includes('Every rule change is measured against a pinned benchmark of intentionally vulnerable apps'),
      'contains exact FAQ rule governance wording'
    );
  });
});
