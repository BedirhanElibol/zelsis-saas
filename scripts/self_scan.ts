import fs from 'fs';
import path from 'path';
import { runStaticCodeScan } from '../lib/scanner-engine';

const EXCLUDE_DIRS = new Set([
  'node_modules',
  '.next',
  '.git',
  '.agent',
  'dist',
  'coverage',
  'tests',
  'scratch',
  '.gemini',
  // benchmark / mobile corpora and agent worktrees: other people's code, not this repo
  '.cache',
  '.claude',
]);

const VALID_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.json',
  '.sql',
  '.py',
  '.go',
  '.php',
  '.cs',
  '.java',
  '.rb',
  '.env.example',
  'Dockerfile',
]);

function collectFiles(dir: string, baseDir: string = dir): { path: string; content: string }[] {
  let results: { path: string; content: string }[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (EXCLUDE_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(baseDir, fullPath).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      results = results.concat(collectFiles(fullPath, baseDir));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (VALID_EXTENSIONS.has(ext) || entry.name === 'Dockerfile') {
        try {
          const content = fs.readFileSync(fullPath, 'utf-8');
          // Limit individual file size to 500KB
          if (content.length < 500 * 1024) {
            results.push({ path: relPath, content });
          }
        } catch {
          // ignore unreadable
        }
      }
    }
  }

  return results;
}

async function main() {
  const rootDir = path.resolve(__dirname, '..');
  console.log(`[Self-Scan] Collecting source files from: ${rootDir}`);
  const files = collectFiles(rootDir);
  console.log(`[Self-Scan] Collected ${files.length} candidate files.`);

  console.log('[Self-Scan] Executing Zelsis AST Engine...');
  const startTime = Date.now();
  const scanResult = await runStaticCodeScan(files);
  const durationMs = Date.now() - startTime;

  console.log(`[Self-Scan] Scan completed in ${durationMs}ms`);
  console.log(`[Self-Scan] Overall Score: ${scanResult.score}/100`);
  console.log(`[Self-Scan] Total Findings: ${scanResult.findings.length}`);
  console.log(`[Self-Scan] Gate Status: ${scanResult.gateStatus}`);
  console.log(`[Self-Scan] Detected Stacks: ${scanResult.detectedDatabases?.join(', ') || 'None'}`);

  // Format into markdown baseline report
  const criticals = scanResult.findings.filter((f) => f.severity === 'CRITICAL');
  const highs = scanResult.findings.filter((f) => f.severity === 'HIGH');
  const mediums = scanResult.findings.filter((f) => f.severity === 'MEDIUM');
  const lows = scanResult.findings.filter((f) => f.severity === 'LOW');

  let report = `# Zelsis Self-Scan Dogfooding Baseline Report\n\n`;
  report += `**Generated At:** ${new Date().toISOString()}  \n`;
  report += `**Target:** Zelsis Codebase (Internal Self-Scan)  \n`;
  report += `**Analyzed Files:** ${files.length} source files  \n`;
  report += `**Duration:** ${durationMs}ms  \n`;
  report += `**Readiness Score:** ${scanResult.score}/100  \n`;
  report += `**Gate Clearance:** ${scanResult.gateStatus}  \n\n`;

  report += `## Executive Summary\n\n`;
  report += `| Metric | Count |\n`;
  report += `|---|---|\n`;
  report += `| **Critical Blockers** | ${criticals.length} |\n`;
  report += `| **High Severity Issues** | ${highs.length} |\n`;
  report += `| **Medium Warnings** | ${mediums.length} |\n`;
  report += `| **Low / Informational** | ${lows.length} |\n`;
  report += `| **Total Findings** | ${scanResult.findings.length} |\n\n`;

  report += `## Detected Stacks & Architecture\n\n`;
  report += `- **Databases:** ${scanResult.detectedDatabases?.join(', ') || 'PostgreSQL (Supabase)'}\n`;
  report += `- **ORMs:** ${scanResult.detectedOrms?.join(', ') || 'Supabase Client'}\n\n`;

  report += `## Detailed Findings Catalog\n\n`;
  if (scanResult.findings.length === 0) {
    report += `🎉 **Zero findings detected! Codebase meets all active deployment gates cleanly.**\n`;
  } else {
    report += `| ID | Severity | Pillar | Rule Code | File | Description |\n`;
    report += `|---|---|---|---|---|---|\n`;
    scanResult.findings.forEach((f, idx) => {
      report += `| ${idx + 1} | **${f.severity}** | ${f.type} | \`${f.ruleId}\` | \`${f.filePath}:${f.lineRange || '1'}\` | ${f.title.replace(/\|/g, '-')} |\n`;
    });
  }

  report += `\n## Remediation & Hardening Plan\n\n`;
  if (criticals.length > 0) {
    report += `### Critical Remediation Items:\n`;
    criticals.forEach((c) => {
      report += `- **${c.title}** in \`${c.filePath}\` (Lines ${c.lineRange})\n  - Fix: ${c.remediationPrompt || 'Review manual resolution'}\n`;
    });
  } else {
    report += `✅ Zero critical deployment blockers exist in the Zelsis core architecture.\n`;
  }

  const outPath = path.resolve(rootDir, 'docs', 'self-scan-baseline.md');
  fs.writeFileSync(outPath, report, 'utf-8');
  console.log(`[Self-Scan] Report successfully saved to: ${outPath}`);
}

main().catch((err) => {
  console.error('[Self-Scan Error]', err);
  process.exit(1);
});
