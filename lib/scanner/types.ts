import type { Finding } from '@/data/schema';

export interface CodeFile {
  path: string;
  content: string;
}

export interface ScanResult {
  score: number;
  gateStatus: 'PASSED' | 'WARNING' | 'FAILED';
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  uiClicheCount: number;
  /** Open findings from experimental rules (not counted in score, gate or severity counts). */
  experimentalCount?: number;
  /** Wall-clock scan duration in ms (engine only; the dashboard replaces it with end-to-end time). */
  durationMs?: number;
  findings: Finding[];
  logs: string[];
  summary?: string;
  detectedDatabases?: string[];
  detectedOrms?: string[];
  /** Application framework detected from manifests (package.json, requirements.txt, Gemfile, go.mod, ...). */
  detectedFramework?: string;
  /** Hosting / CI providers detected from config files. */
  detectedProviders?: string[];
}
