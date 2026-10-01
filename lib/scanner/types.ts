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
  findings: Finding[];
  logs: string[];
  summary?: string;
  detectedDatabases?: string[];
  detectedOrms?: string[];
}
