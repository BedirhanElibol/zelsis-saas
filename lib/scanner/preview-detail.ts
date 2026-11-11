const PREVIEW_FIX_MAX = 400;

export interface PreviewDetail {
  filePath: string;
  line?: number;
  impact?: string;
  fix: string;
}

/**
 * File, line, impact and a trimmed fix for the one finding the signup-free preview shows in full.
 * The preview only runs on public GitHub repositories, so the path is already public.
 */
export function previewDetail(f: { filePath: string; lineRange: string; impact?: string; remediationPrompt: string }): PreviewDetail {
  const line = /\d+/.exec(f.lineRange || '')?.[0];
  const fix = (f.remediationPrompt || '').trim();
  return {
    filePath: f.filePath,
    ...(line ? { line: Number(line) } : {}),
    ...(f.impact ? { impact: f.impact } : {}),
    fix: fix.length > PREVIEW_FIX_MAX ? `${fix.slice(0, PREVIEW_FIX_MAX).trimEnd()}…` : fix,
  };
}
