/**
 * Strips single-line (//), multi-line (/* ... *\/), and HTML (<!-- ... -->) comments
 * to prevent false positives in commented-out code snippets or documentation.
 */
export function stripComments(content: string): string {
  if (!content) return '';
  return content
    .replace(/\/\*[\s\S]*?\*\//g, (match) => {
      // F-12 Remediation: Preserve newlines so AST/regex line numbers do not drift
      const lineBreaks = match.split('\n').length - 1;
      return '\n'.repeat(lineBreaks);
    })
    .replace(/<!--[\s\S]*?-->/g, (match) => {
      const lineBreaks = match.split('\n').length - 1;
      return '\n'.repeat(lineBreaks);
    })
    .replace(/(?<!:)\/\/.*$/gm, '');   // Single-line JS/TS comments (preserves http:// and https:// URLs)
}

/**
 * Cooperative scheduling utility for streaming AST analysis.
 * Yields control back to the browser or Node.js event loop to prevent main thread freeze
 * on large (1,000+ files) codebases.
 */
export async function yieldToMain(): Promise<void> {
  if (typeof window !== 'undefined' && 'scheduler' in window && typeof (window as any).scheduler?.yield === 'function') {
    return (window as any).scheduler.yield();
  }
  return new Promise((resolve) => setTimeout(resolve, 0));
}
