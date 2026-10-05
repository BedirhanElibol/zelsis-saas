/**
 * JS/TS parsing for the AST rules (@babel/parser). Never throws: unparsable or oversized files return null
 * and the caller falls back to the line-based rules only.
 */
import { parse } from '@babel/parser';
import type { AstNode } from './walk';

const PARSABLE = /\.(?:m|c)?[jt]sx?$/i;
const SKIPPED_DIR = /(?:^|\/)(?:node_modules|\.next|dist|build|out|coverage|vendor)\//;
const MAX_BYTES = 400 * 1024;

export function isParsablePath(path: string): boolean {
  return PARSABLE.test(path) && !/\.d\.[cm]?ts$/i.test(path) && !SKIPPED_DIR.test(path.replace(/\\/g, '/'));
}

/** Parses raw file content (real line numbers). Returns the Program node, or null on failure. */
export function parseSource(path: string, content: string): AstNode | null {
  if (!isParsablePath(path) || !content || content.length > MAX_BYTES) return null;
  // .ts files may not contain JSX (`<T>x` casts would mis-parse); .js files often do (React without .jsx)
  const plugins: ('typescript' | 'jsx')[] = /\.[cm]?ts$/i.test(path) ? ['typescript'] : ['typescript', 'jsx'];
  for (const p of [plugins, ['jsx'] as ('jsx')[]]) {
    try {
      const file = parse(content, {
        sourceType: 'module',
        plugins: p,
        errorRecovery: true,
        allowReturnOutsideFunction: true,
        allowImportExportEverywhere: true,
        allowAwaitOutsideFunction: true,
        allowUndeclaredExports: true,
      }) as unknown as AstNode;
      return (file.program as AstNode) ?? null;
    } catch {
      // try the next plugin set (plain JSX for .js files with Flow-like syntax), then give up silently
      if (/\.[cm]?ts$/i.test(path)) return null;
    }
  }
  return null;
}
