/**
 * String and XML/SVG Sanitization Module for Zelsis SaaS
 * Prevents XML Injection, SVG-based Cross-Site Scripting (XSS),
 * and parameter tampering in SVG badges and API endpoints.
 */

const XML_SPECIAL_CHARS: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&apos;'
};

const XML_ESCAPE_REGEX = /[&<>"']/g;
// Matches XML 1.0 disallowed control characters: 0x00-0x08, 0x0B-0x0C, 0x0E-0x1F, 0x7F
const XML_CONTROL_CHARS_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

/**
 * Escapes characters with special meaning in XML/SVG documents:
 * & -> &amp;, < -> &lt;, > -> &gt;, " -> &quot;, ' -> &apos;
 * Also strips illegal XML control characters to prevent parser errors.
 */
export function escapeXml(value: unknown): string {
  if (value === null || value === undefined) return '';
  const str = String(value).replace(XML_CONTROL_CHARS_REGEX, '');
  return str.replace(XML_ESCAPE_REGEX, (char) => XML_SPECIAL_CHARS[char] || char);
}

/**
 * Specifically cleans and escapes text destined for SVG <text> elements.
 * Clamps length, removes newlines/carriage returns, strips control codes,
 * and escapes XML entities.
 */
export function escapeSvgText(value: unknown, maxLength = 64): string {
  if (value === null || value === undefined) return '';
  const cleanStr = String(value)
    .replace(/[\r\n\t]/g, ' ')
    .replace(XML_CONTROL_CHARS_REGEX, '')
    .trim()
    .slice(0, maxLength);

  return escapeXml(cleanStr);
}

/**
 * General string sanitization for API inputs.
 * Strips null bytes and excessive whitespace.
 */
export function sanitizeInput(value: unknown, maxLength = 256): string {
  if (typeof value !== 'string') {
    if (value === null || value === undefined) return '';
    return String(value).normalize('NFKC').slice(0, maxLength);
  }

  return value
    .normalize('NFKC')
    .replace(/\0/g, '') // Strip null bytes
    .trim()
    .slice(0, maxLength);
}

/**
 * HTML entities encoder for safe web text display.
 */
export function escapeHtml(value: unknown): string {
  return escapeXml(value);
}

export { purgeZelsisStorage, purgeShipguardStorage } from './storage';
