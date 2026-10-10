/**
 * The GitHub App private key as a valid PEM, however it was pasted into the environment:
 * literal "\n" sequences, CRLF, surrounding quotes, newlines turned into spaces (a single line),
 * or the whole PEM base64-encoded. OpenSSL rejects all of those with "DECODER routines::unsupported".
 */
export function normalizePrivateKey(raw: string | undefined): string | null {
  if (!raw) return null;
  let key = raw.trim().replace(/^["']|["']$/g, '').replace(/\\n/g, '\n').replace(/\r\n?/g, '\n').trim();

  // Whole PEM base64-encoded (no BEGIN line)
  if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)) {
    try {
      const decoded = Buffer.from(key, 'base64').toString('utf8');
      if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(decoded)) key = decoded.trim();
    } catch {
      /* not base64 */
    }
  }

  const m = /-----BEGIN ([A-Z ]*PRIVATE KEY)-----([\s\S]*?)-----END \1-----/.exec(key);
  if (!m) return null;
  // Re-wrap the body at 64 characters, whatever whitespace it had
  const body = m[2].replace(/\s+/g, '');
  const lines = body.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${m[1]}-----\n${lines.join('\n')}\n-----END ${m[1]}-----\n`;
}
