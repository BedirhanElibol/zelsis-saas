/**
 * CWE ids for security findings, read from the rule title. A wrong CWE costs more trust than a missing one, so only
 * unambiguous vulnerability names are mapped and everything else stays empty. Catalog `cweId` values are not used:
 * most hold the placeholder CWE-1234. First match wins, so narrower names come before broader ones.
 */
const TITLE_CWE: [RegExp, number][] = [
  [/\bno-?sql injection\b/i, 943],
  [/\bsql injection\b/i, 89],
  [/\b(?:os )?command injection\b/i, 78],
  [/\bcross-site scripting\b|\bxss\b/i, 79],
  [/\bssrf\b|\bserver-side request forgery\b/i, 918],
  [/\bpath traversal\b|\bzip slip\b|\bdirectory traversal\b/i, 22],
  [/\bopen redirect\b/i, 601],
  [/\bxxe\b|\bxml external entit/i, 611],
  [/\bcsrf\b|\bcross-site request forgery\b/i, 352],
  [/\bdeserialization\b/i, 502],
  [/\bldap injection\b/i, 90],
  [/\bxpath\b.*\b(?:injection|request value)\b/i, 643],
  [/\bprototype pollution\b/i, 1321],
  [/\bredos\b|\bcatastrophic backtrack/i, 1333],
  [/\bmass assignment\b/i, 915],
  [/\bclickjacking\b/i, 1021],
  [/\bformat string\b/i, 134],
  [/\bdouble free\b/i, 415],
  [/\buse[- ]after[- ]free\b/i, 416],
  [/\binteger overflow\b/i, 190],
  [/\bbuffer overflow\b/i, 120],
  [/\bidor\b|\binsecure direct object reference\b/i, 639],
  [/\bhard-?coded\b.*\b(?:secret|credential|password|api key|token)s?\b/i, 798],
  [/\bfixed initialization vector\b/i, 329],
  [/\bserver-side template injection\b|\bssti\b/i, 1336],
  [/\bdynamic code execution\b|\bremote code execution via eval\b/i, 95],
  [/\bweak password hashing\b|\bpassword hashed with a fast\b/i, 916],
  [/\bweak cryptographic hash\b|\bbroken cryptographic hash\b/i, 328],
  [/\bweak prng\b/i, 338],
  [/\becb\b|\bweak cipher\b|\bweak cryptographic algorithm\b|\bcryptographically (?:weak|broken)\b/i, 327],
  [/\b(?:certificate|tls|ssl) (?:\/ tls )?(?:certificate )?(?:verification|validation) disabled\b|\binsecureskipverify\b|\bnode_tls_reject_unauthorized\b|\bdisables certificate checks\b/i, 295],
  [/\bjwt algorithm confusion\b|\bunverified jwt\b|\bjwt signature verification disabled\b|\bjwt parsing without signature\b|\btrusts jwt claims decoded without\b/i, 347],
  [/\bcookie set without httponly\b/i, 1004],
  [/\bcors\b.*\b(?:wildcard|reflects|any origin|every origin|permissive)\b|\b(?:wildcard|permissive|insecure)\b.*\bcors\b/i, 942],
  [/\bmath\.random\b|\binsecure pseudo-random\b|\bweak random number\b|\bpredictable random\b/i, 338],
  [/\btiming attack\b|\bmissing timing-safe\b/i, 208],
  [/\bsubresource integrity\b/i, 353],
  [/\bdebug mode enabled in production\b|\brunning in debug mode\b/i, 489],
  [/\bunrestricted (?:multipart graphql )?file upload\b/i, 434],
];

/** Rules whose title does not name the weakness in standard terms. */
const RULE_CWE: Record<number, number> = {
  31008: 489, // Struts development mode
  31010: 521, // Empty Django password validators
};

interface CweInput {
  ruleId?: number;
  title?: string;
  type?: string;
}

/** The CWE id such as `CWE-89` for a security finding, or undefined when no mapping is certain. */
export function cweForFinding(finding: CweInput): string | undefined {
  if (finding.type !== 'SECURITY') return undefined;
  const byRule = finding.ruleId === undefined ? undefined : RULE_CWE[finding.ruleId];
  if (byRule) return `CWE-${byRule}`;
  // A title that names its own CWE is the rule author's choice.
  const named = finding.title?.match(/\bCWE-(\d+)\b/)?.[1];
  if (named) return `CWE-${named}`;
  const hit = TITLE_CWE.find(([pattern]) => pattern.test(finding.title || ''));
  return hit ? `CWE-${hit[1]}` : undefined;
}

export const cweUrl = (cwe: string) => `https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`;

/** SARIF tag GitHub Code Scanning reads as a CWE reference. */
export const cweSarifTag = (cwe: string) => `external/cwe/${cwe.toLowerCase()}`;
