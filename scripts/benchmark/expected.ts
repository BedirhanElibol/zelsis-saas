/**
 * Documented flaws in the intentionally vulnerable corpus apps, located by reading their source.
 * A flaw counts as detected when any finding in that file has a title of the matching class
 * (rule-ID agnostic, so renaming or merging rules cannot game recall).
 */
export interface ExpectedFlaw { repo: string; file: string; flaw: string; match: RegExp }

const SQLI = /SQL/i;
const CODE_EXEC = /eval|Code Execution|Code Injection|Remote Code/i;
const REDIRECT = /Redirect/i;
const SSRF = /SSRF|Server-Side Request/i;
const SECRET = /Secret|Hardcoded|Credential|Private Key/i;

export const EXPECTED_FLAWS: ExpectedFlaw[] = [
  { repo: 'OWASP/NodeGoat', file: 'app/routes/contributions.js', flaw: 'Server-side JS injection via eval(req.body.preTax)', match: CODE_EXEC },
  { repo: 'OWASP/NodeGoat', file: 'app/data/allocations-dao.js', flaw: 'NoSQL injection through $where string', match: /NoSQL|\$where|Mongo/i },
  { repo: 'OWASP/NodeGoat', file: 'app/routes/index.js', flaw: 'Open redirect via res.redirect(req.query.url)', match: REDIRECT },
  { repo: 'OWASP/NodeGoat', file: 'app/routes/research.js', flaw: 'SSRF via needle.get(url + symbol)', match: SSRF },
  { repo: 'OWASP/NodeGoat', file: 'config/env/all.js', flaw: 'Hardcoded session cookie secret', match: SECRET },
  { repo: 'appsecco/dvna', file: 'core/appHandler.js', flaw: 'SQL injection by string concatenation in sequelize.query', match: SQLI },
  { repo: 'appsecco/dvna', file: 'core/appHandler.js', flaw: "Command injection: exec('ping -c 2 ' + req.body.address)", match: /Command|Shell|exec/i },
  { repo: 'appsecco/dvna', file: 'core/appHandler.js', flaw: 'Insecure deserialization with node-serialize unserialize', match: /Deserializ/i },
  { repo: 'appsecco/dvna', file: 'core/appHandler.js', flaw: 'XXE: libxmljs parseXmlString with noent:true', match: /XXE|XML External|External Entit/i },
  { repo: 'appsecco/dvna', file: 'core/appHandler.js', flaw: 'Open redirect via res.redirect(req.query.url)', match: REDIRECT },
  { repo: 'appsecco/dvna', file: 'core/appHandler.js', flaw: 'Code injection via mathjs.eval(req.body.eqn)', match: CODE_EXEC },
  { repo: 'juice-shop/juice-shop', file: 'routes/login.ts', flaw: 'SQL injection in login query template literal', match: SQLI },
  { repo: 'juice-shop/juice-shop', file: 'routes/search.ts', flaw: 'Union SQL injection in product search', match: SQLI },
  { repo: 'juice-shop/juice-shop', file: 'lib/insecurity.ts', flaw: 'Hardcoded RSA private key for JWT signing', match: SECRET },
  { repo: 'juice-shop/juice-shop', file: 'lib/insecurity.ts', flaw: 'MD5 password hashing', match: /MD5|Broken Cryptographic|Weak Hash/i },
  { repo: 'juice-shop/juice-shop', file: 'routes/profileImageUrlUpload.ts', flaw: 'SSRF via fetch(user-supplied imageUrl)', match: SSRF }
];
