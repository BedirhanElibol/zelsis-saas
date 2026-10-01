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
const CMD = /Command|Shell|exec|system/i;
const DESER = /Deserializ|pickle|Marshal|YAML/i;
const XXE = /XXE|XML External|External Entit/i;
const XSS = /XSS|Cross-Site Scripting|html_safe|Unescaped|autoescape/i;
const WEAK_HASH = /MD5|Broken Cryptographic|Weak Hash/i;

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
  { repo: 'juice-shop/juice-shop', file: 'routes/profileImageUrlUpload.ts', flaw: 'SSRF via fetch(user-supplied imageUrl)', match: SSRF },
  { repo: 'WebGoat/WebGoat', file: 'src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java', flaw: 'SQL injection: string-built query passed to Statement.executeQuery', match: SQLI },
  { repo: 'WebGoat/WebGoat', file: 'src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson10.java', flaw: 'SQL injection in access_log search', match: SQLI },
  { repo: 'WebGoat/WebGoat', file: 'src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java', flaw: 'Java deserialization with ObjectInputStream.readObject on user data', match: DESER },
  { repo: 'WebGoat/WebGoat', file: 'src/main/java/org/owasp/webgoat/lessons/xxe/CommentsCache.java', flaw: 'XXE: XMLInputFactory without disabling external entities', match: XXE },
  { repo: 'OWASP/railsgoat', file: 'app/controllers/users_controller.rb', flaw: 'SQL injection: User.where with interpolated params', match: SQLI },
  { repo: 'OWASP/railsgoat', file: 'app/controllers/users_controller.rb', flaw: 'Mass assignment: params.require(:user).permit!', match: /Mass Assignment|permit/i },
  { repo: 'OWASP/railsgoat', file: 'app/models/benefits.rb', flaw: 'Command injection: system() with interpolated file name', match: CMD },
  { repo: 'OWASP/railsgoat', file: 'app/controllers/password_resets_controller.rb', flaw: 'Insecure deserialization: Marshal.load(params[:user])', match: DESER },
  { repo: 'OWASP/railsgoat', file: 'app/views/layouts/shared/_header.html.erb', flaw: 'Stored XSS via html_safe on user first name', match: XSS },
  { repo: 'digininja/DVWA', file: 'vulnerabilities/sqli/source/low.php', flaw: 'SQL injection: $id interpolated into query', match: SQLI },
  { repo: 'digininja/DVWA', file: 'vulnerabilities/exec/source/low.php', flaw: "Command injection: shell_exec('ping ' . $target)", match: CMD },
  { repo: 'digininja/DVWA', file: 'vulnerabilities/fi/index.php', flaw: 'File inclusion: include($file) from request', match: /Inclusion|Include|Path Traversal|LFI|RFI/i },
  { repo: 'digininja/DVWA', file: 'vulnerabilities/xss_r/source/low.php', flaw: "Reflected XSS: $_GET['name'] echoed into HTML", match: XSS },
  { repo: 'digininja/DVWA', file: 'vulnerabilities/upload/source/low.php', flaw: 'Unrestricted file upload (no type/extension check)', match: /Upload/i },
  { repo: 'adeyosemanputra/pygoat', file: 'introduction/views.py', flaw: 'SQL injection: concatenated query passed to objects.raw', match: SQLI },
  { repo: 'adeyosemanputra/pygoat', file: 'introduction/views.py', flaw: 'Insecure deserialization: pickle.loads / yaml.load with yaml.Loader', match: DESER },
  { repo: 'adeyosemanputra/pygoat', file: 'introduction/views.py', flaw: 'Code injection: eval() on request value', match: CODE_EXEC },
  { repo: 'adeyosemanputra/pygoat', file: 'introduction/views.py', flaw: 'SSRF: requests.get(request.POST["url"])', match: SSRF },
  { repo: 'adeyosemanputra/pygoat', file: 'introduction/views.py', flaw: 'MD5 password hashing', match: WEAK_HASH },
  { repo: 'anxolerd/dvpwa', file: 'sqli/dao/student.py', flaw: 'SQL injection: % string formatting in INSERT', match: SQLI },
  { repo: 'anxolerd/dvpwa', file: 'sqli/dao/user.py', flaw: 'MD5 password hashing', match: WEAK_HASH },
  { repo: 'anxolerd/dvpwa', file: 'sqli/app.py', flaw: 'Template autoescaping disabled (autoescape=False)', match: XSS }
];
