/**
 * Language coverage matrix: one small vulnerable file per (language, bug class).
 * Prints which classes the scanner catches in each language, so gaps are visible.
 * Run: npx tsx scripts/language-coverage.ts [--json]
 */
import { runStaticCodeScan } from '../lib/scanner-engine';

type Probe = { lang: string; cls: string; path: string; content: string };

// Fake credential assembled at runtime so secret scanners don't flag this file
const AWS = 'AKIA' + '2E0A8F3B244C9986';
const SK = 'q8Rv3TnLw0Zp' + 'Xk5Hd2Ys7Fb9Mc4Gj1Ue6Wa8Pn';

export const PROBES: Probe[] = [
  // SQL built from request input
  { lang: 'TypeScript', cls: 'sqli', path: 'src/routes/users.ts', content: "app.get('/users', async (req, res) => {\n  const rows = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);\n  res.json(rows);\n});\n" },
  { lang: 'Python', cls: 'sqli', path: 'app/views.py', content: "def search(request):\n    name = request.GET['name']\n    cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n    return JsonResponse(cursor.fetchall(), safe=False)\n" },
  { lang: 'Go', cls: 'sqli', path: 'handlers/users.go', content: "func Search(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get(\"name\")\n\trows, _ := db.Query(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n\tdefer rows.Close()\n}\n" },
  { lang: 'Java', cls: 'sqli', path: 'src/main/java/app/UserController.java', content: "@GetMapping(\"/users\")\npublic List<User> search(@RequestParam String name) {\n    return jdbcTemplate.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\", mapper);\n}\n" },
  { lang: 'Kotlin', cls: 'sqli', path: 'src/main/kotlin/app/UserController.kt', content: "@GetMapping(\"/users\")\nfun search(@RequestParam name: String): List<User> =\n    jdbcTemplate.query(\"SELECT * FROM users WHERE name = '$name'\", mapper)\n" },
  { lang: 'C#', cls: 'sqli', path: 'Controllers/UsersController.cs', content: "[HttpGet]\npublic IActionResult Search(string name)\n{\n    var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = '\" + name + \"'\", conn);\n    return Ok(cmd.ExecuteReader());\n}\n" },
  { lang: 'PHP', cls: 'sqli', path: 'public/search.php', content: "<?php\n$name = $_GET['name'];\n$result = mysqli_query($conn, \"SELECT * FROM users WHERE name = '$name'\");\n" },
  { lang: 'Ruby', cls: 'sqli', path: 'app/controllers/users_controller.rb', content: "class UsersController < ApplicationController\n  def search\n    @users = User.where(\"name = '#{params[:name]}'\")\n  end\nend\n" },
  { lang: 'Rust', cls: 'sqli', path: 'src/handlers.rs', content: "async fn search(Query(q): Query<Search>, State(pool): State<PgPool>) -> Json<Vec<User>> {\n    let sql = format!(\"SELECT * FROM users WHERE name = '{}'\", q.name);\n    Json(sqlx::query_as(&sql).fetch_all(&pool).await.unwrap())\n}\n" },
  { lang: 'Swift', cls: 'sqli', path: 'App/Database.swift', content: "func findUser(name: String) {\n    let sql = \"SELECT * FROM users WHERE name = '\\(name)'\"\n    sqlite3_exec(db, sql, nil, nil, nil)\n}\n" },
  { lang: 'Dart', cls: 'sqli', path: 'lib/data/user_repo.dart', content: "Future<List<Map>> findUser(String name) async {\n  return db.rawQuery(\"SELECT * FROM users WHERE name = '$name'\");\n}\n" },

  // OS command built from input
  { lang: 'TypeScript', cls: 'cmdi', path: 'src/routes/convert.ts', content: "import { exec } from 'child_process';\napp.post('/convert', (req, res) => {\n  exec(`convert ${req.body.file} out.png`, () => res.end());\n});\n" },
  { lang: 'Python', cls: 'cmdi', path: 'app/tools.py', content: "import os\ndef ping(request):\n    host = request.GET['host']\n    os.system('ping -c 1 ' + host)\n" },
  { lang: 'Go', cls: 'cmdi', path: 'handlers/ping.go', content: "func Ping(w http.ResponseWriter, r *http.Request) {\n\thost := r.URL.Query().Get(\"host\")\n\tout, _ := exec.Command(\"sh\", \"-c\", \"ping -c 1 \"+host).Output()\n\tw.Write(out)\n}\n" },
  { lang: 'Java', cls: 'cmdi', path: 'src/main/java/app/PingController.java', content: "@GetMapping(\"/ping\")\npublic String ping(@RequestParam String host) throws Exception {\n    Runtime.getRuntime().exec(\"ping -c 1 \" + host);\n    return \"ok\";\n}\n" },
  { lang: 'C#', cls: 'cmdi', path: 'Controllers/PingController.cs', content: "[HttpGet]\npublic IActionResult Ping(string host)\n{\n    Process.Start(\"cmd.exe\", \"/c ping \" + host);\n    return Ok();\n}\n" },
  { lang: 'PHP', cls: 'cmdi', path: 'public/ping.php', content: "<?php\n$host = $_GET['host'];\necho shell_exec('ping -c 1 ' . $host);\n" },
  { lang: 'Ruby', cls: 'cmdi', path: 'app/controllers/ping_controller.rb', content: "class PingController < ApplicationController\n  def show\n    render plain: `ping -c 1 #{params[:host]}`\n  end\nend\n" },
  { lang: 'Rust', cls: 'cmdi', path: 'src/ping.rs', content: "async fn ping(Query(q): Query<Host>) -> String {\n    let out = Command::new(\"sh\").arg(\"-c\").arg(format!(\"ping -c 1 {}\", q.host)).output().unwrap();\n    String::from_utf8_lossy(&out.stdout).to_string()\n}\n" },

  // Hardcoded cloud credential
  { lang: 'TypeScript', cls: 'secret', path: 'src/lib/s3.ts', content: `export const s3 = new S3Client({ credentials: { accessKeyId: '${AWS}', secretAccessKey: '${SK}' } });\n` },
  { lang: 'Python', cls: 'secret', path: 'app/storage.py', content: `AWS_ACCESS_KEY_ID = "${AWS}"\nAWS_SECRET_ACCESS_KEY = "${SK}"\n` },
  { lang: 'Go', cls: 'secret', path: 'internal/storage/s3.go', content: `const accessKey = "${AWS}"\nconst secretKey = "${SK}"\n` },
  { lang: 'Java', cls: 'secret', path: 'src/main/java/app/S3Config.java', content: `public class S3Config {\n    static final String ACCESS_KEY = "${AWS}";\n    static final String SECRET_KEY = "${SK}";\n}\n` },
  { lang: 'Kotlin', cls: 'secret', path: 'app/src/main/java/com/acme/Keys.kt', content: `object Keys {\n    const val ACCESS_KEY = "${AWS}"\n    const val SECRET_KEY = "${SK}"\n}\n` },
  { lang: 'Swift', cls: 'secret', path: 'App/Config.swift', content: `enum Config {\n    static let accessKey = "${AWS}"\n    static let secretKey = "${SK}"\n}\n` },
  { lang: 'Dart', cls: 'secret', path: 'lib/config.dart', content: `const accessKey = '${AWS}';\nconst secretKey = '${SK}';\n` },
  { lang: 'C#', cls: 'secret', path: 'Services/S3Service.cs', content: `public class S3Service {\n    private const string AccessKey = "${AWS}";\n    private const string SecretKey = "${SK}";\n}\n` },
  { lang: 'PHP', cls: 'secret', path: 'config/aws.php', content: `<?php\nreturn ['key' => '${AWS}', 'secret' => '${SK}'];\n` },
  { lang: 'Ruby', cls: 'secret', path: 'config/initializers/aws.rb', content: `Aws.config.update(credentials: Aws::Credentials.new('${AWS}', '${SK}'))\n` },
  { lang: 'Rust', cls: 'secret', path: 'src/config.rs', content: `pub const ACCESS_KEY: &str = "${AWS}";\npub const SECRET_KEY: &str = "${SK}";\n` },
  { lang: 'C++', cls: 'secret', path: 'src/config.cpp', content: `const char* ACCESS_KEY = "${AWS}";\nconst char* SECRET_KEY = "${SK}";\n` },

  // TLS certificate checks turned off
  { lang: 'TypeScript', cls: 'tls-off', path: 'src/lib/http.ts', content: "import https from 'https';\nexport const agent = new https.Agent({ rejectUnauthorized: false });\n" },
  { lang: 'Python', cls: 'tls-off', path: 'app/client.py', content: "import requests\ndef fetch(url):\n    return requests.get(url, verify=False).json()\n" },
  { lang: 'Go', cls: 'tls-off', path: 'internal/client/http.go', content: "var Client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}\n" },
  { lang: 'Java', cls: 'tls-off', path: 'src/main/java/app/TrustAll.java', content: "public class TrustAll implements X509TrustManager {\n    public void checkClientTrusted(X509Certificate[] c, String a) {}\n    public void checkServerTrusted(X509Certificate[] c, String a) {}\n    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }\n}\n" },
  { lang: 'Swift', cls: 'tls-off', path: 'App/Network/SessionDelegate.swift', content: "func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {\n    completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))\n}\n" },
  { lang: 'Dart', cls: 'tls-off', path: 'lib/net/client.dart', content: "HttpClient createClient() {\n  final client = HttpClient();\n  client.badCertificateCallback = (cert, host, port) => true;\n  return client;\n}\n" },
  { lang: 'C#', cls: 'tls-off', path: 'Services/ApiClient.cs', content: "var handler = new HttpClientHandler();\nhandler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;\nvar client = new HttpClient(handler);\n" },
  { lang: 'PHP', cls: 'tls-off', path: 'src/Http.php', content: "<?php\n$ch = curl_init($url);\ncurl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\n$body = curl_exec($ch);\n" },
  { lang: 'Ruby', cls: 'tls-off', path: 'lib/api_client.rb', content: "http = Net::HTTP.new(uri.host, uri.port)\nhttp.use_ssl = true\nhttp.verify_mode = OpenSSL::SSL::VERIFY_NONE\n" },
  { lang: 'Rust', cls: 'tls-off', path: 'src/client.rs', content: "let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;\n" },

  // Unsafe deserialization of untrusted data
  { lang: 'Python', cls: 'deserialize', path: 'app/api.py', content: "import pickle\ndef load(request):\n    obj = pickle.loads(request.body)\n    return JsonResponse(obj)\n" },
  { lang: 'Java', cls: 'deserialize', path: 'src/main/java/app/ImportController.java', content: "@PostMapping(\"/import\")\npublic void importData(HttpServletRequest req) throws Exception {\n    ObjectInputStream in = new ObjectInputStream(req.getInputStream());\n    Object o = in.readObject();\n}\n" },
  { lang: 'C#', cls: 'deserialize', path: 'Controllers/ImportController.cs', content: "[HttpPost]\npublic IActionResult Import()\n{\n    var formatter = new BinaryFormatter();\n    var obj = formatter.Deserialize(Request.Body);\n    return Ok();\n}\n" },
  { lang: 'PHP', cls: 'deserialize', path: 'public/import.php', content: "<?php\n$data = unserialize($_COOKIE['cart']);\n" },
  { lang: 'Ruby', cls: 'deserialize', path: 'app/controllers/import_controller.rb', content: "class ImportController < ApplicationController\n  def create\n    data = Marshal.load(Base64.decode64(params[:blob]))\n  end\nend\n" },

  // Weak password hashing
  { lang: 'TypeScript', cls: 'weak-hash', path: 'src/auth/password.ts', content: "import crypto from 'crypto';\nexport const hashPassword = (password: string) => crypto.createHash('md5').update(password).digest('hex');\n" },
  { lang: 'Python', cls: 'weak-hash', path: 'app/auth.py', content: "import hashlib\ndef hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()\n" },
  { lang: 'Go', cls: 'weak-hash', path: 'internal/auth/password.go', content: "func HashPassword(password string) string {\n\tsum := md5.Sum([]byte(password))\n\treturn hex.EncodeToString(sum[:])\n}\n" },
  { lang: 'Java', cls: 'weak-hash', path: 'src/main/java/app/PasswordUtil.java', content: "public static String hashPassword(String password) throws Exception {\n    MessageDigest md = MessageDigest.getInstance(\"MD5\");\n    return new String(md.digest(password.getBytes()));\n}\n" },
  { lang: 'C#', cls: 'weak-hash', path: 'Services/PasswordHasher.cs', content: "public string HashPassword(string password)\n{\n    using var md5 = MD5.Create();\n    return Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));\n}\n" },
  { lang: 'PHP', cls: 'weak-hash', path: 'src/Auth.php', content: "<?php\nfunction hashPassword($password) {\n    return md5($password);\n}\n" },

  // Path traversal from request input
  { lang: 'TypeScript', cls: 'path', path: 'src/routes/files.ts', content: "app.get('/files', (req, res) => {\n  res.sendFile(path.join(__dirname, 'uploads', req.query.name as string));\n});\n" },
  { lang: 'Python', cls: 'path', path: 'app/files.py', content: "@app.route('/files')\ndef download():\n    name = request.args.get('name')\n    return open(os.path.join('uploads', name)).read()\n" },
  { lang: 'Go', cls: 'path', path: 'handlers/files.go', content: "func Download(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get(\"name\")\n\thttp.ServeFile(w, r, filepath.Join(\"uploads\", name))\n}\n" },
  { lang: 'Java', cls: 'path', path: 'src/main/java/app/FileController.java', content: "@GetMapping(\"/files\")\npublic byte[] download(@RequestParam String name) throws Exception {\n    return Files.readAllBytes(Paths.get(\"uploads\", name));\n}\n" },
  { lang: 'C#', cls: 'path', path: 'Controllers/FilesController.cs', content: "[HttpGet]\npublic IActionResult Download(string name)\n{\n    return PhysicalFile(Path.Combine(\"/app/uploads\", name), \"application/octet-stream\");\n}\n" },
  { lang: 'PHP', cls: 'path', path: 'public/download.php', content: "<?php\nreadfile('uploads/' . $_GET['name']);\n" },

  // Mobile: tokens in plain local storage
  { lang: 'Kotlin', cls: 'mobile-storage', path: 'app/src/main/java/com/acme/Session.kt', content: "fun saveToken(ctx: Context, token: String) {\n    ctx.getSharedPreferences(\"auth\", Context.MODE_PRIVATE).edit().putString(\"access_token\", token).apply()\n}\n" },
  { lang: 'Swift', cls: 'mobile-storage', path: 'App/Auth/Session.swift', content: "func save(token: String) {\n    UserDefaults.standard.set(token, forKey: \"access_token\")\n}\n" },
  { lang: 'Dart', cls: 'mobile-storage', path: 'lib/auth/session.dart', content: "Future<void> saveToken(String token) async {\n  final prefs = await SharedPreferences.getInstance();\n  await prefs.setString('access_token', token);\n}\n" },
  { lang: 'C#', cls: 'mobile-storage', path: 'MauiApp/Services/Session.cs', content: "public void SaveToken(string token)\n{\n    Preferences.Set(\"access_token\", token);\n}\n" },

  // Mobile: cleartext / ATS off
  { lang: 'Android XML', cls: 'cleartext', path: 'app/src/main/AndroidManifest.xml', content: "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n  <application android:usesCleartextTraffic=\"true\" android:label=\"Acme\" />\n</manifest>\n" },
  { lang: 'iOS plist', cls: 'cleartext', path: 'App/Info.plist', content: "<plist version=\"1.0\"><dict>\n<key>NSAppTransportSecurity</key>\n<dict>\n<key>NSAllowsArbitraryLoads</key>\n<true/>\n</dict>\n</dict></plist>\n" },
];

async function main() {
  const rows: { lang: string; cls: string; hit: string[] }[] = [];
  for (const p of PROBES) {
    const res = await runStaticCodeScan([{ path: p.path, content: p.content }], 'probe', { keepDuplicateRules: true });
    const hit = res.findings.filter((f) => f.severity !== 'LOW' && f.severity !== 'PASSED').map((f) => `${f.ruleId}`);
    rows.push({ lang: p.lang, cls: p.cls, hit: [...new Set(hit)] });
  }
  if (process.argv.includes('--json')) { console.log(JSON.stringify(rows, null, 1)); return; }
  const miss = rows.filter((r) => r.hit.length === 0);
  for (const r of rows) console.log(`${r.hit.length ? 'OK  ' : 'MISS'} ${r.lang.padEnd(12)} ${r.cls.padEnd(15)} ${r.hit.join(',')}`);
  console.log(`\n${rows.length - miss.length}/${rows.length} caught`);
}

if (require.main === module) main();
