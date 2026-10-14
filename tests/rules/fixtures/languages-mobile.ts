import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

/** Gaps closed by scripts/language-coverage.ts: Swift, Dart, Rust, C#, PHP, Ruby, Java and mobile storage. */
export const CASES: RuleCase[] = [
  {
    ruleIds: [24101],
    name: 'CORE-01 Swift SQL with string interpolation; a bound parameter is fine',
    detects: f('App/Database.swift', 'func findUser(name: String) {\n    let sql = "SELECT * FROM users WHERE name = \'\\(name)\'"\n    sqlite3_exec(db, sql, nil, nil, nil)\n}\n'),
    ignores: f('App/Database.swift', 'func findUser(name: String) {\n    let sql = "SELECT * FROM users WHERE name = ?"\n    sqlite3_prepare_v2(db, sql, -1, &stmt, nil)\n    sqlite3_bind_text(stmt, 1, name, -1, nil)\n}\n')
  },
  {
    ruleIds: [24101],
    name: 'CORE-01 Dart rawQuery with $name; whereArgs is fine',
    detects: f('lib/data/user_repo.dart', 'Future<List<Map>> findUser(String name) async {\n  return db.rawQuery("SELECT * FROM users WHERE name = \'$name\'");\n}\n'),
    ignores: f('lib/data/user_repo.dart', "Future<List<Map>> findUser(String name) async {\n  return db.rawQuery('SELECT * FROM users WHERE name = ?', [name]);\n}\n")
  },
  {
    ruleIds: [24102],
    name: 'CORE-02 Rust sh -c with format!; an argument list is fine',
    detects: f('src/ping.rs', 'async fn ping(Query(q): Query<Host>) -> String {\n    let out = Command::new("sh").arg("-c").arg(format!("ping -c 1 {}", q.host)).output().unwrap();\n    String::from_utf8_lossy(&out.stdout).to_string()\n}\n'),
    ignores: f('src/ping.rs', 'async fn ping(Query(q): Query<Host>) -> String {\n    let out = Command::new("ping").args(["-c", "1", &q.host]).output().unwrap();\n    String::from_utf8_lossy(&out.stdout).to_string()\n}\n')
  },
  {
    ruleIds: [24109],
    name: 'CORE-09 Dart badCertificateCallback returns true; a pinned check is fine',
    detects: f('lib/net/client.dart', 'HttpClient createClient() {\n  final client = HttpClient();\n  client.badCertificateCallback = (cert, host, port) => true;\n  return client;\n}\n'),
    ignores: f('lib/net/client.dart', 'HttpClient createClient() {\n  final client = HttpClient();\n  client.badCertificateCallback = (cert, host, port) => cert.sha1.toString() == pinnedSha1;\n  return client;\n}\n')
  },
  {
    ruleIds: [24109],
    name: 'CORE-09 C# validation callback returns true; the default handler is fine',
    detects: f('Services/ApiClient.cs', 'var handler = new HttpClientHandler();\nhandler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;\nvar client = new HttpClient(handler);\n'),
    ignores: f('Services/ApiClient.cs', 'var handler = new HttpClientHandler();\nhandler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => errors == SslPolicyErrors.None;\nvar client = new HttpClient(handler);\n')
  },
  {
    ruleIds: [24109],
    name: 'CORE-09 PHP curl VERIFYPEER false; verification on is fine',
    detects: f('src/Http.php', "<?php\n$ch = curl_init($url);\ncurl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\n$body = curl_exec($ch);\n"),
    ignores: f('src/Http.php', "<?php\n$ch = curl_init($url);\ncurl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);\n$body = curl_exec($ch);\n")
  },
  {
    ruleIds: [24109],
    name: 'CORE-09 Ruby VERIFY_NONE; VERIFY_PEER is fine',
    detects: f('lib/api_client.rb', "http = Net::HTTP.new(uri.host, uri.port)\nhttp.use_ssl = true\nhttp.verify_mode = OpenSSL::SSL::VERIFY_NONE\n"),
    ignores: f('lib/api_client.rb', "http = Net::HTTP.new(uri.host, uri.port)\nhttp.use_ssl = true\nhttp.verify_mode = OpenSSL::SSL::VERIFY_PEER\n")
  },
  {
    ruleIds: [24110],
    name: 'CORE-10 Java request param in Paths.get; a normalized startsWith check is fine',
    detects: f('src/main/java/app/FileController.java', '@GetMapping("/files")\npublic byte[] download(@RequestParam String name) throws Exception {\n    return Files.readAllBytes(Paths.get("uploads", name));\n}\n'),
    ignores: f('src/main/java/app/FileController.java', '@GetMapping("/files")\npublic byte[] download(@RequestParam String name) throws Exception {\n    Path p = Paths.get("uploads").resolve(name).normalize();\n    if (!p.normalize().startsWith(Paths.get("uploads"))) throw new SecurityException();\n    return Files.readAllBytes(p);\n}\n')
  },
  {
    ruleIds: [24110],
    name: 'CORE-10 C# action parameter in Path.Combine; Path.GetFileName is fine',
    detects: f('Controllers/FilesController.cs', '[HttpGet]\npublic IActionResult Download(string name)\n{\n    return PhysicalFile(Path.Combine("/app/uploads", name), "application/octet-stream");\n}\n'),
    ignores: f('Controllers/FilesController.cs', '[HttpGet]\npublic IActionResult Download(string name)\n{\n    return PhysicalFile(Path.Combine("/app/uploads", Path.GetFileName(name)), "application/octet-stream");\n}\n')
  },
  {
    ruleIds: [24110],
    name: 'CORE-10 PHP readfile with $_GET; basename() is fine',
    detects: f('public/download.php', "<?php\nreadfile('uploads/' . $_GET['name']);\n"),
    ignores: f('public/download.php', "<?php\nreadfile('uploads/' . basename($_GET['name']));\n")
  },
  {
    ruleIds: [9301],
    name: 'MOB-SEC-01 Flutter token in SharedPreferences; flutter_secure_storage is fine',
    detects: f('lib/auth/session.dart', "Future<void> saveToken(String token) async {\n  final prefs = await SharedPreferences.getInstance();\n  await prefs.setString('access_token', token);\n}\n"),
    ignores: f('lib/auth/session.dart', "const storage = FlutterSecureStorage();\nFuture<void> saveToken(String token) async {\n  await storage.write(key: 'access_token', value: token);\n}\n")
  },
  {
    ruleIds: [9301],
    name: 'MOB-SEC-01 MAUI token in Preferences; SecureStorage is fine',
    detects: f('MauiApp/Services/Session.cs', 'public void SaveToken(string token)\n{\n    Preferences.Set("access_token", token);\n}\n'),
    ignores: f('MauiApp/Services/Session.cs', 'public async Task SaveToken(string token)\n{\n    await SecureStorage.Default.SetAsync("access_token", token);\n    Preferences.Set("theme", "dark");\n}\n')
  }
];
