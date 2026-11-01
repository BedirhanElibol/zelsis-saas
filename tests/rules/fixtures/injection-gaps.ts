import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

const JAVA = 'import javax.servlet.http.*;\nimport javax.naming.*;\nimport java.io.*;\nimport java.util.zip.*;\nimport javax.crypto.spec.*;\n';
const ANDROID = 'package a;\nimport android.app.Activity;\nimport android.content.*;\nimport android.webkit.*;\n';

export const CASES: RuleCase[] = [
  {
    ruleIds: [31001], name: 'IGAP-01 Java zip entry name as a write path vs a canonical path check',
    detects: f('src/main/java/I.java', JAVA + 'public class I {\n  void z(ZipInputStream in, File d) throws Exception {\n    ZipEntry e = in.getNextEntry();\n    new FileOutputStream(new File(d, e.getName()));\n  }\n}\n'),
    ignores: f('src/main/java/I.java', JAVA + 'public class I {\n  void z(ZipInputStream in, File d) throws Exception {\n    ZipEntry e = in.getNextEntry();\n    File t = new File(d, e.getName());\n    if (!t.getCanonicalPath().startsWith(d.getCanonicalPath())) throw new IOException();\n    new FileOutputStream(t);\n  }\n}\n'),
  },
  {
    ruleIds: [31001], name: 'IGAP-01 Go zip entry joined to the target vs filepath.IsLocal',
    detects: f('internal/unzip.go', 'package x\nimport ("archive/zip"; "path/filepath")\nfunc u(dest string) {\n\tr, _ := zip.OpenReader("a.zip")\n\tfor _, f := range r.File {\n\t\tp := filepath.Join(dest, f.Name)\n\t\t_ = p\n\t}\n}\n'),
    ignores: f('internal/unzip.go', 'package x\nimport ("archive/zip"; "path/filepath")\nfunc u(dest string) {\n\tr, _ := zip.OpenReader("a.zip")\n\tfor _, f := range r.File {\n\t\tif !filepath.IsLocal(f.Name) { continue }\n\t\tp := filepath.Join(dest, f.Name)\n\t\t_ = p\n\t}\n}\n'),
  },
  {
    ruleIds: [31001], name: 'IGAP-01 Python tarfile extractall vs the data filter',
    detects: f('app/unpack.py', 'import tarfile\ndef u(p, d):\n    with tarfile.open(p) as t:\n        t.extractall(d)\n'),
    ignores: f('app/unpack.py', 'import tarfile\ndef u(p, d):\n    with tarfile.open(p) as t:\n        t.extractall(d, filter="data")\n'),
  },
  {
    ruleIds: [31002], name: 'IGAP-02 literal IV in Java vs a random IV',
    detects: f('src/main/java/W.java', JAVA + 'public class W {\n  IvParameterSpec i = new IvParameterSpec("1234567890123456".getBytes());\n}\n'),
    ignores: f('src/main/java/W.java', JAVA + 'public class W {\n  IvParameterSpec i(byte[] iv) { return new IvParameterSpec(iv); }\n}\n'),
  },
  {
    ruleIds: [31002], name: 'IGAP-02 zero IV in Node vs randomBytes',
    detects: f('src/crypto.ts', 'import { createCipheriv } from "node:crypto";\nexport const c = (k: Buffer) => createCipheriv("aes-256-cbc", k, Buffer.alloc(16));\n'),
    ignores: f('src/crypto.ts', 'import { createCipheriv, randomBytes } from "node:crypto";\nexport const c = (k: Buffer) => createCipheriv("aes-256-gcm", k, randomBytes(12));\n'),
  },
  {
    ruleIds: [31003], name: 'IGAP-03 JNDI lookup of a request value vs a fixed name',
    detects: f('src/main/java/H.java', JAVA + 'public class H extends HttpServlet {\n  protected void doGet(HttpServletRequest r, HttpServletResponse s) throws Exception {\n    new InitialContext().lookup(r.getParameter("n"));\n  }\n}\n'),
    ignores: f('src/main/java/H.java', JAVA + 'public class H extends HttpServlet {\n  protected void doGet(HttpServletRequest r, HttpServletResponse s) throws Exception {\n    new InitialContext().lookup("java:comp/env/jdbc/app");\n  }\n}\n'),
  },
  {
    ruleIds: [31004], name: 'IGAP-04 XPath built from request input vs a bound variable',
    detects: f('app/views.py', 'from flask import request\ndef f(tree):\n    return tree.xpath("//u[name=\'" + request.args.get("n") + "\']")\n'),
    ignores: f('app/views.py', 'from flask import request\ndef f(tree):\n    return tree.xpath("//u[name=$n]", n=request.args.get("n"))\n'),
  },
  {
    ruleIds: [31005], name: 'IGAP-05 printf of argv vs a literal format',
    detects: f('src/l.c', '#include <stdio.h>\nint main(int c, char **argv) {\n  printf(argv[1]);\n  return 0;\n}\n'),
    ignores: f('src/l.c', '#include <stdio.h>\nint main(int c, char **argv) {\n  printf("%s", argv[1]);\n  printf(USAGE);\n  return 0;\n}\n'),
  },
  {
    ruleIds: [31006], name: 'IGAP-06 JS WebView loads an Intent URL vs a fixed URL',
    detects: f('app/src/main/java/P.java', ANDROID + 'public class P extends Activity {\n  void w(WebView v) {\n    v.getSettings().setJavaScriptEnabled(true);\n    v.loadUrl(getIntent().getStringExtra("u"));\n  }\n}\n'),
    ignores: f('app/src/main/java/P.java', ANDROID + 'public class P extends Activity {\n  void w(WebView v) {\n    v.getSettings().setJavaScriptEnabled(true);\n    v.loadUrl("https://example.com/help");\n  }\n}\n'),
  },
  {
    ruleIds: [31007], name: 'IGAP-07 forwarded Intent from extras vs an explicit new Intent',
    detects: f('app/src/main/java/R.java', ANDROID + 'public class R extends Activity {\n  void f() {\n    Intent next = (Intent) getIntent().getParcelableExtra("next");\n    startActivity(next);\n  }\n}\n'),
    ignores: f('app/src/main/java/R.java', ANDROID + 'public class R extends Activity {\n  void f() {\n    Intent next = new Intent(this, HomeActivity.class);\n    startActivity(next);\n  }\n}\n'),
  },
  {
    ruleIds: [31008], name: 'IGAP-08 Struts devMode true vs false',
    detects: f('src/main/resources/struts.xml', '<?xml version="1.0"?>\n<struts>\n  <constant name="struts.devMode" value="true"/>\n</struts>\n'),
    ignores: f('src/main/resources/struts.xml', '<?xml version="1.0"?>\n<struts>\n  <constant name="struts.devMode" value="false"/>\n</struts>\n'),
  },
  {
    ruleIds: [31009], name: 'IGAP-09 Sinatra protection off vs one excepted check',
    detects: f('app.rb', "require 'sinatra'\ndisable :protection\nget('/') { 'x' }\n"),
    ignores: f('app.rb', "require 'sinatra'\nset :protection, except: :frame_options\nget('/') { 'x' }\n"),
  },
  {
    ruleIds: [31010], name: 'IGAP-10 Django empty password validators vs configured ones',
    detects: f('proj/settings.py', "DEBUG = False\nINSTALLED_APPS = ['django.contrib.auth']\nAUTH_PASSWORD_VALIDATORS = []\n"),
    ignores: f('proj/settings.py', "DEBUG = False\nINSTALLED_APPS = ['django.contrib.auth']\nAUTH_PASSWORD_VALIDATORS = [{'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'}]\n"),
  },
];
