/**
 * Native and React Native mobile app security (MOB-SEC-04, 06, 09..18; Rule IDs 9304-9318, catalog
 * data/catalogs/mobile-security-catalog.ts). Each rule keys on a call or setting that is wrong wherever it
 * appears in shipped app code: disabled TLS checks, file-URL WebView access, ECB / DES ciphers, deep links
 * loaded into a WebView, debuggable manifests, secrets in logs, always-readable Keychain items, SQL built
 * from strings, tokens in AsyncStorage, world-readable files and FileProvider root paths.
 * Tests, debug source sets and sample code are skipped: they are not what ships to the store.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export interface MobileNativeRuleResult {
  findings: Finding[];
  logs: string[];
}

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; category: string; lineIdx: number; why: string; fix: string }

/** Rules with an Android and an iOS variant share one definition (one id, one title). */
const TLS_OFF = { ruleId: 9304, code: 'MOB-SEC-04', severity: 'HIGH' as const, category: 'Mobile Network Security', title: 'TLS Certificate Validation Disabled' };
const WEBVIEW_FILES = { ruleId: 9306, code: 'MOB-SEC-06', severity: 'HIGH' as const, category: 'Mobile WebView Security', title: 'WebView Lets file:// Pages Read Local Files' };
const SECRET_LOG = { ruleId: 9312, code: 'MOB-SEC-12', severity: 'MEDIUM' as const, category: 'Mobile Data Leakage', title: 'Secret Written to the Device Log' };

const isComment = (l: string) => /^\s*(?:\/\/|\*|\/\*|#|<!--)/.test(l);
/** Paths that never ship in the release build. */
const NOT_SHIPPED = /(?:^|\/)(?:test|tests|androidTest|testDebug|debug|sample|samples|example|examples|demo|Tests|UITests|\w+Tests|\w+UITests|fastlane)\//;
const SECRET_NAME = /(?:password|passwd|token|secret|api_?key|apikey|credential|session_?id|private_?key)/i;

export function evaluateMobileNativeRules(file: CodeFile, lines: string[], cleanContent: string, findingCounter: {
  count: number;
}): MobileNativeRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (/(?:^|\/)(?:node_modules|Pods|Carthage|build)\//.test(path) || NOT_SHIPPED.test(path)) return { findings, logs };
  const isKotlin = /\.kts?$/i.test(path);
  const isJava = /\.java$/i.test(path);
  const isAndroidCode = isKotlin || isJava;
  const isSwift = /\.swift$/i.test(path);
  const isObjC = /\.mm?$/i.test(path);
  const isManifest = /(?:^|\/)AndroidManifest\.xml$/i.test(path);
  const isAndroidXml = /(?:^|\/)res\/xml\/[^/]+\.xml$/i.test(path);
  const isJs = /\.[cm]?[jt]sx?$/i.test(path) && !/\.d\.ts$/i.test(path);
  if (!isAndroidCode && !isSwift && !isObjC && !isManifest && !isAndroidXml && !isJs) return { findings, logs };

  const hits: Hit[] = [];
  const add = (h: Hit) => { if (h.lineIdx >= 0 && !hits.some((x) => x.ruleId === h.ruleId && x.lineIdx === h.lineIdx)) hits.push(h); };
  const findLine = (re: RegExp) => lines.findIndex((l) => !isComment(l) && re.test(l));
  /** Inside if (BuildConfig.DEBUG) / #if DEBUG a few lines up: compiled out of or skipped in release builds. */
  const debugOnly = (i: number) => lines.slice(Math.max(0, i - 3), i).some((l) => /\bif\s*\(?\s*(?:BuildConfig\.)?DEBUG\b|#if\s+DEBUG\b/.test(l));

  if (isAndroidCode) {
    // MOB-SEC-04: TLS certificate or hostname checks turned off
    let tlsIdx = -1;
    lines.forEach((l, i) => {
      if (tlsIdx >= 0 || isComment(l)) return;
      if (/\bcheckServerTrusted\s*\(/.test(l) && /\b(?:override\s+fun|public\s+void|fun)\b/.test(l)) {
        // Empty body: the next code after the opening brace is the closing brace
        const body = lines.slice(i, i + 4).join('\n');
        if (/\{\s*(?:\/\/[^\n]*\s*)*\}/.test(body.slice(body.indexOf('{')))) tlsIdx = i;
      } else if (/HostnameVerifier\s*\{\s*_?\w*\s*,\s*_?\w*\s*->\s*true\s*\}|hostnameVerifier\s*\{\s*_\s*,\s*_\s*->\s*true\s*\}|\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*true|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier/.test(l) && /hostname|verif/i.test(l)) {
        tlsIdx = i;
      } else if (/\bonReceivedSslError\s*\(/.test(l) && /\.proceed\s*\(\s*\)/.test(lines.slice(i, i + 4).join('\n')) && !/\.cancel\s*\(\s*\)/.test(lines.slice(i, i + 8).join('\n'))) {
        tlsIdx = i;
      }
    });
    add({ ...TLS_OFF, lineIdx: tlsIdx,
      why: 'The app accepts any certificate or hostname, so anyone on the same Wi-Fi can impersonate your API and read or change tokens and personal data in transit.',
      fix: 'Remove the trust-all TrustManager / HostnameVerifier / SslErrorHandler.proceed(). Use the platform defaults, and a network_security_config.xml with certificate pins for critical hosts.' });

    // MOB-SEC-06: WebView may read local files from file:// pages
    add({ ...WEBVIEW_FILES, lineIdx: findLine(/(?:setAllow(?:Universal|File)AccessFromFileURLs\s*\(\s*true\s*\)|allow(?:Universal|File)AccessFromFileURLs\s*=\s*true)/),
      why: 'With file-URL access on, any HTML the WebView opens from storage can read the app\'s private files (tokens, databases) and send them to a remote server.',
      fix: 'Leave allowFileAccessFromFileURLs and allowUniversalAccessFromFileURLs false (the default); serve local content through WebViewAssetLoader instead.' });

    // MOB-SEC-10: deep-link / intent URL loaded straight into a WebView
    {
      // The deep-link data URI; extras are mostly the app passing URLs to itself
      const fromIntent = /\b(?:getIntent\(\)|intent\??)\.(?:getData\(\)|data\b|getDataString\(\)|dataString\b)/;
      const tainted = new Set<string>();
      lines.forEach((l) => { const m = l.match(/\b(?:val|var|String|Uri)\s+(\w+)\s*(?::\s*[\w?]+)?\s*=\s*(.*)/); if (m && fromIntent.test(m[2])) tainted.add(m[1]); });
      const idx = lines.findIndex((l) => {
        if (isComment(l)) return false;
        const m = l.match(/\.loadUrl\s*\(([^)]*)\)/);
        if (!m) return false;
        return fromIntent.test(m[1]) || [...tainted].some((v) => new RegExp(String.raw`\b${v}\b`).test(m[1]));
      });
      const checked = /(?:host|scheme|authority)\s*(?:==|!=|\.equals|in\s|\bin\b)|startsWith\(\s*"https:\/\/[\w.-]+/.test(cleanContent);
      if (!checked) add({ ruleId: 9310, code: 'MOB-SEC-10', severity: 'HIGH', category: 'Mobile Deep Links', lineIdx: idx,
        title: 'Deep-Link URL Loaded Into a WebView Without a Host Check',
        why: 'Any app or web page can open this activity with a URL of its choice, so the WebView loads attacker pages with your app\'s JavaScript bridges, cookies and login state.',
        fix: 'Parse the URL and only load it when its scheme is https and its host is on an allowlist you control; open anything else in the browser.' });
    }

    // MOB-SEC-12: secrets written to Logcat
    add({ ...SECRET_LOG, lineIdx: lines.findIndex((l, i) => {
      if (isComment(l) || debugOnly(i)) return false;
      const m = l.match(/\b(?:Log|Timber)\.[vdiwe]\s*\((.*)/);
      if (!m) return false;
      const outside = m[1].replace(/"(?:[^"\\]|\\.)*"/g, (s) => (/\$\{?\w/.test(s) ? s.replace(/^"|"$/g, ' ') : '""'));
      return /[$+]\s*\{?\s*[\w.?]*(?:password|passwd|token|secret|apiKey|api_key)\w*/i.test(outside) || /,\s*[\w.]*(?:password|token|secret)\w*\s*\)/i.test(outside);
    }),
      why: 'Logcat output is collected by crash reporters and readable over adb, so tokens and passwords in log lines end up outside the app.',
      fix: 'Remove the value from the log message, or log only in debug builds (if (BuildConfig.DEBUG)) and never the secret itself.' });

    // MOB-SEC-14: SQLite query built from strings (schema migrations work on the app's own data)
    const isMigration = /migration|upgrad/i.test(path);
    // Only when a variable is spliced in: TABLE_NAME / KEY_* constants in schema migrations are fixed SQL
    add({ ruleId: 9314, code: 'MOB-SEC-14', severity: 'HIGH', category: 'Mobile Injection', title: 'SQLite Query Built by String Concatenation', lineIdx: lines.findIndex((l, i) => {
      if (isMigration || isComment(l) || !/\b(?:rawQuery|execSQL)\s*\(/.test(l)) return false;
      const call = lines.slice(i, i + 6).join(' ');
      // The call's arguments only, so the execSQL( token itself is never read as a spliced value
      const callAt = call.search(/\b(?:rawQuery|execSQL)\s*\(/);
      const stmt = call.slice(call.indexOf('(', callAt) + 1, call.includes(';') ? call.indexOf(';') : undefined);
      const spliced = [
        ...[...stmt.replace(/"(?:[^"\\]|\\.)*"/g, '""').matchAll(/\+\s*([\w.]+(?:\([^()"]*\))?)|([\w.]+(?:\([^()"]*\))?)\s*\+/g)].map((m) => m[1] || m[2]),
        ...[...stmt.matchAll(/"(?:[^"\\]|\\.)*"/g)].flatMap((s) => [...s[0].matchAll(/\$\{?([\w.]+)/g)].map((m) => m[1])),
      ];
      // Constants (TABLE_NAME, KEY_X, NAME_v2) and numeric ids / counts are not attacker-controlled text
      return spliced.some((v) => {
        const last = (v.replace(/\(.*$/, '').split('.').pop() || '').replace(/_v\d+$/, '');
        return /[a-z]/.test(last) && !/^(?:length|size|toString|count|index|position|offset|limit|\w*(?:Id|Ids|ID|Count|Index|Version|Timestamp|Time))$/.test(last) && !/^(?:id|ids)$/i.test(last);
      });
    }),
      why: 'A value from the user, a deep link or a server response becomes part of the SQL, so it can read or delete other rows in the local database.',
      fix: 'Pass values as selection arguments: rawQuery("SELECT * FROM notes WHERE id = ?", arrayOf(id)), or use Room / query() with ? placeholders.' });

    // MOB-SEC-16: world-readable / world-writable files
    add({ ruleId: 9316, code: 'MOB-SEC-16', severity: 'HIGH', category: 'Mobile Data Storage', lineIdx: findLine(/\bMODE_WORLD_(?:READABLE|WRITEABLE)\b/),
      title: 'File or Preferences Created World-Readable',
      why: 'Every other app on the device can read (or overwrite) this file; on Android 7+ the call also throws a SecurityException.',
      fix: 'Use Context.MODE_PRIVATE, and share data with other apps only through a FileProvider with explicit grants.' });
  }

  if (isKotlin || isSwift || isObjC) {
    // MOB-SEC-09: ECB mode or DES / 3DES (Java is covered by JAVA-SEC-05)
    add({ ruleId: 9309, code: 'MOB-SEC-09', severity: 'HIGH', category: 'Mobile Cryptography', lineIdx: findLine(isKotlin
      ? /Cipher\.getInstance\s*\(\s*"(?:AES|DES[^"]*|DESede[^"]*|RC4|(?!RSA\/)[^"]*\/ECB\/[^"]*)"\s*\)/
      : /\bkCCOptionECBMode\b|\bkCCAlgorithm(?:DES|3DES|RC4)\b|\.ecb\b(?=\s*[,)])/),
      title: 'Weak Encryption Mode or Cipher (ECB / DES)',
      why: 'ECB encrypts equal blocks to equal output, so patterns in the data stay visible, and DES / 3DES / RC4 keys can be broken. Plain "AES" on Android defaults to ECB.',
      fix: 'Use AES-GCM (Cipher.getInstance("AES/GCM/NoPadding") on Android, CryptoKit AES.GCM on iOS) with a random nonce per message.' });
  }

  if (isSwift || isObjC) {
    // MOB-SEC-04 (iOS): server trust accepted without evaluating it
    {
      const idx = findLine(/completionHandler\s*\(\s*\.useCredential\s*,\s*URLCredential\s*\(\s*trust\s*:|NSURLSessionAuthChallengeUseCredential\s*,\s*\[NSURLCredential\s+credentialForTrust/);
      if (idx >= 0 && !/SecTrustEvaluate(?:WithError)?\s*\(|evaluate(?:Trust)?\s*\(|pinn?ed|pinning|publicKeyHash|certificateHash/i.test(cleanContent)) {
        add({ ...TLS_OFF, lineIdx: idx,
          why: 'The session delegate hands back the server\'s trust without evaluating it, so any certificate is accepted and anyone on the network can read and change the traffic.',
          fix: 'Call SecTrustEvaluateWithError (and compare pinned key hashes if you pin) before .useCredential; otherwise use .performDefaultHandling.' });
      }
    }

    // MOB-SEC-06 (iOS): WKWebView file-URL access switched on through private keys
    add({ ...WEBVIEW_FILES, lineIdx: findLine(/setValue\s*\(\s*(?:true|@?YES|NSNumber\(value:\s*true\))\s*,\s*forKey\s*:\s*@?"allow(?:Universal|File)AccessFromFileURLs"/),
      why: 'With file-URL access on, a local HTML file can read the app container (tokens, databases) and send it anywhere.',
      fix: 'Remove the allowFileAccessFromFileURLs / allowUniversalAccessFromFileURLs override; load local files with loadFileURL(_:allowingReadAccessTo:) scoped to one folder.' });

    // MOB-SEC-12 (iOS): secrets printed to the console
    add({ ...SECRET_LOG, lineIdx: lines.findIndex((l, i) => {
      if (isComment(l) || debugOnly(i)) return false;
      const m = l.match(/\b(?:print|debugPrint|NSLog|os_log|logger\.\w+)\s*\((.*)/);
      return Boolean(m && /\\\(\s*[\w.]*(?:password|token|secret|apiKey)\w*\s*\)|"[^"]*%@[^"]*"\s*,\s*[\w.]*(?:password|token|secret|apiKey)/i.test(m[1]));
    }),
      why: 'Console output ends up in sysdiagnoses and crash logs, so tokens and passwords printed there leave the app.',
      fix: 'Do not print the value; with os_log / Logger mark it privacy: .private, or log only in DEBUG builds.' });

    // MOB-SEC-18: credentials put in a dictionary that is written to a plain file (plist in Documents)
    if (/\.write\s*\(\s*to(?:File)?\s*:/.test(cleanContent)) {
      add({ ruleId: 9318, code: 'MOB-SEC-18', severity: 'HIGH', category: 'Mobile Data Storage', lineIdx: findLine(/(?:setValue|setObject)\s*\([^)]*forKey\s*:\s*@?"(?:password|passwd|pin|token|access_?token|refresh_?token|auth_?token|secret|api_?key)"|\[\s*@?"(?:password|token|access_?token|secret|api_?key)"\s*\]\s*=/i),
        title: 'Credentials Saved to a Plain File',
        why: 'The dictionary is written to a plist / file in the app container without encryption, so the password or token can be read from an unencrypted backup or a jailbroken device.',
        fix: 'Store credentials in the Keychain (kSecAttrAccessibleWhenUnlockedThisDeviceOnly); keep only non-secret settings in plist files.' });
    }

    // MOB-SEC-13: Keychain item readable while the device is locked
    add({ ruleId: 9313, code: 'MOB-SEC-13', severity: 'MEDIUM', category: 'Mobile Data Storage', lineIdx: findLine(/\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b/),
      title: 'Keychain Item Readable While the Device Is Locked',
      why: 'kSecAttrAccessibleAlways keeps the secret decryptable even when the phone is locked; Apple deprecated it for that reason.',
      fix: 'Use kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly (background access) or kSecAttrAccessibleWhenUnlockedThisDeviceOnly.' });
  }

  if (isManifest) {
    // MOB-SEC-11: release manifest marked debuggable
    add({ ruleId: 9311, code: 'MOB-SEC-11', severity: 'HIGH', category: 'Mobile Build Configuration', lineIdx: findLine(/android:debuggable\s*=\s*"true"/),
      title: 'App Manifest Marked Debuggable',
      why: 'A debuggable build lets anyone with the phone attach a debugger, run code as your app and read its private files and tokens.',
      fix: 'Remove android:debuggable from AndroidManifest.xml; Gradle sets it for debug builds only.' });
  }

  if (isAndroidXml) {
    // MOB-SEC-17: FileProvider shares the whole filesystem
    add({ ruleId: 9317, code: 'MOB-SEC-17', severity: 'MEDIUM', category: 'Mobile Data Storage', lineIdx: /<paths\b/.test(cleanContent) ? findLine(/<root-path\b/) : -1,
      title: 'FileProvider Exposes the Device Root',
      why: '<root-path> lets a content:// URI point at any file the app can read, including its databases and shared preferences, once a grant leaks.',
      fix: 'Replace <root-path> with the narrowest folder you share, such as <cache-path name="shared" path="shared/" />.' });
  }

  if (isJs && /@react-native-async-storage\/async-storage|from\s+['"]react-native['"]/.test(cleanContent)) {
    // MOB-SEC-15: auth tokens in unencrypted AsyncStorage
    add({ ruleId: 9315, code: 'MOB-SEC-15', severity: 'HIGH', category: 'Mobile Data Storage', lineIdx: lines.findIndex((l) => {
      if (isComment(l)) return false;
      const m = l.match(/AsyncStorage\.(?:setItem|multiSet)\s*\(\s*([^,]+),/);
      return Boolean(m && SECRET_NAME.test(m[1]) && !/expires|timestamp|remember|onboard/i.test(m[1]));
    }),
      title: 'Auth Token Stored in Unencrypted AsyncStorage',
      why: 'AsyncStorage is a plain file (SQLite / JSON) in the app sandbox, readable from backups and on rooted or jailbroken devices.',
      fix: 'Store tokens with expo-secure-store or react-native-keychain (Keychain / Android Keystore); keep only non-secret settings in AsyncStorage.' });
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `mob${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'SECURITY',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: h.category,
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Mobile Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [MOBILE] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
