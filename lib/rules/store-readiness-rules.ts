/**
 * App Store and Google Play readiness (STORE-01..04, Rule IDs 9351-9354, catalog data/catalogs/mobile-security-catalog.ts).
 * Each rule keys on a build or config value the store review rejects or holds back: a template application id, a Play
 * restricted permission, an out-of-date Android target SDK, and an empty or placeholder iOS permission prompt.
 * Tests, samples and generated build output are skipped: they are not what gets uploaded.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export interface StoreReadinessRuleResult {
  findings: Finding[];
  logs: string[];
}

interface Hit { ruleId: number; code: string; title: string; severity: Finding['severity']; lineIdx: number; why: string; fix: string }

const NOT_SHIPPED = /(?:^|\/)(?:node_modules|Pods|Carthage|build|test|tests|androidTest|debug|sample|samples|example|examples|demo|fixtures?|\w+Tests)\//;
/** Template ids from Android Studio, React Native, Expo and Flutter starters; stores reject or flag them. */
const TEMPLATE_ID = /\b(?:com\.example(?:\.[\w.]+)?|com\.(?:yourcompany|mycompany|yourname|company)\.[\w.]+|org\.reactjs\.native\.example\.[\w.]+)\b/;
const ID_KEY = /\b(?:applicationId|PRODUCT_BUNDLE_IDENTIFIER|bundleIdentifier)\b|["']?package["']?\s*[:=]|\bpackage\s*=\s*["']/;
const RESTRICTED = /android\.permission\.(READ_SMS|RECEIVE_SMS|SEND_SMS|READ_CALL_LOG|WRITE_CALL_LOG|PROCESS_OUTGOING_CALLS|MANAGE_EXTERNAL_STORAGE|QUERY_ALL_PACKAGES|ACCESS_BACKGROUND_LOCATION|REQUEST_INSTALL_PACKAGES)\b/;
/** Google Play has required new apps and updates to target Android 15 (API level 35) since 31 August 2025. */
const MIN_TARGET_SDK = 35;
const PLACEHOLDER_TEXT = /^\s*(?:|todo.*|fixme.*|tbd|test|xxx+|lorem.*|placeholder.*|description|usage description)\s*$/i;

export function evaluateStoreReadinessRules(file: CodeFile, lines: string[], _cleanContent: string, findingCounter: {
  count: number;
}): StoreReadinessRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const path = file.path.replace(/\\/g, '/');
  if (NOT_SHIPPED.test(path)) return { findings, logs };
  const isManifest = /(?:^|\/)AndroidManifest\.xml$/i.test(path);
  const isGradle = /\.gradle(?:\.kts)?$/i.test(path);
  const isPlist = /(?:^|\/)Info\.plist$/i.test(path);
  const isPbx = /\.pbxproj$/i.test(path);
  const isExpo = /(?:^|\/)app\.(?:json|config\.[cm]?[jt]s)$/i.test(path);
  if (!isManifest && !isGradle && !isPlist && !isPbx && !isExpo) return { findings, logs };

  const hits: Hit[] = [];
  const isComment = (l: string) => /^\s*(?:\/\/|\*|\/\*|#|<!--)/.test(l);
  const findLine = (test: (l: string, i: number) => boolean) => lines.findIndex((l, i) => !isComment(l) && test(l, i));

  // STORE-01: the app still carries a starter template id
  const idIdx = findLine((l) => TEMPLATE_ID.test(l) && ID_KEY.test(l));
  if (idIdx >= 0) {
    hits.push({ ruleId: 9351, code: 'STORE-01', title: 'App Still Uses a Template Application ID', severity: 'HIGH', lineIdx: idIdx,
      why: 'Google Play refuses uploads whose package name starts with com.example, and an id like com.yourcompany or org.reactjs.native.example ships a placeholder that cannot be changed once the app is published.',
      fix: 'Pick the permanent reverse-domain id you own (for example com.acme.invoices) and set it in applicationId / bundleIdentifier before the first upload.' });
  }

  // STORE-02: a permission Google Play only allows with a declaration form and a core-feature reason
  if (isManifest) {
    const permIdx = findLine((l) => RESTRICTED.test(l) && /<uses-permission/.test(l) && !/tools:node\s*=\s*["']remove["']/.test(l));
    if (permIdx >= 0) {
      const perm = RESTRICTED.exec(lines[permIdx])?.[1] ?? 'restricted';
      hits.push({ ruleId: 9352, code: 'STORE-02', title: `Play Restricted Permission ${perm} Requested`, severity: 'MEDIUM', lineIdx: permIdx,
        why: `Google Play only accepts ${perm} with a permissions declaration form and a core feature that needs it; without one the release is rejected or the app is removed.`,
        fix: `Remove ${perm} if a narrower API covers the feature (photo picker, SMS Retriever, scoped storage, foreground location), or prepare the Play Console declaration before release.` });
    }
  }

  // STORE-03: Android target SDK below what Google Play accepts
  if (isGradle) {
    const sdkIdx = findLine((l) => {
      const m = /\btargetSdk(?:Version)?\s*[=(]?\s*(\d{2})\b/.exec(l);
      return !!m && Number(m[1]) < MIN_TARGET_SDK;
    });
    if (sdkIdx >= 0) {
      hits.push({ ruleId: 9353, code: 'STORE-03', title: 'Android Target SDK Too Old for Google Play', severity: 'MEDIUM', lineIdx: sdkIdx,
        why: `Google Play requires new apps and updates to target API level ${MIN_TARGET_SDK} or higher; a lower targetSdk blocks the upload.`,
        fix: `Raise targetSdk to ${MIN_TARGET_SDK} and test the behaviour changes of that Android release (edge-to-edge, foreground service types).` });
    }
  }

  // STORE-04: iOS permission prompt with no real explanation
  if (isPlist || isExpo) {
    const usageIdx = findLine((l, i) => {
      if (isPlist) {
        if (!/<key>NS\w+UsageDescription<\/key>/.test(l)) return false;
        const m = /<string>([^<]*)<\/string>/.exec(l + (lines[i + 1] || '')) ?? /<string\s*\/>/.exec(lines[i + 1] || '');
        return !!m && PLACEHOLDER_TEXT.test(m[1] ?? '');
      }
      const m = /["']?NS\w+UsageDescription["']?\s*:\s*["']([^"']*)["']/.exec(l);
      return !!m && PLACEHOLDER_TEXT.test(m[1]);
    });
    if (usageIdx >= 0) {
      hits.push({ ruleId: 9354, code: 'STORE-04', title: 'iOS Permission Prompt Is Empty or a Placeholder', severity: 'HIGH', lineIdx: usageIdx,
        why: 'App Review rejects apps whose camera, photo, location or microphone prompt does not explain why the app needs it (Guideline 5.1.1), and an empty string crashes the request on some iOS versions.',
        fix: 'Write one sentence per permission that names the feature, for example "Scan receipts with the camera to add them to an expense."' });
    }
  }

  const ts = new Date().toLocaleTimeString();
  for (const h of hits) {
    const lineNum = h.lineIdx + 1;
    findings.push({
      id: `store${h.ruleId}-${Date.now()}-${findingCounter.count++}`,
      ruleId: h.ruleId,
      type: 'VIBECARE',
      title: `${h.code}: ${h.title}`,
      severity: h.severity,
      category: 'App Store Readiness',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: (lines[h.lineIdx] || '').trim(),
      reproductionSteps: [`Scanned ${file.path}:${lineNum}.`, h.why],
      remediationPrompt: `${h.fix} (${file.path}:${lineNum})`,
      status: 'OPEN',
      owner: 'Mobile Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] [STORE] ${h.severity}: ${h.code} ${h.title} at ${file.path}:${lineNum}`);
  }
  return { findings, logs };
}
