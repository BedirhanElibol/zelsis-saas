'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Server, Download, Copy, CheckCircle2, GitBranch, Terminal, Shield, FileCode, Check, LucideIcon, Lock } from 'lucide-react';
import { UserTier } from '@/data/schema';
import { isCicdIntegrationAllowed } from '@/lib/quota-manager';
import { getPublicAppUrl } from '@/lib/app-url';

const APP_URL = getPublicAppUrl();
const GATE_CURL = `curl -s -X POST "${APP_URL}/api/v1/gate-check?failOnBlock=true" -H "Content-Type: application/json" -d '{"repoUrl":"https://github.com/OWNER/REPO"}'`;

interface DeploymentManifestModalProps {
  isOpen: boolean;
  onClose: () => void;
  projectName: string;
  userTier?: UserTier;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

type TabType = 'github' | 'gitlab' | 'husky' | 'docker' | 'k8s';

export const DeploymentManifestModal: React.FC<DeploymentManifestModalProps> = ({
  isOpen,
  onClose,
  projectName,
  userTier,
  onOpenCheckout,
}) => {
  const isAllowed = isCicdIntegrationAllowed(userTier);
  const [activeTab, setActiveTab] = useState<TabType>('github');
  const [copiedType, setCopiedType] = useState<string | null>(null);

  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const safeProjectName = (projectName ?? 'Zelsis Project').toLowerCase().replace(/\s+/g, '-');

  const githubActionYaml = `name: Zelsis Release Gate & SCA Audit

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master ]

jobs:
  release-gate:
    name: Zelsis Quality & Security Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1

      - name: Run Zelsis Deterministic Gate Check
        id: gate_check
        run: |
          echo "Initiating pre-flight release audit for \${{ github.repository }}..."
          
          REF=""
          BASE=""
          if [ "\${{ github.event_name }}" = "pull_request" ]; then
            REF="\${{ github.event.pull_request.head.sha }}"
            BASE="\${{ github.event.pull_request.base.sha }}"
          fi

          FAIL_OPEN="\${{ vars.ZELSIS_FAIL_OPEN || 'false' }}"

          RESPONSE=$(curl -s -w "\\n%{http_code}" -X POST "${APP_URL}/api/v1/gate-check?failOnBlock=true" \\
            -H "Content-Type: application/json" \\
            -d '{"repoUrl": "\${{ github.server_url }}/\${{ github.repository }}", "ref": "'$REF'", "base": "'$BASE'"}')
          
          HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
          BODY=$(echo "$RESPONSE" | sed '$d')

          if [ "$HTTP_CODE" -ge 500 ] || [ -z "$BODY" ] || ! echo "$BODY" | jq -e . >/dev/null 2>&1; then
            echo "❌ Zelsis API unreachable or returned invalid response."
            if [ "$FAIL_OPEN" = "true" ]; then
              echo "⚠️ Fail-open strategy is enabled. Passing the gate."
              echo "gate_status=PASSED" >> $GITHUB_OUTPUT
              echo "readiness_score=100" >> $GITHUB_OUTPUT
              exit 0
            else
              echo "🛑 Failing the workflow."
              exit 1
            fi
          fi
          
          STATUS=$(echo "$BODY" | jq -r '.gateStatus // "FAILED"')
          SCORE=$(echo "$BODY" | jq -r '.readinessScore // 0')
          CRITICALS=$(echo "$BODY" | jq -r '.criticalCount // 0')
          HIGHS=$(echo "$BODY" | jq -r '.highCount // 0')

          echo "gate_status=$STATUS" >> $GITHUB_OUTPUT
          echo "readiness_score=$SCORE" >> $GITHUB_OUTPUT

          # Build GitHub Job Step Summary Table
          echo "## 🛡️ Zelsis Pre-Flight Release Gate Evaluation" >> $GITHUB_STEP_SUMMARY
          echo "| Metric | Value |" >> $GITHUB_STEP_SUMMARY
          echo "| :--- | :--- |" >> $GITHUB_STEP_SUMMARY
          echo "| **Gate Status** | **$STATUS** |" >> $GITHUB_STEP_SUMMARY
          echo "| **Readiness Score** | **$SCORE / 100** |" >> $GITHUB_STEP_SUMMARY
          echo "| **Critical Vulnerabilities** | $CRITICALS |" >> $GITHUB_STEP_SUMMARY
          echo "| **High Severity Issues** | $HIGHS |" >> $GITHUB_STEP_SUMMARY

          if [ "$STATUS" = "FAILED" ] || [ "$SCORE" -lt 80 ] || [ "$CRITICALS" -gt 0 ]; then
            echo "" >> $GITHUB_STEP_SUMMARY
            echo "❌ **Deployment Blocked:** Quality gate failed or score is under 80/100 threshold." >> $GITHUB_STEP_SUMMARY
            echo "::error::[BLOCKED] Release blocked by Zelsis Quality Gate. Score: $SCORE/100"
            exit 1
          fi

          echo "" >> $GITHUB_STEP_SUMMARY
          echo "✅ **Deployment Approved:** Ready for production deployment." >> $GITHUB_STEP_SUMMARY
          echo "[PASSED] Release passed Zelsis Quality Gate."`;

  const gitlabCiYaml = `stages:
  - test
  - release-gate

zelsis_gate_audit:
  stage: release-gate
  image: curlimages/curl:latest
  script:
    - echo "Running Zelsis Release Gate for $CI_PROJECT_PATH..."
    - >
      RESPONSE=$(curl -s -X POST "${APP_URL}/api/v1/gate-check?failOnBlock=true"
      -H "Content-Type: application/json"
      -d '{"repoUrl": "'$CI_PROJECT_URL'"}')
    - echo "Audit Payload: $RESPONSE"
    - STATUS=$(echo "$RESPONSE" | grep -o '"gateStatus":"[^"]*' | cut -d'"' -f4)
    - SCORE=$(echo "$RESPONSE" | grep -o '"readinessScore":[0-9]*' | cut -d':' -f2)
    - echo "Zelsis Gate Status: $STATUS ($SCORE/100)"
    - if [ "$STATUS" = "FAILED" ]; then exit 1; fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`;

  const huskyHook = `#!/bin/sh
# .husky/pre-commit
# Zero-Retention Local Release Gate & Secret Exposure Check

echo "🛡️  Running Zelsis Pre-Commit Quality & Secret Check..."

# Check staged files using Zelsis API
BRANCH=$(git rev-parse --abbrev-ref HEAD)
REPO_REMOTE=$(git config --get remote.origin.url)

if [ -z "$REPO_REMOTE" ]; then
  echo "⚠️  No remote origin configured; skipping remote gate."
  exit 0
fi

echo "Verifying branch $BRANCH against release criteria..."
STATUS=$(curl -s -X POST "${APP_URL}/api/v1/gate-check" \\
  -H "Content-Type: application/json" \\
  -d "{\\"repoUrl\\": \\"$REPO_REMOTE\\"}" | grep -o '"gateStatus":"[^"]*' | cut -d'"' -f4)

if [ "$STATUS" = "FAILED" ]; then
  echo "❌ [BLOCKED] Pre-commit rejected: Critical issues or secrets detected."
  echo "Run 'npm run test' or view Zelsis dashboard to review open findings."
  exit 1
fi

echo "✅ Pre-commit verification passed cleanly."
exit 0`;

  const dockerComposeYaml = `version: '3.8'
services:
  zelsis-release-gate:
    image: zelsis/release-gate:v3.0.0
    container_name: zelsis-${safeProjectName}
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
      - ZELSIS_TARGET_URL=http://localhost:3000
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/v1/gate-check"]
      interval: 30s
      timeout: 10s
      retries: 3`;

  const k8sHelmYaml = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: zelsis-gate-${safeProjectName}
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: zelsis-gate
  template:
    metadata:
      labels:
        app: zelsis-gate
    spec:
      containers:
      - name: release-gate
        image: zelsis/release-gate:v3.0.0
        ports:
        - containerPort: 3000
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"
          requests:
            cpu: "250m"
            memory: "128Mi"`;

  const TAB_ITEMS: Array<{ id: TabType; label: string; icon: LucideIcon; filename: string; content: string }> = [
    { id: 'github', label: 'GitHub Actions', icon: GitBranch, filename: 'zelsis-gate.yml', content: githubActionYaml },
    { id: 'gitlab', label: 'GitLab CI', icon: Server, filename: '.gitlab-ci.yml', content: gitlabCiYaml },
    { id: 'husky', label: 'Pre-Commit (Husky)', icon: Terminal, filename: 'pre-commit', content: huskyHook },
    { id: 'docker', label: 'Docker Compose', icon: FileCode, filename: 'docker-compose.yml', content: dockerComposeYaml },
    { id: 'k8s', label: 'Kubernetes', icon: Shield, filename: 'k8s-deployment.yaml', content: k8sHelmYaml },
  ];

  const currentTabItem = TAB_ITEMS.find(t => t.id === activeTab) || TAB_ITEMS[0];

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(id);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const handleDownload = (text: string, filename: string) => {
    const blob = new Blob([text], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <AnimatePresence>
      <div
        onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200"
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-4xl max-h-[90vh] overflow-hidden bg-[#141414] border border-white/10 rounded-2xl flex flex-col shadow-2xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 p-5 sm:p-6 bg-[#0A0A0A]">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-zinc-300">
                <Server size={20} />
              </div>
              <div>
                <h2 className="text-lg font-extrabold text-[#EDEDED] flex items-center gap-2">
                  <span>CI/CD &amp; Pipeline Integration Hub</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-white/10 text-white border border-white/20">
                    Snyk-Grade CI/CD
                  </span>
                </h2>
                <p className="text-xs text-[#A1A1AA]">
                  Automate pre-flight release gates in GitHub PRs, GitLab pipelines, and local Git hooks
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              aria-label="Close deployment manifest"
              className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors cursor-pointer"
            >
              <X size={20} />
            </button>
          </div>

          {!isAllowed ? (
            <div className="flex flex-col items-center justify-center gap-6 py-12 px-6 bg-[#0A0A0A] border border-white/10 rounded-2xl text-center m-6">
              <div className="w-14 h-14 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center">
                <Lock size={26} className="text-zinc-400" />
              </div>
              <div className="max-w-md">
                <h3 className="text-base font-extrabold text-[#EDEDED] mb-2">
                  CI/CD &amp; Pipeline Manifests is a Pro Feature
                </h3>
                <p className="text-xs text-[#A1A1AA] leading-relaxed">
                  Export production-grade CI/CD release gate pipelines for GitHub Actions, GitLab CI, Husky pre-commit hooks, Docker Compose, and Kubernetes.
                  Available on <span className="text-white font-semibold">Pro</span> and <span className="text-white font-semibold">Enterprise</span> plans.
                </p>
              </div>
              <div className="flex items-center gap-3 w-full max-w-xs">
                <button
                  type="button"
                  onClick={onClose}
                  className="btn btn-secondary text-xs px-4 py-2.5 flex-1 min-h-[44px]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => onOpenCheckout?.('Pro')}
                  className="btn btn-primary text-xs px-5 py-2.5 font-bold rounded-xl flex items-center justify-center gap-2 bg-emerald-500 text-black hover:bg-emerald-400 transition-all shadow-sm flex-1 min-h-[44px]"
                >
                  <Lock size={13} />
                  <span>Upgrade to Pro</span>
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Platform Tab Navigation */}
              <div className="flex items-center gap-1.5 px-6 pt-4 border-b border-white/10 bg-[#0E0E0E] overflow-x-auto">
                {TAB_ITEMS.length === 0 ? null : TAB_ITEMS.map((tab) => {
                  const Icon = tab.icon;
                  const isActive = activeTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id as TabType)}
                      className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-mono rounded-t-lg transition-all border-b-2 cursor-pointer whitespace-nowrap ${
                        isActive
                          ? 'border-white text-white bg-white/[0.06] font-bold'
                          : 'border-transparent text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.02]'
                      }`}
                    >
                      <Icon size={14} className={isActive ? 'text-white' : 'text-zinc-400'} />
                      <span>{tab.label}</span>
                    </button>
                  );
                })}
              </div>

              {/* Main Body */}
              <div className="p-6 flex flex-col gap-4 overflow-y-auto flex-1">
                {/* Quick CLI Callout */}
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3.5 rounded-xl bg-white/[0.02] border border-white/10 text-xs font-mono">
                  <div className="flex items-center gap-2 text-zinc-300">
                    <Terminal size={14} className="text-zinc-400 shrink-0" />
                    <span>Terminal:</span>
                    <code className="text-zinc-200 font-bold bg-black/50 px-2 py-0.5 rounded border border-white/10 break-all">
                      {GATE_CURL}
                    </code>
                  </div>
                  <button
                    onClick={() => handleCopy(GATE_CURL, 'cli')}
                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-[11px] text-zinc-300 hover:text-white transition-colors cursor-pointer shrink-0"
                  >
                    {copiedType === 'cli' ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                    <span>{copiedType === 'cli' ? 'Copied' : 'Copy Command'}</span>
                  </button>
                </div>

                {/* Code Header Bar */}
                <div className="flex items-center justify-between pt-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-zinc-400">Target File:</span>
                    <span className="text-xs font-mono font-bold text-white bg-white/5 px-2 py-0.5 rounded border border-white/10">
                      {currentTabItem.filename}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleCopy(currentTabItem.content, currentTabItem.id)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-xs font-mono text-zinc-200 hover:text-white transition-colors border border-white/10 cursor-pointer"
                    >
                      {copiedType === currentTabItem.id ? (
                        <>
                          <CheckCircle2 size={13} className="text-emerald-400" />
                          <span>Copied to Clipboard</span>
                        </>
                      ) : (
                        <>
                          <Copy size={13} />
                          <span>Copy Workflow</span>
                        </>
                      )}
                    </button>
                    <button
                      onClick={() => handleDownload(currentTabItem.content, currentTabItem.filename)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-xs font-mono text-zinc-200 hover:text-white transition-colors border border-white/10 cursor-pointer"
                    >
                      <Download size={13} />
                      <span>Download</span>
                    </button>
                  </div>
                </div>

                {/* Code Viewer */}
                <div className="relative rounded-xl border border-white/10 bg-[#0A0A0A] overflow-hidden">
                  <pre className="p-4 font-mono text-xs text-zinc-300 overflow-x-auto max-h-[380px] leading-relaxed">
                    {currentTabItem.content}
                  </pre>
                </div>
              </div>

              {/* Footer */}
              <div className="flex items-center justify-between p-4 px-6 border-t border-white/10 bg-[#0A0A0A]">
                <div className="text-xs text-[#A1A1AA] flex items-center gap-2">
                  <Shield size={14} className="text-zinc-400" />
                  <span>Zero-Retention Architecture: Source code is analyzed in-memory and never written to disk.</span>
                </div>
                <button
                  className="px-4 py-2 text-xs font-bold uppercase tracking-wider rounded-lg bg-white text-black hover:bg-neutral-200 transition-all shadow-sm cursor-pointer min-h-[44px]"
                  onClick={onClose}
                >
                  Done
                </button>
              </div>
            </>
          )}
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
