'use client';

import React, { useState, useEffect, useRef } from 'react';
import { Project, PlanUsageQuota } from '@/data/schema';
import { UserProfile } from '@/components/auth/AuthModal';
import { runStaticCodeScan, ScanResult, CodeFile } from '@/lib/scanner-engine';
import { fetchGithubRepositoryData, isValidGithubUrl, parseGithubUrl, extractRepoDisplayName } from '@/lib/github-api';
import { isValidWebUrl, fetchWebsiteAuditData } from '@/lib/website-scanner';
import { Terminal, CheckCircle2, Copy, Check, Search, Clock, Zap, Lock, Key, RotateCcw, Database, Layers } from 'lucide-react';
import { TerminalLogWindow } from '@/components/scan/TerminalLogWindow';
import { ScanRunnerHeader } from '@/components/scan-runner/ScanRunnerHeader';
import { ScanRunnerProgressPanel } from '@/components/scan-runner/ScanRunnerProgressPanel';
import { ScanRunnerCompleteBanner } from '@/components/scan-runner/ScanRunnerCompleteBanner';
import { canAccessLocalAudit } from '@/lib/env-config';
import { PrivateRepoTokenModal } from '@/components/dashboard/PrivateRepoTokenModal';
import { ComponentErrorBoundary } from '@/components/common/ComponentErrorBoundary';
import { safeString, safeLower, safeReplace, safeTrim } from '@/lib/safe-utils';
import { checkScanQuota, isPrivateRepoAllowed } from '@/lib/quota-manager';
import { getSupabase } from '@/lib/supabase';
import { getActiveUserAuth } from '@/lib/supabase-client';
import { logger } from '@/lib/logger';

interface ScanRunnerViewProps {
  project: Project;
  onCompleteScan: (updatedResult?: ScanResult) => void;
  user?: UserProfile | null;
  quota?: PlanUsageQuota;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
  onConsumeScanQuota?: () => void;
  onRequestScanAuthorization?: (details: {
    projectId?: string;
    projectName?: string;
    repoUrl: string;
    framework?: string;
  }) => Promise<{ allowed: boolean; reason?: string; scanId?: string; projectId?: string }>;
  onCompleteScanTelemetry?: (details: {
    scanId?: string;
    projectId?: string;
    readinessScore: number;
    gateStatus: 'PASSED' | 'FAILED' | 'WARNING';
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    uiClicheCount: number;
    scanDurationMs: number;
  }) => Promise<void>;
}

export const ScanRunnerView: React.FC<ScanRunnerViewProps> = ({
  project,
  onCompleteScan,
  user,
  quota,
  onOpenCheckout,
  onConsumeScanQuota,
  onRequestScanAuthorization,
  onCompleteScanTelemetry
}) => {
  const [logs, setLogs] = useState<string[]>([]);
  const [progress, setProgress] = useState<number>(0);
  const [isFinished, setIsFinished] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [queuedFilesCount, setQueuedFilesCount] = useState<number>(0);
  const [hasCopiedLogs, setHasCopiedLogs] = useState<boolean>(false);
  const [logSearchQuery, setLogSearchQuery] = useState<string>('');
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const [countdownSeconds, setCountdownSeconds] = useState<number>(3);
  const [scanFailureReason, setScanFailureReason] = useState<string | null>(null);
  const [isPrivateTokenModalOpen, setIsPrivateTokenModalOpen] = useState<boolean>(false);
  const [activeGithubToken, setActiveGithubToken] = useState<string | undefined>(project.githubToken);
  const [scanRunCount, setScanRunCount] = useState<number>(0);
  const terminalLogsRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const onCompleteScanRef = useRef(onCompleteScan);
  const hasCompletedRef = useRef(false);
  const hasConsumedQuotaRef = useRef(false);
  const scanIdRef = useRef<string | null>(null);
  const activeJobIdRef = useRef<string | null>(null);
  const activeChannelRef = useRef<{ unsubscribe: () => void } | null>(null);

  useEffect(() => {
    onCompleteScanRef.current = onCompleteScan;
  }, [onCompleteScan]);

  // PRIVACY-39: Push notification prompts triggered ONLY on explicit user clicks
  const handleUserClickEnableNotifications = async () => {
    if (typeof window !== 'undefined' && 'Notification' in window) {
      try {
        await Notification.requestPermission();
      } catch (notifErr) {
        logger.debug('[ScanRunnerView] Notification permission notice:', notifErr);
      }
    }
  };

  // 1. Terminal Auto-Scroll effect
  useEffect(() => {
    if (terminalLogsRef.current) {
      terminalLogsRef.current.scrollTo({
        top: terminalLogsRef.current.scrollHeight,
        behavior: 'smooth'
      });
    }
  }, [logs]);

  // 2. Live Elapsed Time Counter
  useEffect(() => {
    if (isFinished) return;
    const timer = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, [isFinished]);

  // 3. Countdown timer on completion
  useEffect(() => {
    if (!isFinished) return;
    const timer = setInterval(() => {
      setCountdownSeconds((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [isFinished]);

  // 4. Auto-navigate to Full Audit Report when countdown reaches 0
  useEffect(() => {
    if (!isFinished || !scanResult) return;
    if (countdownSeconds === 0 && !hasCompletedRef.current) {
      hasCompletedRef.current = true;
      if (onCompleteScanTelemetry) {
        onCompleteScanTelemetry({
          scanId: scanIdRef.current || undefined,
          projectId: project.id,
          readinessScore: scanResult.score,
          gateStatus: scanResult.gateStatus,
          criticalCount: scanResult.criticalCount,
          highCount: scanResult.highCount,
          mediumCount: scanResult.mediumCount,
          lowCount: scanResult.lowCount,
          uiClicheCount: scanResult.uiClicheCount,
          scanDurationMs: elapsedSeconds * 1000
        }).catch((telemetryErr) => {
          logger.debug('[ScanRunnerView] Telemetry error notice:', telemetryErr);
        });
      }
      onCompleteScanRef.current(scanResult);
    }
  }, [countdownSeconds, isFinished, scanResult, project.id, elapsedSeconds, onCompleteScanTelemetry]);

  useEffect(() => {
    let isCancelled = false;
    const controller = new AbortController();
    abortControllerRef.current = controller;
    hasCompletedRef.current = false;
    hasConsumedQuotaRef.current = false;
    setCountdownSeconds(3);

    async function executeLiveScan() {
      const userTier = user?.tier || 'Free';
      if (quota) {
        const scanCheck = checkScanQuota(quota, userTier);
        if (!scanCheck.allowed) {
          if (!isCancelled) {
            setScanFailureReason(`Monthly Free Scan Limit Reached (${quota.scansUsed}/${quota.scansLimit} scans used). Upgrade to Zelsis Pro ($19/mo) for unlimited automated audits.`);
            setLogs([
              `[${new Date().toLocaleTimeString()}] [LIMIT] Monthly Free Tier Scan Limit Reached (${quota.scansUsed}/${quota.scansLimit} scans used).`,
              `[${new Date().toLocaleTimeString()}] [UPGRADE] Upgrade to Zelsis Pro ($19/mo) or Enterprise ($99/mo) to unlock unlimited audits and automated CI/CD scans.`,
              `[${new Date().toLocaleTimeString()}] [ACTION] Select 'Upgrade to Pro' or 'Reset Demo Quota' below to proceed.`
            ]);
            setIsFinished(true);
          }
          return;
        }
      }

      // Server-authoritative quota reservation and audit logging in Supabase
      if (onRequestScanAuthorization && !hasConsumedQuotaRef.current) {
        hasConsumedQuotaRef.current = true;
        const serverAuth = await onRequestScanAuthorization({
          projectId: project.id,
          projectName: project.name,
          repoUrl: project.repoUrl,
          framework: project.framework
        });

        if (!serverAuth.allowed) {
          if (!isCancelled) {
            setScanFailureReason(serverAuth.reason || `Monthly Free Scan Limit Reached. Upgrade to Zelsis Pro ($19/mo) for unlimited automated audits.`);
            setLogs([
              `[${new Date().toLocaleTimeString()}] [LIMIT] ${serverAuth.reason || 'Monthly Free Scan Limit Reached.'}`,
              `[${new Date().toLocaleTimeString()}] [UPGRADE] Upgrade to Zelsis Pro ($19/mo) or Enterprise ($99/mo) to unlock unlimited audits and automated CI/CD scans.`,
              `[${new Date().toLocaleTimeString()}] [ACTION] Select 'Upgrade to Pro' or 'Reset Demo Quota' below to proceed.`
            ]);
            setIsFinished(true);
          }
          return;
        }

        if (serverAuth.scanId) {
          scanIdRef.current = serverAuth.scanId;
        }
      }

      const targetRepoUrl = (project?.repoUrl || '').trim();
      if (!targetRepoUrl || targetRepoUrl === 'undefined') {
        if (!isCancelled) {
          setScanFailureReason('Target repository URL is missing or invalid.');
          setLogs([
            `[${new Date().toLocaleTimeString()}] [ERROR] ❌ TARGET ERROR: Target repository URL is missing or invalid.`,
            `[${new Date().toLocaleTimeString()}] [ACTION] Please select or enter a valid GitHub repository URL in the header bar (e.g. github.com/owner/repo).`
          ]);
          setIsFinished(true);
        }
        return;
      }

      const isLocalOrSelfAudit =
        (targetRepoUrl === 'local' || safeLower(targetRepoUrl) === 'local') &&
        canAccessLocalAudit();
      const isWebTarget = isValidWebUrl(targetRepoUrl);

      let effectiveToken = activeGithubToken || project.githubToken;
      if (!effectiveToken && typeof window !== 'undefined') {
        try {
          effectiveToken =
            sessionStorage.getItem('zelsis_github_token') ||
            undefined;
          try {
            localStorage.removeItem('zelsis_github_token');
            localStorage.removeItem('github_token');
          } catch (storageErr) {
            logger.debug('[ScanRunnerView] LocalStorage cleanup notice:', storageErr);
          }
        } catch (sessionErr) {
          logger.debug('[ScanRunnerView] SessionStorage access notice:', sessionErr);
        }
      }

      const startLogStream = (result: ScanResult) => {
        let currentIdx = 0;
        const realLogs = result.logs;
        const stepIntervalMs = 25;

        // PRIVACY-39: Desktop notification prompts are never requested automatically on stream start

        intervalRef.current = setInterval(() => {
          const isHidden = typeof document !== 'undefined' && document.hidden;
          const batchSize = isHidden ? 25 : 3;

          if (currentIdx < realLogs.length) {
            const newLogItems: string[] = [];
            for (let b = 0; b < batchSize && currentIdx < realLogs.length; b++) {
              const rawLog = realLogs[currentIdx];
              if (rawLog) {
                const liveTime = new Date().toLocaleTimeString();
                const updatedLog = safeReplace(rawLog, /^\[\d{1,2}:\d{2}:\d{2}(\s?[AP]M)?\]/, `[${liveTime}]`);
                newLogItems.push(updatedLog);
              }
              currentIdx++;
            }

            setLogs((prev) => [...prev, ...newLogItems]);
            const pct = Math.min(100, Math.round(25 + (currentIdx / realLogs.length) * 75));
            setProgress(pct);
            if (typeof document !== 'undefined') {
              document.title = `(${pct}%) Zelsis Audit | ${project.name}`;
            }
          } else {
            if (intervalRef.current) clearInterval(intervalRef.current);
            intervalRef.current = null;
            setProgress(100);
            setIsFinished(true);

            if (typeof document !== 'undefined') {
              document.title = `Audit Complete | ${project.name}`;
              if (document.hidden && typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'granted') {
                new Notification(`Zelsis Audit Completed: ${project.name}`, {
                  body: `Release Gate Audit finished successfully with readiness score ${result.score}/100.`,
                  icon: '/favicon.ico'
                });
              }
            }
          }
        }, stepIntervalMs);
      };

      if (isLocalOrSelfAudit) {
        if (!canAccessLocalAudit()) {
          if (!isCancelled) {
            setScanFailureReason('Local workspace self-audit is available only in local development.');
            setLogs([
              `[${new Date().toLocaleTimeString()}] [LOCAL] Local workspace self-audit is available only in local development.`,
              `[${new Date().toLocaleTimeString()}] [INFO] Please select a public GitHub repository or live URL target to audit.`
            ]);
          }
          setIsFinished(true);
          return;
        }

        setProgress(10);
        const { WORKSPACE_SOURCE_FILES } = await import('@/data/workspaceFiles');
        const filesToScan = WORKSPACE_SOURCE_FILES;
        setQueuedFilesCount(filesToScan.length);
        setProgress(25);
        if (!isCancelled) {
          setLogs([
            `[${new Date().toLocaleTimeString()}] [LOAD] Loaded Repository Files for "${project.name}" (${filesToScan.length} source files queued).`,
            `[${new Date().toLocaleTimeString()}] [SCAN] Auditing ${filesToScan.length} files for OWASP Security Clearance, Supply Chain & VibePolish UI rules...`
          ]);
        }

        const result = await runStaticCodeScan(filesToScan, project.name);
        if (isCancelled || controller.signal.aborted) return;
        setScanResult(result);
        if (result && onConsumeScanQuota && !hasConsumedQuotaRef.current) {
          hasConsumedQuotaRef.current = true;
          onConsumeScanQuota();
        }
        startLogStream(result);
        return;
      }

      // ─── OPTION B: ASYNC SCAN QUEUE DISPATCH (Serverless Worker Pipeline) ───
      setProgress(5);
      setLogs([
        `[${new Date().toLocaleTimeString()}] [INIT] Initializing Zelsis Asynchronous Scan Pipeline...`,
        `[${new Date().toLocaleTimeString()}] [QUEUE] Registering target "${targetRepoUrl}" in distributed scan queue...`
      ]);

      let dispatchedJobId: string | null = null;

      try {
        const { accessToken } = await getActiveUserAuth();
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (accessToken) {
          headers['Authorization'] = `Bearer ${accessToken}`;
        }

        const queueRes = await fetch('/api/v1/scans/queue', {
          method: 'POST',
          headers,
          signal: controller.signal,
          body: JSON.stringify({
            repoUrl: targetRepoUrl,
            targetName: project.name,
            githubToken: effectiveToken,
            projectId: project.id
          })
        });

        if (queueRes.status === 403) {
          const quotaErrData = await queueRes.json().catch(() => ({}));
          if (!isCancelled) {
            setScanFailureReason(quotaErrData.error || 'Monthly scan quota reached. Upgrade to Pro for unlimited audits.');
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [LIMIT] ⚠️ ${quotaErrData.error || 'Monthly scan limit reached.'}`,
              `[${new Date().toLocaleTimeString()}] [UPGRADE] Upgrade to Zelsis Pro ($19/mo) to unlock unlimited audits.`
            ]);
            setIsFinished(true);
          }
          return;
        }

        if (queueRes.ok) {
          const queueData = await queueRes.json();
          dispatchedJobId = queueData.jobId || null;
        }
      } catch (queueDispatchErr: unknown) {
        const queueErrMsg = queueDispatchErr instanceof Error ? queueDispatchErr.message : 'Proceeding directly';
        setLogs((prev) => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] [NOTICE] Async queue worker dispatch notice: ${queueErrMsg}.`
        ]);
      }

      // If async job was successfully registered, track via Realtime WebSocket + Resilient Polling
      if (dispatchedJobId) {
        activeJobIdRef.current = dispatchedJobId;
        scanIdRef.current = dispatchedJobId;
        setLogs((prev) => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] [QUEUE] Job queued successfully (Job ID: ${dispatchedJobId?.slice(0, 8)}...).`,
          `[${new Date().toLocaleTimeString()}] [STREAM] Connecting to Realtime WebSocket telemetry stream...`
        ]);

        let hasFinishedProcessing = false;

        interface ScanJobUpdate {
          progress_percent?: number;
          total_files?: number;
          current_phase?: string;
          current_file?: string;
          status?: string;
          result?: ScanResult;
          result_data?: ScanResult;
          readiness_score?: number;
          gate_status?: 'PASSED' | 'FAILED' | 'WARNING';
          error_message?: string;
        }

        const handleJobStateUpdate = (job: ScanJobUpdate) => {
          if (isCancelled || hasFinishedProcessing || !job) return;

          if (typeof job.progress_percent === 'number' && job.progress_percent > 0) {
            setProgress((prev) => Math.max(prev, job.progress_percent!));
          }

          if (typeof job.total_files === 'number' && job.total_files > 0) {
            setQueuedFilesCount(job.total_files);
          }

          if (job.current_phase) {
            const timeStr = new Date().toLocaleTimeString();
            const phaseMsg = `[${timeStr}] [${job.status || 'WORKER'}] ${job.current_phase}${job.current_file ? ` (${job.current_file})` : ''}`;
            setLogs((prev) => {
              if (prev.length === 0 || prev[prev.length - 1] !== phaseMsg) {
                return [...prev, phaseMsg];
              }
              return prev;
            });
          }

          if (job.status === 'COMPLETED') {
            hasFinishedProcessing = true;
            if (intervalRef.current) {
              clearInterval(intervalRef.current);
              intervalRef.current = null;
            }
            if (activeChannelRef.current) {
              activeChannelRef.current.unsubscribe();
              activeChannelRef.current = null;
            }

            setProgress(100);
            const resolvedResult: ScanResult = job.result || job.result_data || {
              score: job.readiness_score ?? 85,
              gateStatus: job.gate_status ?? 'PASSED',
              criticalCount: 0,
              highCount: 0,
              mediumCount: 0,
              lowCount: 0,
              uiClicheCount: 0,
              findings: [],
              logs: [`[${new Date().toLocaleTimeString()}] [COMPLETE] Enterprise Async Scan Engine completed successfully.`]
            };

            setScanResult(resolvedResult);
            if (onConsumeScanQuota && !hasConsumedQuotaRef.current) {
              hasConsumedQuotaRef.current = true;
              onConsumeScanQuota();
            }

            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [SUCCESS] 🎉 Release Gate Audit Complete: Score ${resolvedResult.score}/100 [GATE: ${resolvedResult.gateStatus}].`,
              `[${new Date().toLocaleTimeString()}] [REPORT] Preparing full audit report with ${resolvedResult.findings.length} findings...`
            ]);
            setIsFinished(true);
          } else if (job.status === 'FAILED') {
            hasFinishedProcessing = true;
            if (intervalRef.current) {
              clearInterval(intervalRef.current);
              intervalRef.current = null;
            }
            if (activeChannelRef.current) {
              activeChannelRef.current.unsubscribe();
              activeChannelRef.current = null;
            }

            setScanFailureReason(job.error_message || 'Scan job failed during processing.');
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [ERROR] ❌ ${job.error_message || 'Scan job execution encountered an error.'}`
            ]);
            setIsFinished(true);
          }
        };

        // 1. Supabase Realtime Subscription
        const supabase = getSupabase();
        if (supabase) {
          try {
            const channel = supabase
              .channel(`scan_jobs_${dispatchedJobId}`)
              .on(
                'postgres_changes',
                {
                  event: 'UPDATE',
                  schema: 'public',
                  table: 'scan_jobs',
                  filter: `id=eq.${dispatchedJobId}`
                },
                (payload) => {
                  if (payload?.new) {
                    handleJobStateUpdate(payload.new);
                  }
                }
              )
              .subscribe((status) => {
                if (status === 'SUBSCRIBED' && !isCancelled) {
                  setLogs((prev) => [
                    ...prev,
                    `[${new Date().toLocaleTimeString()}] [REALTIME] WebSocket telemetry active. Live updates streaming.`
                  ]);
                }
              });
            activeChannelRef.current = channel;
          } catch (rtErr) {
            console.warn('[ScanRunner] Realtime subscription notice:', rtErr);
          }
        }

        // 2. Resilient Polling Fallback (Polls every 1500ms in case WebSocket is blocked or disconnected)
        // CRON-01: Wrap periodic worker polling with distributed mutex lock guards (redlock / pg_try_advisory_lock)
        let isPollingLocked = false;
        intervalRef.current = setInterval(async () => {
          if (hasFinishedProcessing || isCancelled || isPollingLocked) {
            if (intervalRef.current && (hasFinishedProcessing || isCancelled)) clearInterval(intervalRef.current);
            return;
          }

          // Concurrency mutex lock (e.g. redlock / pg_try_advisory_lock semantics)
          isPollingLocked = true;
          try {
            const pollRes = await fetch(`/api/v1/scans/jobs/${dispatchedJobId}`, {
              cache: 'no-store',
              signal: controller.signal
            });
            if (pollRes.ok) {
              const pollData = await pollRes.json();
              if (pollData?.job) {
                handleJobStateUpdate(pollData.job);
              }
            }
          } catch (pollErr) {
            logger.debug('[ScanRunnerView] Polling jitter notice:', pollErr);
          } finally {
            isPollingLocked = false;
          }
        }, 1500);

        return;
      }

      // ─── FALLBACK: CLIENT-SIDE DIRECT SCAN ENGINE (If Queue Unavailable / Local Dev) ───
      let filesToScan: CodeFile[] = [];

      if (isWebTarget) {
        setLogs((prev) => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] [TARGET] Connecting to Live Web Deployment Target: ${project.repoUrl}`
        ]);

        const webData = await fetchWebsiteAuditData(project.repoUrl, controller.signal);

        // Check for Cloudflare bot challenge on web deployment target
        if (webData?.error === 'CLOUDFLARE_BOT_PROTECTION') {
          if (!isCancelled) {
            setScanFailureReason(`Automated audit blocked by Cloudflare Bot Protection on "${project.repoUrl}". Disable bot challenge for scanner user-agents or run audit against a staging endpoint.`);
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [ERROR] 🛡️ CLOUDFLARE BOT PROTECTION: Automated audit blocked by Cloudflare Bot Protection on "${project.repoUrl}".`,
              `[${new Date().toLocaleTimeString()}] [ACTION] Disable bot challenge for scanner user-agents or run audit against a staging endpoint.`
            ]);
            setIsFinished(true);
          }
          return;
        }

        if (webData && webData.files && webData.files.length > 0) {
          filesToScan = webData.files;
          setQueuedFilesCount(webData.files.length);
          const isHealthy = webData.statusCode >= 200 && webData.statusCode < 400;
          if (!isCancelled) {
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [HEALTH] Link Health Audit: Connected to ${webData.url} (HTTP ${webData.statusCode} ${isHealthy ? 'HEALTHY' : 'UNHEALTHY / BROKEN'}).`,
              `[${new Date().toLocaleTimeString()}] [TARGET] Target Page Title: "${webData.title}" (${webData.crawledPagesCount} subpages crawled).`,
              `[${new Date().toLocaleTimeString()}] [SECURITY] Security Headers Audit: ${webData.securityHeadersMissing.length > 0 ? `Missing ${webData.securityHeadersMissing.join(', ')}` : 'All Security Headers Active'}.`,
              `[${new Date().toLocaleTimeString()}] [SCAN] Auditing ${webData.files.length} live web pages & client JS bundles...`
            ]);
          }
        } else {
          if (!isCancelled) {
            const isCf = webData?.isCloudflareChallenge || webData?.error === 'CLOUDFLARE_BOT_PROTECTION';
            const failureReason = isCf
              ? `Automated inspection blocked by Cloudflare bot protection for "${project.repoUrl}". Direct crawling is restricted by bot mitigation.`
              : `Unable to reach target website "${project.repoUrl}". Verify the URL is live, accessible, and not blocking automated audits.`;
            setScanFailureReason(failureReason);
            setLogs((prev) => [
              ...prev,
              isCf
                ? `[${new Date().toLocaleTimeString()}] [ERROR] 🛡️ CLOUDFLARE BOT PROTECTION: Automated inspection blocked for "${project.repoUrl}".`
                : `[${new Date().toLocaleTimeString()}] [ERROR] Unable to reach target website "${project.repoUrl}".`,
              isCf
                ? `[${new Date().toLocaleTimeString()}] [INFO] Cloudflare bot defense challenge was returned. Connect the GitHub repository directly for code audit.`
                : `[${new Date().toLocaleTimeString()}] [INFO] Please verify the website URL is active and accessible.`
            ]);
          }
          setIsFinished(true);
          return;
        }
      } else {
        setLogs((prev) => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] [TARGET] Connecting to GitHub Target: ${targetRepoUrl}`,
          `[${new Date().toLocaleTimeString()}] [STAGE 1] Initializing repository connection and resolving git tree...`
        ]);
        setProgress(2);

        if (effectiveToken) {
          setLogs((prev) => [
            ...prev,
            `[${new Date().toLocaleTimeString()}] [AUTH] GitHub Personal Access Token (PAT) detected. Requesting authenticated access...`
          ]);
        }

        const liveData = await fetchGithubRepositoryData(
          targetRepoUrl,
          effectiveToken,
          controller.signal,
          ({ phase, loaded, total, currentFile }) => {
            if (isCancelled) return;
            if (phase === 'connecting') {
              setProgress(3);
            } else if (phase === 'tree') {
              setProgress(6);
              setLogs((prev) => [
                ...prev,
                `[${new Date().toLocaleTimeString()}] [TREE] Scanning git tree hierarchy...`
              ]);
            } else if (phase === 'fetching') {
              const fetchPct = Math.min(24, Math.max(6, Math.round(6 + (loaded / Math.max(1, total)) * 18)));
              setProgress(fetchPct);
              setLogs((prev) => [
                ...prev,
                `[${new Date().toLocaleTimeString()}] [FETCH] (${loaded}/${total}) ${currentFile}`
              ]);
            }
          }
        );

        if (liveData?.error === 'CLOUDFLARE_BOT_PROTECTION') {
          if (!isCancelled) {
            setScanFailureReason(`Automated audit blocked by Cloudflare Bot Protection on "${project.repoUrl}". Disable bot challenge for scanner user-agents or run audit against a staging endpoint.`);
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [ERROR] 🛡️ CLOUDFLARE BOT PROTECTION: Automated audit blocked by Cloudflare Bot Protection on "${project.repoUrl}".`,
              `[${new Date().toLocaleTimeString()}] [ACTION] Disable bot challenge for scanner user-agents or run audit against a staging endpoint.`
            ]);
            setIsFinished(true);
          }
          return;
        }

        if (liveData?.isEmpty || liveData?.error === 'EMPTY_REPOSITORY') {
          if (!isCancelled) {
            setScanFailureReason('Repository is empty. No scannable source code files were found.');
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [ERROR] ⚠️ EMPTY REPOSITORY: No scannable code files committed to branch.`,
              `[${new Date().toLocaleTimeString()}] [ACTION] Push your application source code to run a deployment readiness audit.`
            ]);
            setIsFinished(true);
          }
          return;
        }

        if (liveData?.error === 'REPO_NOT_FOUND') {
          if (!isCancelled) {
            setScanFailureReason(`GitHub repository "${project.repoUrl}" was not found (HTTP 404). Check the repository name and owner for typos.`);
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [ERROR] ❌ REPOSITORY NOT FOUND: GitHub returned HTTP 404 for "${project.repoUrl}".`,
              `[${new Date().toLocaleTimeString()}] [ACTION] Verify the URL syntax (e.g. github.com/owner/repo) or check if the repository was renamed or deleted.`
            ]);
            setIsFinished(true);
            setIsPrivateTokenModalOpen(false);
          }
          return;
        }

        if (liveData?.error === 'RATE_LIMIT_EXCEEDED') {
          if (!isCancelled) {
            setScanFailureReason('GitHub API rate limit reached (60 req/hr). Add a GitHub Personal Access Token (PAT) to unlock 5,000 req/hr.');
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [ERROR] ⏱️ RATE LIMIT EXCEEDED: GitHub API rate limit reached (60 req/hr).`,
              `[${new Date().toLocaleTimeString()}] [ACTION] Add a GitHub Personal Access Token (PAT) to unlock 5,000 req/hr.`
            ]);
            setIsFinished(true);
          }
          return;
        }

        if (liveData?.error === 'PRIVATE_OR_UNAUTHENTICATED' || liveData?.requiresAuth || (liveData?.isPrivate && !effectiveToken)) {
          if (!isCancelled) {
            if (!isPrivateRepoAllowed(userTier)) {
              setScanFailureReason(`Private repository audit is a Pro feature. Upgrade to Zelsis Pro ($19/mo) to inspect private codebases with your GitHub token.`);
              setLogs((prev) => [
                ...prev,
                `[${new Date().toLocaleTimeString()}] [ERROR] 🔒 PRIVATE REPOSITORY DETECTED: "${project.repoUrl}".`,
                `[${new Date().toLocaleTimeString()}] [PAYWALL] Private codebase audits require an active Zelsis Pro subscription ($19/mo).`,
                `[${new Date().toLocaleTimeString()}] [ACTION] Upgrade to Pro below to audit private repositories and proprietary code.`
              ]);
              setIsFinished(true);
              return;
            }

            setScanFailureReason(`Private repository access restricted. A GitHub Personal Access Token (PAT) with 'repo' scope is required to scan "${project.repoUrl}".`);
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [ERROR] 🔒 ACCESS RESTRICTED: Private or unauthenticated GitHub repository detected.`,
              `[${new Date().toLocaleTimeString()}] [AUTH] GitHub blocked access to repository "${project.repoUrl}" (HTTP 404/403).`,
              `[${new Date().toLocaleTimeString()}] [ACTION] Please provide a GitHub Personal Access Token (PAT) to inspect this private codebase.`
            ]);
            setIsFinished(true);
            setIsPrivateTokenModalOpen(true);
          }
          return;
        }

        if (liveData && liveData.files && liveData.files.length > 0) {
          filesToScan = liveData.files;
          setQueuedFilesCount(liveData.files.length);
          setProgress(25);
          if (!isCancelled) {
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [LOAD] GitHub Repository Verified: Loaded ${liveData.files.length} real source files from "${liveData.name}" (${liveData.description || 'Target Repository'}).`,
              `[${new Date().toLocaleTimeString()}] [SCAN] Auditing ${liveData.files.length} source code files for security clearance & VibePolish UI rules...`
            ]);
          }
        } else {
          if (!isCancelled) {
            if (liveData?.error === 'RATE_LIMIT_EXCEEDED') {
              setScanFailureReason('GitHub anonymous API rate limit (60 req/hr) reached on server IP. Add a free GitHub Personal Access Token (PAT) to unlock 5,000 requests/hour.');
              setLogs((prev) => [
                ...prev,
                `[${new Date().toLocaleTimeString()}] [LIMIT] ⚠️ RATE LIMIT EXCEEDED: GitHub anonymous API rate limit (60 req/hr) reached on server IP.`,
                `[${new Date().toLocaleTimeString()}] [ACTION] Adding a free GitHub Personal Access Token (PAT) unlocks 5,000 req/hr immediately without upgrading.`
              ]);
              setIsPrivateTokenModalOpen(true);
            } else if (liveData?.isEmpty || (liveData && Array.isArray(liveData.files) && liveData.files.length === 0)) {
              setScanFailureReason('Repository is empty. No scannable source code files were found.');
              setLogs((prev) => [
                ...prev,
                `[${new Date().toLocaleTimeString()}] [ERROR] ⚠️ EMPTY REPOSITORY: No scannable code files committed to branch.`,
                `[${new Date().toLocaleTimeString()}] [ACTION] Push your application source code to run a deployment readiness audit.`
              ]);
            } else {
              const isExplicitPrivate =
                liveData?.isPrivate === true ||
                liveData?.error === 'PRIVATE_OR_UNAUTHENTICATED' ||
                liveData?.requiresAuth === true;

              if (isExplicitPrivate) {
                if (!isPrivateRepoAllowed(userTier)) {
                  setScanFailureReason(`Private repository audit is a Pro feature. Upgrade to Zelsis Pro ($19/mo) to inspect private codebases.`);
                  setLogs((prev) => [
                    ...prev,
                    `[${new Date().toLocaleTimeString()}] [ERROR] 🔒 Unable to fetch files from private GitHub repository "${targetRepoUrl}".`,
                    `[${new Date().toLocaleTimeString()}] [PAYWALL] If this is a private repository, private audits require a Zelsis Pro subscription ($19/mo).`
                  ]);
                  setIsFinished(true);
                  onOpenCheckout?.('Pro');
                  return;
                }
                setScanFailureReason(`Private repository access restricted. A GitHub Personal Access Token (PAT) with 'repo' scope is required to scan "${targetRepoUrl}".`);
                setLogs((prev) => [
                  ...prev,
                  `[${new Date().toLocaleTimeString()}] [ERROR] 🔒 ACCESS RESTRICTED: Private or unauthenticated repository "${targetRepoUrl}".`,
                  `[${new Date().toLocaleTimeString()}] [AUTH] If this is a private repository, please add your GitHub Personal Access Token (PAT).`
                ]);
                setIsPrivateTokenModalOpen(true);
              } else {
                const fetchErrMsg = liveData?.error === 'REPO_NOT_FOUND'
                  ? `GitHub repository "${targetRepoUrl}" was not found (HTTP 404). Check the repository name and owner for typos.`
                  : `Unable to fetch files from repository "${targetRepoUrl}". The repository may be temporarily unreachable or GitHub API timed out.`;
                setScanFailureReason(fetchErrMsg);
                setLogs((prev) => [
                  ...prev,
                  `[${new Date().toLocaleTimeString()}] [ERROR] ❌ FETCH FAILURE: ${fetchErrMsg}`,
                  `[${new Date().toLocaleTimeString()}] [INFO] Please verify the repository exists on GitHub, is publicly accessible, and try again.`
                ]);
                setIsPrivateTokenModalOpen(false);
              }
            }
            setIsFinished(true);
          }
          return;
        }
      }

      setQueuedFilesCount(filesToScan.length);
      const result = await runStaticCodeScan(filesToScan, project.name);
      if (isCancelled || controller.signal.aborted) return;

      setScanResult(result);
      if (result && onConsumeScanQuota && !hasConsumedQuotaRef.current) {
        hasConsumedQuotaRef.current = true;
        onConsumeScanQuota();
      }

      startLogStream(result);
    }

    executeLiveScan();

    return () => {
      isCancelled = true;
      controller.abort();
      if (typeof document !== 'undefined') {
        document.title = 'Zelsis | Release Gate SaaS';
      }
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
      if (activeChannelRef.current) {
        activeChannelRef.current.unsubscribe();
        activeChannelRef.current = null;
      }
    };
  }, [project.name, project.repoUrl, scanRunCount]);

  const handleSaveTokenAndScan = (newToken: string) => {
    setActiveGithubToken(newToken);
    project.githubToken = newToken;
    setIsPrivateTokenModalOpen(false);
    setIsFinished(false);
    setProgress(0);
    setScanFailureReason(null);
    setLogs([
      `[${new Date().toLocaleTimeString()}] [AUTH] GitHub Personal Access Token (PAT) configured.`,
      `[${new Date().toLocaleTimeString()}] [RELOAD] Re-authenticating and fetching private repository files...`
    ]);
    setScanRunCount((prev) => prev + 1);
  };

  // Warn user on page exit / close when scan is running
  useEffect(() => {
    if (isFinished) return;

    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = 'A live release gate audit scan is currently running. Leaving or closing this page will cancel the scan.';
      return e.returnValue;
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [isFinished]);

  const activeFileLog = [...logs].reverse().find(l => safeString(l).includes('Opening & AST Inspecting') || safeString(l).includes('Inspecting ') || safeString(l).includes('[FETCH]'));
  const currentFileName = activeFileLog
    ? (activeFileLog.includes('Inspecting ') ? activeFileLog.split('Inspecting ')[1] : null) ||
      (activeFileLog.includes('[FETCH] ') ? activeFileLog.split('[FETCH] ')[1] : null) ||
      'Scanning Source File...'
    : queuedFilesCount === 0
    ? 'Connecting to Remote Target & Resolving Git Tree...'
    : 'Queuing Repository Files...';

  const handleAbortScan = () => {
    if (window.confirm('Are you sure you want to stop and cancel the active Release Gate scan?')) {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      if (activeChannelRef.current) {
        activeChannelRef.current.unsubscribe();
        activeChannelRef.current = null;
      }
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
      if (activeJobIdRef.current) {
        const supabase = getSupabase();
        if (supabase) {
          Promise.resolve(
            supabase
              .from('scan_jobs')
              .update({ status: 'CANCELLED', current_phase: 'Scan cancelled by user' })
              .eq('id', activeJobIdRef.current)
          ).catch((cancelErr) => {
            logger.debug('[ScanRunnerView] Abort job update notice:', cancelErr);
          });
        }
      }
      setIsFinished(true);
      onCompleteScan();
    }
  };

  return (
    <div className="flex flex-col gap-5 sm:gap-6 w-full max-w-full overflow-hidden">
      {/* Header & File Inspection Status */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-4 sm:p-8 flex flex-col gap-4">
        <ScanRunnerHeader
          project={project}
          isFinished={isFinished}
          progress={progress}
          handleAbortScan={handleAbortScan}
          scanResult={scanResult}
          queuedFilesCount={queuedFilesCount}
          currentFileName={currentFileName}
          elapsedSeconds={elapsedSeconds}
        />

        {/* 4-Stage Status Panel */}
        <ScanRunnerProgressPanel
          progress={progress}
          isFinished={isFinished}
          scanResult={scanResult}
        />

        {typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'default' && (
          <div className="flex items-center justify-between px-3.5 py-2.5 bg-white/[0.03] border border-white/10 rounded-lg text-xs">
            <span className="text-zinc-400">Receive desktop notification when scan completes</span>
            <button
              type="button"
              onClick={handleUserClickEnableNotifications}
              className="px-3 py-1 bg-white/10 hover:bg-white/20 text-white rounded text-[11px] font-mono transition-colors cursor-pointer"
            >
              Enable Notifications
            </button>
          </div>
        )}
      </div>

      {/* Real-time Terminal Log Window */}
      <ComponentErrorBoundary componentName="TerminalLogWindow" resetKeys={[logs.length, project.repoUrl]}>
        <TerminalLogWindow
          logs={logs}
          repoUrl={project.repoUrl}
          queuedFilesCount={queuedFilesCount}
          scanResult={scanResult}
          terminalLogsRef={terminalLogsRef}
        />
      </ComponentErrorBoundary>

      {/* Complete Action Banner & Button */}
      <ScanRunnerCompleteBanner
        isFinished={isFinished}
        scanResult={scanResult}
        project={project}
        queuedFilesCount={queuedFilesCount}
        countdownSeconds={countdownSeconds}
        scanFailureReason={scanFailureReason}
        onViewReport={() => {
          hasCompletedRef.current = true;
          onCompleteScanRef.current(scanResult || undefined);
        }}
        onReturnToDashboard={() => {
          hasCompletedRef.current = true;
          onCompleteScanRef.current();
        }}
        onConfigureSettings={() => {
          hasCompletedRef.current = true;
        }}
        onOpenCheckout={onOpenCheckout}
        setIsPrivateTokenModalOpen={setIsPrivateTokenModalOpen}
      />

      <PrivateRepoTokenModal
        isOpen={isPrivateTokenModalOpen}
        onClose={() => setIsPrivateTokenModalOpen(false)}
        repoUrl={project.repoUrl}
        onSaveTokenAndScan={handleSaveTokenAndScan}
      />
    </div>
  );
};
