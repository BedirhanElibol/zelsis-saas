import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { dispatchWebhookAlerts } from '@/lib/notifications';
import { ScanResult } from '@/lib/scanner-engine';
import { logger } from '@/lib/logger';

/**
 * Validates that a Slack webhook URL is authentic and safe against SSRF attacks.
 * Strictly enforces HTTPS and hooks.slack.com hostname.
 */
function isValidSlackWebhookUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:') return false;
    if (parsed.username || parsed.password) return false;
    const hostname = parsed.hostname.toLowerCase();
    return hostname === 'hooks.slack.com';
  } catch {
    return false;
  }
}

/**
 * Validates that a Discord webhook URL is authentic and safe against SSRF attacks.
 * Strictly enforces HTTPS and discord.com or discordapp.com hostnames.
 */
function isValidDiscordWebhookUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:') return false;
    if (parsed.username || parsed.password) return false;
    const hostname = parsed.hostname.toLowerCase();
    return (
      hostname === 'discord.com' ||
      hostname === 'discordapp.com' ||
      hostname.endsWith('.discord.com') ||
      hostname.endsWith('.discordapp.com')
    );
  } catch {
    return false;
  }
}

/**
 * Server-Side Test Webhook Dispatcher
 * Allows testing Slack and Discord webhooks without encountering browser CORS blocks or CSP violations.
 */
export async function POST(req: NextRequest) {
  try {
    // 1. Sliding-Window Rate Limiting (10 requests per minute per IP)
    const rateLimit = await checkRateLimit(req, {
      maxRequests: 10,
      windowSeconds: 60,
      prefix: 'test-webhook'
    });

    if (!rateLimit.allowed) {
      return createRateLimitResponse(rateLimit);
    }

    // Validate Content-Type
    const contentType = req.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      return NextResponse.json(
        { error: 'Unsupported Media Type: Content-Type must be application/json' },
        { status: 415 }
      );
    }

    // 2. Caller authentication: a verified Supabase user (headers like Origin or sec-fetch-site are client-controlled)
    const accessToken = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
    let isAuthenticated = false;
    if (accessToken && supabaseUrl && anonKey) {
      const { data } = await createClient(supabaseUrl, anonKey, { auth: { persistSession: false } }).auth.getUser(accessToken);
      isAuthenticated = Boolean(data?.user);
    }

    if (!isAuthenticated && (process.env.NODE_ENV === 'production' || (supabaseUrl && anonKey))) {
      return NextResponse.json(
        {
          success: false,
          error: 'Unauthorized',
          message: 'Sign in to test webhook notifications.'
        },
        { status: 401 }
      );
    }

    // 3. Parse request body
    const body = await req.json().catch(() => null);
    if (!body || typeof body !== 'object') {
      return NextResponse.json(
        {
          success: false,
          error: 'Bad Request',
          message: 'Request body must be a valid JSON object'
        },
        { status: 400 }
      );
    }

    const slackWebhookUrl = typeof body.slackWebhookUrl === 'string' ? body.slackWebhookUrl.trim() : '';
    const discordWebhookUrl = typeof body.discordWebhookUrl === 'string' ? body.discordWebhookUrl.trim() : '';
    const projectName = (typeof body.projectName === 'string' && body.projectName.trim()) || 'Production App';
    const repoUrl = (typeof body.repoUrl === 'string' && body.repoUrl.trim()) || 'https://zelsis.com';

    if (!slackWebhookUrl && !discordWebhookUrl) {
      return NextResponse.json(
        {
          success: false,
          error: 'Bad Request',
          message: 'At least one webhook URL (Slack or Discord) must be provided'
        },
        { status: 400 }
      );
    }

    // 3. Strict SSRF Protection for Webhook URLs
    if (slackWebhookUrl && !isValidSlackWebhookUrl(slackWebhookUrl)) {
      return NextResponse.json(
        {
          success: false,
          error: 'SSRF Protection Blocked Request',
          message: 'Invalid Slack webhook URL. Must start with https://hooks.slack.com'
        },
        { status: 400 }
      );
    }

    if (discordWebhookUrl && !isValidDiscordWebhookUrl(discordWebhookUrl)) {
      return NextResponse.json(
        {
          success: false,
          error: 'SSRF Protection Blocked Request',
          message: 'Invalid Discord webhook URL. Must start with https://discord.com or https://discordapp.com'
        },
        { status: 400 }
      );
    }

    // 4. Mock passed scan result for server-side test dispatch
    const mockResult: ScanResult = {
      score: 100,
      gateStatus: 'PASSED',
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      uiClicheCount: 0,
      findings: [],
      logs: [
        `[${new Date().toLocaleTimeString()}] Automated webhook connectivity test dispatched.`
      ],
      summary: 'Production clearance test alert from Zelsis Release Gate.'
    };

    logger.info(`[Test Webhook] Dispatching test alert for project "${projectName}"`);

    // 5. Server-side dispatch
    const { slackSent, discordSent } = await dispatchWebhookAlerts(
      projectName,
      repoUrl,
      mockResult,
      {
        slackWebhookUrl: slackWebhookUrl || undefined,
        discordWebhookUrl: discordWebhookUrl || undefined
      }
    );

    const success = Boolean(
      (!slackWebhookUrl || slackSent) &&
      (!discordWebhookUrl || discordSent) &&
      (slackSent || discordSent)
    );

    return NextResponse.json({
      success,
      slackSent,
      discordSent
    });
  } catch (err: any) {
    logger.error('[Test Webhook Error]', err);
    return NextResponse.json(
      {
        success: false,
        error: 'Internal Server Error',
        message: err?.message || 'Internal error processing webhook test request.'
      },
      { status: 500 }
    );
  }
}

