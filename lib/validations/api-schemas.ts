import { z } from 'zod';
import { NextResponse } from 'next/server';

/**
 * Strict Server-Side Validation Schemas for Zelsis SaaS API Endpoints
 * Prevents input tampering, injection, path traversal, and malicious payloads.
 */

// Disallow path traversal, drive letters, and relative path escape characters
const PATH_TRAVERSAL_REGEX = /(?:\.\.[\\/]|[\\/]\.\.|^[a-zA-Z]:|[<>"|?*])/;

// Strictly allow valid GitHub repository references (owner/repo or https://github.com/owner/repo)
const GITHUB_REPO_REGEX = /^(?:https?:\/\/github\.com\/)?([a-zA-Z0-9_\-\.]+)\/([a-zA-Z0-9_\-\.]+)(?:\.git)?(?:\/.*)?$/;

/**
 * Schema for /api/v1/github-proxy GET query parameters
 */
export const GithubProxyQuerySchema = z.object({
  repoUrl: z
    .string({ message: 'repoUrl is required' })
    .min(1, 'repoUrl cannot be empty')
    .max(300, 'repoUrl exceeds 300 characters')
    .refine((val) => !PATH_TRAVERSAL_REGEX.test(val), {
      message: 'repoUrl contains invalid characters or path traversal sequences'
    })
    .refine(
      (val) => {
        const clean = val.trim();
        return GITHUB_REPO_REGEX.test(clean);
      },
      {
        message: 'repoUrl must be a valid GitHub repository path (e.g., owner/repo or https://github.com/owner/repo)'
      }
    )
});

/**
 * Schema for /api/v1/proxy GET query parameters
 */
export const ProxyQuerySchema = z.object({
  url: z
    .string({ message: 'url parameter is required' })
    .min(3, 'url is too short')
    .max(2048, 'url exceeds maximum length')
    .refine(
      (val) => {
        try {
          const formatted = val.includes('://') ? val : `https://${val}`;
          const parsed = new URL(formatted);
          return parsed.protocol === 'http:' || parsed.protocol === 'https:';
        } catch {
          return false;
        }
      },
      { message: 'url must be a valid HTTP or HTTPS web address' }
    )
    .refine(
      (val) => {
        try {
          const formatted = val.includes('://') ? val : `https://${val}`;
          const parsed = new URL(formatted);
          // Block embedded user credentials (e.g. http://user:pass@host)
          return !parsed.username && !parsed.password;
        } catch {
          return false;
        }
      },
      { message: 'url must not contain embedded user credentials' }
    )
});

/**
 * Schema for /api/v1/badge GET query parameters
 */
export const BadgeQuerySchema = z.object({
  projectId: z.string().uuid().optional(),
  scanId: z.string().uuid().optional(),
  sig: z.string().max(128).optional(),
  status: z
    .string()
    .optional()
    .default('PASSED')
    .transform((v) => (v || 'PASSED').toUpperCase())
    .refine((val) => ['PASSED', 'WARNING', 'FAILED'].includes(val), {
      message: 'status must be PASSED, WARNING, or FAILED'
    }),
  score: z
    .string()
    .optional()
    .default('100')
    .transform((val) => {
      const num = parseInt(val || '100', 10);
      if (isNaN(num)) return 100;
      return Math.max(0, Math.min(100, num));
    }),
  label: z
    .string()
    .optional()
    .default('Zelsis Gate')
    .transform((val) => (val || 'Zelsis Gate').slice(0, 40))
});

/**
 * Schema for /api/v1/gate-check POST payload
 */
export const GateCheckRequestSchema = z
  .object({
    repoUrl: z.string().max(2048).optional(),
    targetUrl: z.string().max(2048).optional(),
    githubToken: z.string().max(256).optional(),
    slackWebhookUrl: z
      .string()
      .url('slackWebhookUrl must be a valid URL')
      .max(500)
      .refine((u) => u.startsWith('https://'), 'slackWebhookUrl must use HTTPS')
      .optional()
      .or(z.literal('')),
    discordWebhookUrl: z
      .string()
      .url('discordWebhookUrl must be a valid URL')
      .max(500)
      .refine((u) => u.startsWith('https://'), 'discordWebhookUrl must use HTTPS')
      .optional()
      .or(z.literal(''))
  })
  .refine(
    (data) => Boolean(data.repoUrl?.trim() || data.targetUrl?.trim()),
    {
      message: 'Either "repoUrl" or "targetUrl" must be provided in the request payload'
    }
  );

/**
 * Schema for Stripe Webhook headers and metadata
 */
export const StripeWebhookHeadersSchema = z.object({
  'stripe-signature': z.string({
    message: 'Missing stripe-signature header'
  }).min(1, 'stripe-signature header cannot be empty')
});

/**
 * Helper to validate query params and format errors into a standard JSON 400 response
 */
export function validateQueryParams<T extends z.ZodTypeAny>(
  schema: T,
  searchParams: URLSearchParams
): { success: true; data: z.output<T> } | { success: false; response: NextResponse } {
  const paramsObj: Record<string, string> = {};
  searchParams.forEach((val, key) => {
    paramsObj[key] = val;
  });

  const result = schema.safeParse(paramsObj);
  if (!result.success) {
    const errorDetails = result.error.issues.map((e) => ({
      field: e.path.join('.') || 'parameter',
      message: e.message
    }));

    return {
      success: false,
      response: NextResponse.json(
        {
          error: 'Validation Error',
          message: 'Invalid request parameters',
          details: errorDetails
        },
        { status: 400 }
      )
    };
  }

  return { success: true, data: result.data };
}

/**
 * Helper to validate JSON body and format errors into a standard JSON 400 response
 */
export function validateRequestBody<T>(
  schema: z.ZodType<T, any, any>,
  body: unknown
): { success: true; data: T } | { success: false; response: NextResponse } {
  const result = schema.safeParse(body);
  if (!result.success) {
    const errorDetails = result.error.issues.map((e) => ({
      field: e.path.join('.') || 'body',
      message: e.message
    }));

    return {
      success: false,
      response: NextResponse.json(
        {
          error: 'Validation Error',
          message: 'Invalid JSON request payload',
          details: errorDetails
        },
        { status: 400 }
      )
    };
  }

  return { success: true, data: result.data };
}
