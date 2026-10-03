import { ScanResult } from './scanner-engine';
import { getConfiguredAppUrl } from './app-url';

export interface WebhookAlertConfig {
  slackWebhookUrl?: string;
  discordWebhookUrl?: string;
}

/**
 * Dispatches automated Slack & Discord webhook alerts when a Zelsis Release Gate scan finishes.
 */
export async function dispatchWebhookAlerts(
  projectName: string,
  targetUrl: string,
  result: ScanResult,
  config: WebhookAlertConfig
): Promise<{ slackSent: boolean; discordSent: boolean }> {
  let slackSent = false;
  let discordSent = false;

  const isPassed = result.gateStatus === 'PASSED';
  const statusEmoji = isPassed ? '✅' : '🚨';
  const colorHex = isPassed ? '#10B981' : '#EF4444';

  // 1. Dispatch Slack Webhook Alert
  if (config.slackWebhookUrl) {
    try {
      const slackPayload = {
        text: `${statusEmoji} *Zelsis Release Gate Alert*: ${projectName} — *GATE ${result.gateStatus}* (Score: ${result.score}%)`,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: `${statusEmoji} Zelsis 3.0 Release Gate Audit: ${projectName}`
            }
          },
          {
            type: 'section',
            fields: [
              {
                type: 'mrkdwn',
                text: `*Gate Status:*\n${result.gateStatus}`
              },
              {
                type: 'mrkdwn',
                text: `*Readiness Score:*\n${result.score}%`
              },
              {
                type: 'mrkdwn',
                text: `*Critical Findings:*\n${result.criticalCount}`
              },
              {
                type: 'mrkdwn',
                text: `*High Risk Findings:*\n${result.highCount}`
              }
            ]
          },
          {
            type: 'context',
            elements: [
              {
                type: 'mrkdwn',
                text: `Target: <${targetUrl}|${targetUrl}> / Audited at ${new Date().toLocaleString()}`
              }
            ]
          }
        ]
      };

      const res = await fetch(config.slackWebhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(slackPayload)
      });
      slackSent = res.ok;
    } catch (e) {
      console.warn('Could not dispatch Slack Webhook alert:', e);
    }
  }

  // 2. Dispatch Discord Webhook Alert
  if (config.discordWebhookUrl) {
    try {
      const discordPayload = {
        username: 'Zelsis Release Gate Bot',
        avatar_url: `${getConfiguredAppUrl()}/zelsis-logo.svg`,
        embeds: [
          {
            title: `${statusEmoji} Release Gate Audit: ${projectName} (${result.gateStatus})`,
            description: isPassed
              ? `Production Clearance Audit PASSED. All security pre-flight checks and VibePolish rules cleared.`
              : `Release BLOCKED. Detected ${result.criticalCount} Critical vulnerabilities requiring remediation before production deployment.`,
            color: parseInt((colorHex || '#10B981').replace('#', ''), 16),
            fields: [
              { name: 'Readiness Score', value: `${result.score}%`, inline: true },
              { name: 'Critical Vulnerabilities', value: `${result.criticalCount}`, inline: true },
              { name: 'High Risk Vulnerabilities', value: `${result.highCount}`, inline: true }
            ],
            footer: {
              text: `Target Endpoint: ${targetUrl} / Zelsis 3.0 AI Gate`
            },
            timestamp: new Date().toISOString()
          }
        ]
      };

      const res = await fetch(config.discordWebhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(discordPayload)
      });
      discordSent = res.ok;
    } catch (e) {
      console.warn('Could not dispatch Discord Webhook alert:', e);
    }
  }

  return { slackSent, discordSent };
}
