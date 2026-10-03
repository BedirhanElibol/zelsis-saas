import { logger } from './logger';
import { getConfiguredAppUrl } from './app-url';

export interface SendEmailOptions {
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
  from?: string;
  replyTo?: string;
}

export interface SendEmailResult {
  success: boolean;
  id?: string;
  error?: string;
}

/**
 * Dispatches an outbound email via the Resend REST API (https://api.resend.com/emails).
 * Uses native fetch with timeout guard, requiring zero external npm dependencies.
 */
export async function sendEmail(options: SendEmailOptions): Promise<SendEmailResult> {
  const apiKey = process.env.RESEND_API_KEY?.trim();
  if (!apiKey) {
    logger.debug('[Resend] RESEND_API_KEY is not set. Email dispatch skipped.');
    return { success: false, error: 'RESEND_API_KEY is not configured' };
  }

  const defaultFrom = process.env.RESEND_FROM_EMAIL?.trim() || 'ShipGuard <onboarding@resend.dev>';
  const from = options.from || defaultFrom;
  const to = Array.isArray(options.to) ? options.to : [options.to];

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from,
        to,
        subject: options.subject,
        html: options.html,
        text: options.text,
        reply_to: options.replyTo,
      }),
      signal: AbortSignal.timeout(8000),
    });

    const data = await res.json().catch(() => null);

    if (!res.ok) {
      const errorMsg = data?.message || data?.error || `HTTP ${res.status}`;
      logger.warn('[Resend] Email dispatch failed:', errorMsg);
      return { success: false, error: errorMsg };
    }

    logger.info(`[Resend] Email dispatched successfully. ID: ${data?.id ?? 'ok'}`);
    return { success: true, id: data?.id };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown network error';
    logger.error('[Resend] Exception during email dispatch:', message);
    return { success: false, error: message };
  }
}

/**
 * Base Dark Luxury HTML template for ShipGuard system emails.
 */
function wrapHtmlTemplate({ title, contentHtml }: { title: string; contentHtml: string }): string {
  const appUrl = getConfiguredAppUrl();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
</head>
<body style="margin:0;padding:0;background-color:#0A0A0A;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#EDEDED;">
  <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color:#0A0A0A;padding:40px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width:540px;background-color:#141414;border:1px solid rgba(255,255,255,0.1);border-radius:12px;overflow:hidden;box-shadow:0 20px 40px rgba(0,0,0,0.6);">
          <!-- Header Bar -->
          <tr>
            <td style="padding:24px 32px;border-bottom:1px solid rgba(255,255,255,0.08);background-color:rgba(255,255,255,0.02);">
              <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <a href="${appUrl}" style="text-decoration:none;display:inline-flex;align-items:center;gap:8px;">
                      <span style="font-size:16px;font-weight:800;letter-spacing:-0.5px;color:#FFFFFF;">SHIPGUARD</span>
                      <span style="font-size:10px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;font-weight:700;background-color:rgba(16,185,129,0.15);color:#34D399;border:1px solid rgba(16,185,129,0.3);padding:2px 6px;border-radius:999px;margin-left:6px;text-transform:uppercase;">Gate</span>
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:32px;font-size:14px;line-height:1.6;color:#D4D4D8;">
              ${contentHtml}
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding:20px 32px;background-color:#0E0E0E;border-top:1px solid rgba(255,255,255,0.06);font-size:11px;color:#71717A;text-align:center;line-height:1.5;">
              <p style="margin:0 0 6px 0;">ShipGuard — Automated AI & Code Deployment Gate</p>
              <p style="margin:0;"><a href="${appUrl}" style="color:#A1A1AA;text-decoration:underline;">shipguard-saas.vercel.app</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

/**
 * Sends a welcome confirmation email when someone joins the waitlist.
 */
export async function sendWaitlistWelcomeEmail(email: string, frameworkInterest?: string | null): Promise<SendEmailResult> {
  const frameworkNote = frameworkInterest
    ? `<div style="margin-top:16px;padding:12px 16px;background-color:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:8px;font-family:ui-monospace,monospace;font-size:12px;color:#A1A1AA;">
        <strong>İlgi Alanı:</strong> <span style="color:#10B981;">${frameworkInterest}</span>
       </div>`
    : '';

  const html = wrapHtmlTemplate({
    title: 'ShipGuard Erken Erişim Bekleme Listesindesiniz',
    contentHtml: `
      <h1 style="margin:0 0 16px 0;font-size:20px;font-weight:700;color:#FFFFFF;letter-spacing:-0.3px;">
        Erken Erişim Sırasına Alındınız
      </h1>
      <p style="margin:0 0 12px 0;">
        Merhaba,
      </p>
      <p style="margin:0 0 12px 0;">
        ShipGuard erken erişim bekleme listesine kaydınız başarıyla tamamlandı. Dağıtım öncesi güvenlik, erişilebilirlik ve VibePolish kontrolleri sağlayan platformumuzun yeni sürümüne ilk erişen ekiplerden biri olacaksınız.
      </p>
      ${frameworkNote}
      <p style="margin:20px 0 0 0;font-size:12px;color:#71717A;">
        Hesabınız açıldığında ve davetiniz onaylandığında size bu adresten bilgi vereceğiz.
      </p>
    `,
  });

  const text = `ShipGuard Erken Erişim Sırasına Alındınız\n\nMerhaba,\n\nShipGuard erken erişim bekleme listesine kaydınız başarıyla tamamlandı. Dağıtım öncesi güvenlik ve kalite kontrolleri hazır olduğunda size özel davet göndereceğiz.\n\nShipGuard Ekibi`;

  return sendEmail({
    to: email,
    subject: 'ShipGuard Erken Erişim Sırasına Alındınız',
    html,
    text,
  });
}

/**
 * Sends an invitation email to a teammate to join an enterprise workspace.
 */
export async function sendWorkspaceInviteEmail(params: {
  toEmail: string;
  orgName: string;
  role: string;
  inviteUrl: string;
}): Promise<SendEmailResult> {
  const { toEmail, orgName, role, inviteUrl } = params;

  const html = wrapHtmlTemplate({
    title: `${orgName} Çalışma Alanına Davet Edildiniz`,
    contentHtml: `
      <h1 style="margin:0 0 16px 0;font-size:20px;font-weight:700;color:#FFFFFF;letter-spacing:-0.3px;">
        Ekip Çalışma Alanına Davet Edildiniz
      </h1>
      <p style="margin:0 0 16px 0;">
        <strong style="color:#FFFFFF;">${orgName}</strong> ekibi sizi ShipGuard üzerinde 
        <strong style="color:#34D399;text-transform:uppercase;font-family:ui-monospace,monospace;font-size:12px;">${role}</strong> 
        rolüyle çalışma alanına katılmaya davet etti.
      </p>
      <div style="margin:28px 0;text-align:center;">
        <a href="${inviteUrl}" style="display:inline-block;background-color:#10B981;color:#000000;font-weight:700;font-size:13px;padding:12px 28px;border-radius:8px;text-decoration:none;letter-spacing:-0.2px;">
          Daveti Kabul Et ve Katıl
        </a>
      </div>
      <p style="margin:0 0 8px 0;font-size:12px;color:#71717A;">
        Buton çalışmıyorsa aşağıdaki bağlantıyı tarayıcınıza yapıştırabilirsiniz:
      </p>
      <p style="margin:0;font-size:11px;font-family:ui-monospace,monospace;color:#A1A1AA;word-break:break-all;">
        ${inviteUrl}
      </p>
      <p style="margin:20px 0 0 0;font-size:11px;color:#52525B;">
        Bu davet bağlantısı tek kullanımlıktır ve 7 gün boyunca geçerlidir.
      </p>
    `,
  });

  const text = `${orgName} ekibi sizi ShipGuard üzerinde ${role} rolüyle çalışma alanına katılmaya davet etti.\n\nDaveti kabul etmek için bağlantı:\n${inviteUrl}\n\nBu bağlantı 7 gün boyunca geçerlidir.`;

  return sendEmail({
    to: toEmail,
    subject: `${orgName} Çalışma Alanına Davet Edildiniz — ShipGuard`,
    html,
    text,
  });
}
