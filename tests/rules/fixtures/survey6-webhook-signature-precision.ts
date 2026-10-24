import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [9704],
    name: 'Rule 9704 Payment webhook without signature vs git/bot webhooks and adapter verification',
    detects: f('app/api/webhooks/stripe/route.ts', `export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === 'payment_intent.succeeded') {
    await fulfillOrder(event.data.object);
  }
  return new Response('ok');
}
`),
    ignores: [
      {
        path: 'src/sentry/integrations/gitlab/webhooks.py',
        content: `class GitlabWebhookEndpoint(View):
    def post(self, request):
        event = request.data
        handle_gitlab_event(event)
        return Response(status=200)
`,
      },
      {
        path: 'src/app/api/webhooks/telegram/route.ts',
        content: `export async function POST(req: Request) {
  const secret = req.headers.get('x-telegram-bot-api-secret-token');
  if (secret !== process.env.TELEGRAM_BOT_SECRET) {
    return new Response('unauthorized', { status: 401 });
  }
  const update = await req.json();
  return new Response('ok');
}
`,
      },
      {
        path: 'app/controllers/payment_webhook.ts',
        content: `export async function handleWebhook(req: Request) {
  const signature = req.headers.get('x-signature') ?? '';
  const payload = await req.text();
  const verified = await adaptador(provedor).verificarWebhook(payload, signature);
  if (!verified) return new Response('invalid', { status: 400 });
  return new Response('ok');
}
`,
      },
    ],
  },
];
