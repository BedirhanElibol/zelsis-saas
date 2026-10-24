import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [14],
    name: 'SEC-14 real session secret fallback vs masked values (asterisks, bullets, <...>)',
    detects: f('src/auth.ts', "export const secret = process.env.SESSION_SECRET ?? 'tEsTeD';\n"),
    ignores: [
      ...f('apps/cli/branches.ts', 'export const secret = rawDetail.jwt_secret ?? "******";\n'),
      ...f('src/auth/config.ts', "export const secret = process.env.JWT_SECRET || 'jwt_***_secret';\n"),
      ...f('src/auth/session.ts', "export const secret = process.env.AUTH_SECRET ?? 'xxxxxxxx';\n"),
      ...f('src/auth/cookie.ts', "export const secret = process.env.COOKIE_SECRET ?? '<your-cookie-secret>';\n"),
    ],
  },
  {
    ruleIds: [5012],
    name: 'SEC-SECRET-12 real Stripe webhook secret vs masked token',
    detects: f('src/billing/stripe.ts', "export const endpointSecret = 'whsec_9876543210abcdef9876543210abcdef';\n"),
    ignores: [
      ...f('packages/seeds/webhooks.ts', "export const signingSecret = 'whse****mc=';\n"),
      ...f('src/billing/webhook.mock.ts', "export const signingSecret = 'whsec_********************************';\n"),
    ],
  },
  {
    ruleIds: [5046],
    name: 'SEC-SECRET-46 real OpenSSH key vs masked key placeholder',
    detects: f(
      'src/ssh/keys.ts',
      "export const key = '-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\\n-----END OPENSSH PRIVATE KEY-----';\n"
    ),
    ignores: [
      ...f('database/factories/key.ts', "export const dummyKey = '----****--';\n"),
      ...f('src/test/ssh.mock.ts', "export const mock = '-----BEGIN OPENSSH PRIVATE KEY----- ***MASKED*** -----END OPENSSH PRIVATE KEY-----';\n"),
    ],
  },
];

CASES.push({
  ruleIds: [5012],
  name: 'SEC-SECRET-12 a real key stays caught when the line also has a TypeScript generic or a block comment',
  detects: f('src/billing/keys.ts', "export const keys: Record<string, string> = { stripe: 'whsec_9876543210abcdef9876543210abcdef' }; /*** billing ***/\n"),
  ignores: [],
});
