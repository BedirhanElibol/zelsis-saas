import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [12902],
    name: 'PCI4-02 Third-party scripts on payment pages without SRI vs checkout.com provider SDK',
    detects: f('resources/views/checkout.blade.php', `<!doctype html>
<html>
<head>
  <script src="https://cdn.jsdelivr.net/npm/tracker@1.0.0/dist/tracker.min.js"></script>
</head>
<body><form id="payment-form"></form></body>
</html>
`),
    ignores: [
      ...f('resources/views/portal/ninja2020/gateways/checkout/credit_card/authorize.blade.php', `<!doctype html>
<html>
<head>
  <script src="https://cdn.checkout.com/js/framesv2.min.js"></script>
</head>
<body><form id="payment-form"></form></body>
</html>
`),
      ...f('resources/views/portal/ninja2020/gateways/checkout/credit_card/pay_livewire.blade.php', `<!doctype html>
<html>
<head>
  <script src="https://checkout-web-components.checkout.com/index.js" async></script>
</head>
<body><form id="payment-form"></form></body>
</html>
`),
    ],
  },
  {
    ruleIds: [12301],
    name: 'TLS-01 Deprecated TLS 1.0/1.1 protocols permitted vs modern TLS 1.2+ only',
    detects: f('deploy/docker/nginx.conf', `server {
    listen 443 ssl;
    server_name example.com;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
}
`),
    ignores: f('deploy/docker/nginx.conf', `server {
    listen 443 ssl;
    server_name example.com;
    ssl_protocols TLSv1.2 TLSv1.3;
}
`),
  },
];
