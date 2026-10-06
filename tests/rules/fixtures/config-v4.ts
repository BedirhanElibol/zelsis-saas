import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29201], name: 'CFG-01 Firestore test-mode rule shipped',
    detects: f('firestore.rules', `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.time < timestamp.date(2026, 12, 1);
    }
  }
}
`),
    ignores: f('firestore.rules', `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
`)
  },
  {
    ruleIds: [29202], name: 'CFG-02 nginx autoindex on',
    detects: f('deploy/nginx/default.conf', `server {
  listen 80;
  root /var/www/app;
  location /uploads/ {
    autoindex on;
  }
}
`),
    ignores: f('deploy/nginx/default.conf', `server {
  listen 80;
  root /var/www/app;
  location /uploads/ {
    try_files $uri =404;
  }
}
`)
  },
  {
    ruleIds: [29203], name: 'CFG-03 Supabase redirect wildcard on vercel.app',
    detects: f('supabase/config.toml', `[auth]
site_url = "https://myapp.com"
additional_redirect_urls = ["https://myapp.com/auth/callback", "https://*.vercel.app/**"]
`),
    ignores: f('supabase/config.toml', `[auth]
site_url = "https://myapp.com"
additional_redirect_urls = ["https://myapp.com/auth/callback", "https://myapp-*-acme.vercel.app/**"]
`)
  },
];
