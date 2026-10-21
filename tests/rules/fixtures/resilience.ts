import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [30341], name: 'RES-01 fetch retried in a tight loop vs a loop that backs off and a paging loop',
    detects: f('src/lib/rates.ts', `export async function getRates(): Promise<Rates> {
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const res = await fetch('https://api.rates.example.com/latest');
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('rates failed', err);
    }
  }
  throw new Error('rates unavailable');
}
`),
    ignores: f('src/lib/rates.ts', `const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
export async function getRates(): Promise<Rates> {
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const res = await fetch('https://api.rates.example.com/latest');
      if (res.ok) return await res.json();
    } catch (err) {
      await sleep(2 ** attempt * 200 + Math.random() * 100);
    }
  }
  throw new Error('rates unavailable');
}

export async function allPages(): Promise<Item[]> {
  const items: Item[] = [];
  for (let page = 1; page <= 10; page++) {
    const res = await fetch(\`https://api.example.com/items?page=\${page}\`);
    items.push(...(await res.json()));
  }
  return items;
}
`),
  },
  {
    ruleIds: [30341], name: 'RES-01 Python requests retried with no sleep vs tenacity backoff',
    detects: f('app/clients/billing.py', `import requests

def fetch_invoice(invoice_id):
    for attempt in range(5):
        try:
            r = requests.get(f"https://billing.example.com/invoices/{invoice_id}", timeout=5)
            r.raise_for_status()
            return r.json()
        except requests.RequestException:
            continue
    raise RuntimeError("billing unavailable")
`),
    ignores: f('app/clients/billing.py', `import requests
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

@retry(stop=stop_after_attempt(5), wait=wait_exponential_jitter())
def fetch_invoice(invoice_id):
    r = requests.get(f"https://billing.example.com/invoices/{invoice_id}", timeout=5)
    r.raise_for_status()
    return r.json()
`),
  },
  {
    ruleIds: [30342], name: 'RES-02 axios-retry with no retryDelay vs exponentialDelay',
    detects: f('src/lib/http.ts', `import axios from 'axios';
import axiosRetry from 'axios-retry';

export const http = axios.create({ baseURL: process.env.API_URL, timeout: 5000 });
axiosRetry(http, { retries: 3 });
`),
    ignores: f('src/lib/http.ts', `import axios from 'axios';
import axiosRetry from 'axios-retry';

export const http = axios.create({ baseURL: process.env.API_URL, timeout: 5000 });
axiosRetry(http, { retries: 3, retryDelay: axiosRetry.exponentialDelay });
`),
  },
];
