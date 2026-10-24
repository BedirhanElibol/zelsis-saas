import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const VITE = { path: 'package.json', content: '{ "dependencies": { "react": "18.3.1" }, "devDependencies": { "vite": "5.4.0" } }' };

export const CASES: RuleCase[] = [
  {
    ruleIds: [29791], name: 'FAKE-01 placeholder payment key',
    detects: f('src/utils/razorpay.ts', `export const options = {
  key: 'YOUR_RAZORPAY_KEY',
  currency: 'INR',
};
`),
    ignores: f('src/utils/razorpay.ts', `export const options = {
  key: import.meta.env.VITE_RAZORPAY_KEY_ID,
  currency: 'INR',
  placeholder: 'Enter amount',
};
`),
  },
  {
    ruleIds: [29792], name: 'FAKE-02 upgrade faked with a timer',
    detects: f('src/contexts/AuthContext.tsx', `export function useUpgrade(user, setUser, setLoading) {
  const upgradeAccount = async () => {
    setLoading(true);
    await new Promise((resolve) => setTimeout(resolve, 1000));
    setUser({ ...user, isPremium: true });
    setLoading(false);
  };
  return upgradeAccount;
}
`),
    ignores: f('src/contexts/AuthContext.tsx', `export function useUpgrade(user, setUser, setLoading) {
  const upgradeAccount = async () => {
    setLoading(true);
    const res = await fetch('/api/checkout', { method: 'POST' });
    const { url } = await res.json();
    window.location.href = url;
  };
  return upgradeAccount;
}
`),
  },
  {
    ruleIds: [29793], name: 'FAKE-03 API call commented out before success',
    detects: f('src/features/Apply.tsx', `export function useApply(setIsSuccess) {
  const onSubmit = async (data) => {
    try {
      // await submitApplication(data);
      setIsSuccess(true);
    } catch (error) {
      console.error(error);
    }
  };
  return onSubmit;
}
`),
    ignores: f('src/features/Apply.tsx', `export function useApply(setIsSuccess) {
  const onSubmit = async (data) => {
    try {
      // send it to the admissions API
      await submitApplication(data);
      setIsSuccess(true);
    } catch (error) {
      console.error(error);
    }
  };
  return onSubmit;
}
`),
  },
  {
    ruleIds: [29794], name: 'FAKE-04 contact form never sends',
    detects: f('src/pages/Contact.tsx', `import { useState } from 'react';
export default function Contact() {
  const [submitted, setSubmitted] = useState(false);
  const handleSubmit = (e) => {
    e.preventDefault();
    setSubmitted(true);
  };
  return <form onSubmit={handleSubmit}><button type="submit">Send</button>{submitted && <p>Thanks!</p>}</form>;
}
`),
    ignores: f('src/pages/Contact.tsx', `import { useState } from 'react';
export default function Contact() {
  const [submitted, setSubmitted] = useState(false);
  const handleSubmit = async (e) => {
    e.preventDefault();
    await fetch('https://formspree.io/f/abc', { method: 'POST', body: new FormData(e.target) });
    setSubmitted(true);
  };
  return <form onSubmit={handleSubmit}><button type="submit">Send</button>{submitted && <p>Thanks!</p>}</form>;
}
`),
  },
  {
    ruleIds: [29795], name: 'FAKE-05 download button with no handler',
    detects: f('src/modules/Documents.tsx', `export function DocRow({ doc }) {
  return (
    <tr>
      <td>{doc.name}</td>
      <td><button className="text-green-600" title="Download">Download</button></td>
    </tr>
  );
}
`),
    ignores: f('src/modules/Documents.tsx', `export function DocRow({ doc, onDownload }) {
  return (
    <tr>
      <td>{doc.name}</td>
      <td><button className="text-green-600" onClick={() => onDownload(doc.id)}>Download</button></td>
    </tr>
  );
}
`),
  },
  {
    ruleIds: [29796], name: 'FAKE-06 link to #',
    detects: f('src/components/Footer.tsx', `export function Footer() {
  return <footer><a href="#" className="icon">Twitter</a></footer>;
}
`),
    ignores: f('src/components/Footer.tsx', `export function Footer() {
  return <footer><a href="https://twitter.com/acme" className="icon">Twitter</a><a href="#" onClick={() => window.scrollTo(0, 0)}>Top</a></footer>;
}
`),
  },
  {
    ruleIds: [29797], name: 'FAKE-07 hard-coded password check',
    detects: f('src/contexts/AuthContext.tsx', `export function login(users, email, password) {
  const found = users.find((u) => u.email === email);
  if (found && password === 'demo123') return found;
  return null;
}
`),
    ignores: f('src/contexts/AuthContext.tsx', `export async function login(supabase, email, password) {
  if (typeof password === 'string' && password.length < 8) return null;
  const { data } = await supabase.auth.signInWithPassword({ email, password });
  return data.user;
}
`),
  },
  {
    ruleIds: [29798], name: 'BUG-144 removeEventListener with a new arrow',
    detects: f('src/App.tsx', `import { useEffect } from 'react';
export function App() {
  useEffect(() => {
    window.addEventListener('popstate', () => console.log('back'));
    return () => window.removeEventListener('popstate', () => {});
  }, []);
  return null;
}
`),
    ignores: f('src/App.tsx', `import { useEffect } from 'react';
export function App() {
  useEffect(() => {
    const onPop = () => console.log('back');
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);
  return null;
}
`),
  },
  {
    ruleIds: [29799], name: 'BUG-145 process.env in a Vite app',
    detects: [VITE, { path: 'src/api/analyze.ts', content: `export const client = { apiKey: process.env.OPENAI_API_KEY };
` }],
    ignores: [VITE, { path: 'src/api/analyze.ts', content: `export const client = { baseUrl: import.meta.env.VITE_API_URL, debug: process.env.NODE_ENV === 'development' };
` }],
  },
  {
    ruleIds: [29800], name: 'BUG-146 week-long setTimeout in a server action',
    detects: f('app/actions.ts', `'use server';
export async function scheduleDeletion(url: string) {
  setTimeout(async () => { await del(url); }, 7 * 24 * 60 * 60 * 1000);
}
`),
    ignores: f('app/actions.ts', `'use server';
export async function retryLater(fn: () => Promise<void>) {
  setTimeout(fn, 500);
}
`),
  },
  {
    ruleIds: [29801], name: 'BUG-147 identical ternary branches',
    detects: f('src/services/api.ts', `const API_BASE_URL = import.meta.env.MODE === 'development' ? 'http://localhost:5000/api' : 'http://localhost:5000/api';
export default API_BASE_URL;
`),
    ignores: f('src/services/api.ts', `const API_BASE_URL = import.meta.env.MODE === 'development' ? 'http://localhost:5000/api' : 'https://api.example.com/api';
export default API_BASE_URL;
`),
  },
  {
    ruleIds: [29802], name: 'BUG-148 insert with user?.id and no session check',
    detects: f('src/hooks/useTools.ts', `export async function addTool(supabase, user, name) {
  return supabase.from('tools').insert({ name, user_id: user?.id });
}
`),
    ignores: f('src/hooks/useTools.ts', `export async function addTool(supabase, user, name) {
  if (!user) throw new Error('Sign in first');
  return supabase.from('tools').insert({ name, user_id: user.id });
}
`),
  },
  {
    ruleIds: [29803], name: 'FAKE-08 test-mode payment key hard-coded',
    detects: f('src/pages/Payment.jsx', `export const RZP_KEY = 'rzp_test_1DP5mmOlF5G5ag';
`),
    ignores: f('src/pages/Payment.jsx', `export const RZP_KEY = import.meta.env.VITE_RAZORPAY_KEY_ID;
`),
  },
  {
    ruleIds: [29804], name: 'FAKE-09 register returns a mock token',
    detects: f('src/services/api.ts', `export async function register(data) {
  return { token: 'mock-jwt-token', user: { id: 1, ...data } };
}
`),
    ignores: f('src/services/api.ts', `export async function register(api, data) {
  const res = await api.post('/auth/register', data);
  return { token: res.token, user: res.user };
}
`),
  },
  {
    ruleIds: [29861], name: 'FAKE-10 refund only updates local state',
    detects: f('src/pages/Orders.tsx', `import { useState } from 'react';
import { toast } from 'sonner';
export default function Orders({ initial }: { initial: { id: string; status: string }[] }) {
  const [orders, setOrders] = useState(initial);
  const handleRefundOrder = (id: string) => {
    setOrders((prev) => prev.map((o) => (o.id === id ? { ...o, status: 'refunded' } : o)));
    toast.success('Refund issued');
  };
  return <ul>{orders.map((o) => <li key={o.id} onClick={() => handleRefundOrder(o.id)}>{o.status}</li>)}</ul>;
}
`),
    ignores: f('src/pages/Orders.tsx', `import { useState } from 'react';
import { toast } from 'sonner';
export default function Orders({ initial }: { initial: { id: string; status: string }[] }) {
  const [orders, setOrders] = useState(initial);
  const handleRefundOrder = async (id: string) => {
    const res = await fetch('/api/refunds', { method: 'POST', body: JSON.stringify({ id }) });
    if (!res.ok) return toast.error('Refund failed');
    setOrders((prev) => prev.map((o) => (o.id === id ? { ...o, status: 'refunded' } : o)));
  };
  const handleRemoveRow = (id: string) => setOrders((prev) => prev.filter((o) => o.id !== id));
  return <ul>{orders.map((o) => <li key={o.id} onClick={() => handleRefundOrder(o.id)} onDoubleClick={() => handleRemoveRow(o.id)}>{o.status}</li>)}</ul>;
}
`),
  },
  {
    ruleIds: [29862], name: 'FAKE-11 coupon checked against a constant in the browser',
    detects: f('src/components/Checkout.tsx', `import { useState } from 'react';
export function Checkout({ price }: { price: number }) {
  const [couponCode, setCouponCode] = useState('');
  const total = couponCode.toUpperCase() === 'SAVE20' ? price * 0.8 : price;
  return <input value={couponCode} onChange={(e) => setCouponCode(e.target.value)} placeholder={String(total)} />;
}
`),
    ignores: f('src/components/Checkout.tsx', `import { useState } from 'react';
export function Checkout({ price }: { price: number }) {
  const [couponCode, setCouponCode] = useState('');
  const [discountType] = useState<'percent' | 'fixed'>('percent');
  const label = discountType === 'percent' ? '%' : '$';
  return <input value={couponCode} onChange={(e) => setCouponCode(e.target.value)} placeholder={label + price} />;
}
`),
  },
  {
    ruleIds: [29863], name: 'FAKE-12 OTP accepted by length only',
    detects: f('src/components/TwoFactor.tsx', `import { useState } from 'react';
export function TwoFactor() {
  const [otp, setOtp] = useState('');
  const [verified, setVerified] = useState(false);
  const handleVerify = () => {
    if (otp.length === 6) setVerified(true);
  };
  return <div><input value={otp} onChange={(e) => setOtp(e.target.value)} /><button onClick={handleVerify}>{String(verified)}</button></div>;
}
`),
    ignores: f('src/components/TwoFactor.tsx', `import { useState } from 'react';
export function TwoFactor() {
  const [otp, setOtp] = useState('');
  const [verified, setVerified] = useState(false);
  const handleVerify = async () => {
    if (otp.length !== 6) return;
    const res = await fetch('/api/2fa/verify', { method: 'POST', body: JSON.stringify({ otp }) });
    if (res.ok) setVerified(true);
  };
  return <div><input value={otp} onChange={(e) => setOtp(e.target.value)} /><button onClick={handleVerify}>{String(verified)}</button></div>;
}
`),
  },
  {
    ruleIds: [29864], name: 'FAKE-13 live metrics from Math.random',
    detects: f('src/components/ServerStats.tsx', `import { useEffect, useState } from 'react';
export function ServerStats() {
  const [cpu, setCpu] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setCpu(Math.round(Math.random() * 100)), 2000);
    return () => clearInterval(id);
  }, []);
  return <span>{cpu}%</span>;
}
`),
    ignores: f('src/components/ServerStats.tsx', `import { useEffect, useState } from 'react';
export function ServerStats() {
  const [cpu, setCpu] = useState(0);
  useEffect(() => {
    const id = setInterval(async () => setCpu((await (await fetch('/api/stats')).json()).cpu), 2000);
    return () => clearInterval(id);
  }, []);
  return <span>{cpu}%</span>;
}
`),
  },
  {
    ruleIds: [29865], name: 'FAKE-14 recovery codes generated only in the browser',
    detects: f('src/components/Security.tsx', `import { useState } from 'react';
export function Security() {
  const [codes, setCodes] = useState<string[]>([]);
  const handleGenerateRecoveryCodes = () => {
    setCodes(Array.from({ length: 8 }, () => Math.random().toString(36).slice(2, 10)));
  };
  return <button onClick={handleGenerateRecoveryCodes}>{codes.join(' ')}</button>;
}
`),
    ignores: f('src/components/Security.tsx', `import { useState } from 'react';
export function Security() {
  const [codes, setCodes] = useState<string[]>([]);
  const handleGenerateRecoveryCodes = async () => {
    const res = await fetch('/api/2fa/recovery-codes', { method: 'POST' });
    setCodes((await res.json()).codes);
  };
  return <button onClick={handleGenerateRecoveryCodes}>{codes.join(' ')}</button>;
}
`),
  },
  {
    ruleIds: [29866], name: 'FAKE-15 JSON saved as application/pdf',
    detects: f('src/components/Invoice.tsx', `export function Invoice({ invoice }: { invoice: { id: string; total: number } }) {
  const download = () => {
    const blob = new Blob([JSON.stringify(invoice)], { type: 'application/pdf' });
    window.open(URL.createObjectURL(blob));
  };
  return <button onClick={download}>Download PDF</button>;
}
`),
    ignores: f('src/components/Invoice.tsx', `import { jsPDF } from 'jspdf';
export function Invoice({ invoice }: { invoice: { id: string; total: number } }) {
  const download = () => {
    const doc = new jsPDF();
    doc.text('Invoice ' + invoice.id, 10, 10);
    const blob = new Blob([doc.output('arraybuffer')], { type: 'application/pdf' });
    window.open(URL.createObjectURL(blob));
  };
  return <button onClick={download}>Download PDF</button>;
}
`),
  },
];
