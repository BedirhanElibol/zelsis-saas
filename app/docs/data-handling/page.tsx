import React from 'react';

export const metadata = { title: 'Data Handling - Zelsis Docs' };

export default function DataHandlingPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Data Handling & Security</h1>
      <p className="text-zinc-400">How we process, store, and secure your source code and vulnerability data.</p>

      <section className="space-y-4 mt-8">
        <h2 className="text-xl font-semibold text-white">What We Store</h2>
        <p>
          Zelsis temporarily processes your source code to perform static analysis. 
          We store metadata about findings (rule codes, file paths, and exact line numbers) to display them in your dashboard.
        </p>
        <p>
          Code snippets surrounding vulnerabilities are stored briefly to provide context within the dashboard.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Data Retention & Location</h2>
        <ul className="list-disc pl-5 space-y-2">
          <li><strong>Retention:</strong> All vulnerability findings and associated code snippets are automatically permanently deleted after <strong>30 days</strong>.</li>
          <li><strong>Region:</strong> All data is stored securely in our Supabase infrastructure located in <strong>Frankfurt, Germany (eu-central-1)</strong>, ensuring strict compliance with GDPR and European data protection standards.</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Service Role Security</h2>
        <p>
          Database operations that bypass Row Level Security (RLS) for system-level background jobs are performed using the <code>SUPABASE_SERVICE_ROLE_KEY</code>. 
          This key is strictly confined to secure backend server environments and is <strong>never</strong> exposed to the client or browser. 
          All user-facing data access is governed by strict RLS policies ensuring users can only access their own organization\'s data.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Architecture Overview</h2>
        <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto border border-white/10">
          <code className="text-zinc-300">
{`graph TD
    Client[Client / GitHub Action] -->|Trigger Scan| API[Zelsis API (Next.js Server)]
    API -->|Clone & Analyze| Engine[Static Analysis Engine]
    Engine -->|Extract Findings| API
    API -->|Secure Write (Service Role)| DB[(Supabase DB - Frankfurt)]
    DB -->|30-Day Purge| /dev/null`}
          </code>
        </pre>
        <p className="text-xs text-zinc-500 mt-2">Diagram: High-level data flow and retention.</p>
      </section>
    </div>
  );
}
