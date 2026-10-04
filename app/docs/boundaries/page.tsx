import React from 'react';

export const metadata = { title: 'What We Don\'t Check - Zelsis Docs' };

export default function BoundariesPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white mb-2">Honest Boundaries</h1>
      <p className="text-zinc-400">What Zelsis does <strong>not</strong> check. We believe in transparency about the limits of static analysis.</p>

      <section className="space-y-4 mt-8">
        <div className="bg-emerald-500/10 border border-emerald-500/20 p-4 rounded-lg mb-6">
          <h3 className="text-emerald-400 font-semibold mb-2">Measured Efficacy</h3>
          <p className="text-sm text-zinc-300">
            Based on an audit of <strong>108 real incidents</strong>, our row-based engine achieved a <strong>77% catch rate for HIGH/CRITICAL</strong> vulnerabilities, and an <strong>87% catch rate</strong> when including MEDIUM severity issues.
          </p>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">1. Runtime and DAST</h2>
        <p>
          Zelsis is a Static Application Security Testing (SAST) tool. It analyzes source code at rest. 
          We do not perform Dynamic Application Security Testing (DAST). We do not send payloads to your live endpoints, nor do we monitor runtime execution.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">2. Complex Business Logic Flaws</h2>
        <p>
          Our engine operates line-by-line and file-by-file. It cannot reason about complex, multi-step business logic flaws that span across multiple decoupled systems.
        </p>
        <p className="text-zinc-300">Examples of limitations:</p>
        <ul className="list-disc pl-5 space-y-2">
          <li><strong>IDOR without ownership:</strong> We can detect missing authorization middleware, but we cannot mathematically prove that a specific IDOR check correctly matches the currently logged-in user\'s ID.</li>
          <li><strong>Cross-file context:</strong> We cannot detect a Laravel <code>$guarded = []</code> vulnerability if the dangerous <code>$request-&gt;all()</code> call happens in a completely different, decoupled file.</li>
          <li><strong>Framework-specific implicit routing:</strong> Unauthenticated GraphQL resolvers or FastAPI routes that rely on complex implicit decorators might be missed if they deviate heavily from standard patterns.</li>
          <li><strong>Publicly exposed lists:</strong> Clerk public route lists or intentionally public data that look identical to misconfigurations.</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">3. Live Database Configurations</h2>
        <p>
          We analyze your database schema definitions and migration files (e.g., checking if <code>FOR SELECT USING (true)</code> is used in a SQL file). 
          However, we do <strong>not</strong> connect to your live production database to inspect its running configuration.
        </p>
        <div className="bg-blue-500/10 border border-blue-500/20 p-4 rounded-lg mt-4">
          <p className="text-sm text-blue-400">
            <strong>Recommendation:</strong> To audit the live configuration of a Supabase database, we highly recommend using the official <strong>Supabase Security Advisor</strong> built into their dashboard.
          </p>
        </div>
      </section>
    </div>
  );
}
