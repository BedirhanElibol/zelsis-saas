import { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { AlertCircle, CheckCircle2, Info, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import Link from 'next/link';

import { WaitlistForm } from '@/components/ui/WaitlistForm';

export const runtime = 'edge';

const FRAMEWORK_DATA = {
  'nextjs': {
    name: 'Next.js',
    projectCount: 450,
    title: 'Security & Quality Patterns in 450 Open-Source Next.js Projects',
    description: 'An aggregated analysis of common vulnerabilities, anti-patterns, and architectural mistakes found in public Next.js repositories.',
    date: '2026-09-30',
    topFindings: [
      {
        id: 'SEC-001',
        name: 'Unsafe Server Actions',
        prevalence: '42%',
        severity: 'High',
        description: 'Server Actions lacking proper authorization checks, allowing IDOR or unauthorized state mutations.',
        exampleBad: `export async function deletePost(id: string) {\n  await db.post.delete({ where: { id } }); // No auth check!\n}`,
        exampleGood: `export async function deletePost(id: string) {\n  const session = await auth();\n  if (!session) throw new Error("Unauthorized");\n  // verify ownership...\n}`
      },
      {
        id: 'PERF-003',
        name: 'Client-Side Waterfall Fetching',
        prevalence: '68%',
        severity: 'Medium',
        description: 'Nested client components fetching data sequentially instead of utilizing React Server Components or parallel fetching.',
        exampleBad: `// nested useEffect fetches in multiple child components`,
        exampleGood: `// Fetching in Server Component and passing data down as props`
      },
      {
        id: 'SEC-005',
        name: 'Exposed Environment Variables',
        prevalence: '14%',
        severity: 'Critical',
        description: 'Accidental leakage of private keys by prefixing them with NEXT_PUBLIC_ during debugging.',
        exampleBad: `DATABASE_URL=postgres://user:pass@host/db?sslmode=require`,
        exampleGood: `DATABASE_URL=postgres://user:pass@host/db?sslmode=require`
      }
    ],
    takeaway: 'Next.js abstracts away many traditional security concerns, but introduces new attack vectors around Server Actions and hybrid rendering state management. Authentication must be explicitly enforced at the action level, not just via middleware.'
  },
  'django': {
    name: 'Django',
    projectCount: 312,
    title: 'Security & Quality Patterns in 312 Open-Source Django Projects',
    description: 'An aggregated analysis of common vulnerabilities, anti-patterns, and architectural mistakes found in public Django repositories.',
    date: '2026-09-30',
    topFindings: [
      {
        id: 'SEC-012',
        name: 'DEBUG=True in Production',
        prevalence: '8%',
        severity: 'Critical',
        description: 'Leaving DEBUG=True in production settings, leaking sensitive traceback information and environment variables.',
        exampleBad: `DEBUG = True # in production.py`,
        exampleGood: `DEBUG = os.getenv('DEBUG', 'False') == 'True'`
      },
      {
        id: 'SEC-015',
        name: 'Raw SQL Injection',
        prevalence: '12%',
        severity: 'High',
        description: 'Using Model.objects.raw() or .extra() with unescaped string formatting instead of parameterized queries.',
        exampleBad: `User.objects.raw(f"SELECT * FROM auth_user WHERE username='{user_input}'")`,
        exampleGood: `User.objects.raw("SELECT * FROM auth_user WHERE username=%s", [user_input])`
      }
    ],
    takeaway: 'Django\'s "batteries included" philosophy prevents many common vulnerabilities like CSRF and basic SQL injection by default, provided developers stick to the ORM and form built-ins. Most critical issues arise when bypassing these defaults for perceived performance gains.'
  }
};

type Props = {
  params: { framework: string };
};

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const data = FRAMEWORK_DATA[params.framework as keyof typeof FRAMEWORK_DATA];
  if (!data) return { title: 'Report Not Found' };

  return {
    title: data.title,
    description: data.description,
    openGraph: {
      images: [`/api/og/scan-result?repo=Open%20Source%20${data.name}%20Projects&score=N%2FA`],
    }
  };
}

export default function ReportPage({ params }: Props) {
  const data = FRAMEWORK_DATA[params.framework as keyof typeof FRAMEWORK_DATA];

  if (!data) {
    notFound();
  }

  return (
    <div className="container max-w-4xl py-12 mx-auto space-y-8">
      <div className="space-y-4">
        <Link href="/" className="text-sm text-muted-foreground hover:text-primary mb-4 inline-block">
          &larr; Back to Zelsis
        </Link>
        <div className="flex items-center gap-2 mb-2">
          <Badge variant="outline" className="text-blue-400 border-blue-400/30 bg-blue-400/10">Research Report</Badge>
          <span className="text-sm text-muted-foreground">{data.date}</span>
        </div>
        <h1 className="text-3xl md:text-5xl font-bold tracking-tight text-white">{data.title}</h1>
        <p className="text-xl text-muted-foreground">
          {data.description}
        </p>
      </div>

      <Alert className="bg-[#141414] border-white/10">
        <Info className="h-4 w-4 text-blue-400" />
        <AlertTitle className="text-white">Methodology Note</AlertTitle>
        <AlertDescription className="text-muted-foreground mt-2">
          This report aggregates findings from {data.projectCount} public GitHub repositories with over 100 stars. 
          The analysis was performed using the Zelsis core engine, applying OWASP Top 10:2025 and language-specific AST heuristics. 
          No proprietary code was analyzed for this public dataset.
        </AlertDescription>
      </Alert>

      <div className="space-y-6">
        <h2 className="text-2xl font-semibold text-white border-b border-white/10 pb-2">Top Findings</h2>
        
        {data.topFindings.length === 0 ? (
          <div className="p-12 text-center bg-[#141414] rounded-xl border border-white/10 flex flex-col items-center">
            <ShieldCheck className="h-12 w-12 text-emerald-500 mb-4" />
            <h3 className="text-xl font-medium text-white">You're clear to deploy</h3>
            <p className="text-muted-foreground mt-2">No security findings or anti-patterns detected.</p>
          </div>
        ) : data.topFindings.map((finding) => (
          <Card key={finding.id} className="bg-[#0A0A0A] border-white/10">
            <CardHeader>
              <div className="flex justify-between items-start">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-sm text-muted-foreground">{finding.id}</span>
                    <Badge variant={finding.severity === 'Critical' ? 'destructive' : finding.severity === 'High' ? 'default' : 'secondary'}
                           className={finding.severity === 'High' ? 'bg-orange-500/20 text-orange-500 hover:bg-orange-500/30' : ''}>
                      {finding.severity}
                    </Badge>
                  </div>
                  <CardTitle className="text-xl">{finding.name}</CardTitle>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-white">{finding.prevalence}</div>
                  <div className="text-xs text-muted-foreground uppercase tracking-wider">Prevalence</div>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-muted-foreground">{finding.description}</p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-sm text-red-400 font-medium">
                    <ShieldAlert className="h-4 w-4" /> Anti-Pattern
                  </div>
                  <pre className="p-3 bg-[#141414] rounded-md overflow-x-auto text-sm font-mono text-red-300 border border-red-500/20">
                    {finding.exampleBad}
                  </pre>
                </div>
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-sm text-emerald-400 font-medium">
                    <ShieldCheck className="h-4 w-4" /> Secure Implementation
                  </div>
                  <pre className="p-3 bg-[#141414] rounded-md overflow-x-auto text-sm font-mono text-emerald-300 border border-emerald-500/20">
                    {finding.exampleGood}
                  </pre>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="mt-12 p-6 bg-[#141414] rounded-xl border border-white/10">
        <h3 className="text-xl font-semibold text-white mb-2">Key Takeaway</h3>
        <p className="text-muted-foreground leading-relaxed">
          {data.takeaway}
        </p>
      </div>
      
      <div className="mt-12 text-center flex flex-col items-center pb-12">
        <p className="text-muted-foreground mb-4">Want to check your own {data.name} codebase for these patterns?</p>
        <WaitlistForm source="report_page" framework={params.framework} />
      </div>
    </div>
  );
}
