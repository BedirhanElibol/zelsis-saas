import { SmoothScroll } from '@/components/SmoothScroll';
import { Navbar } from '@/components/Navbar';
import { SaasHero } from '@/components/saas/SaasHero';
import { ProblemBand } from '@/components/saas/ProblemBand';
import { WorkflowSteps } from '@/components/saas/WorkflowSteps';
import { WhyZelsis } from '@/components/saas/WhyZelsis';
import { ProductCapabilities } from '@/components/saas/ProductCapabilities';
import { WorksWhereYouWork } from '@/components/saas/WorksWhereYouWork';
import { CatchTabs } from '@/components/saas/CatchTabs';
import { FixPromptsDemo } from '@/components/saas/FixPromptsDemo';
import { BenchmarkSection } from '@/components/saas/BenchmarkSection';
import { CompetitorComparison } from '@/components/saas/CompetitorComparison';
import { ComparisonTable } from '@/components/saas/ComparisonTable';
import { FaqSection } from '@/components/saas/FaqSection';
import { FinalCta } from '@/components/saas/FinalCta';
import { Footer } from '@/components/Footer';

// Server Component: the sections are client islands, so the page shell and copy ship as HTML.
export default function Home() {
  return (
    <SmoothScroll>
      <div className="bg-[#0A0A0A] text-[#EDEDED] min-h-full font-sans selection:bg-white selection:text-black">
        <Navbar />

        {/* Hero with the repo scan box and an example failing gate */}
        <SaasHero />

        {/* Order follows what draws a buyer in: the problem, proof on real bugs, how it works and where it runs,
            then depth, trust and price. data-section feeds the "section reached" counts used to tune this order. */}
        {/* What users notice when a rushed release goes out */}
        <div data-section="problem"><ProblemBand /></div>

        {/* Real-bug examples across stacks; every example is scanned by tests/unit/landing-checks.test.ts */}
        <div data-section="examples"><CatchTabs /></div>

        {/* Where the check runs: PR, CLI and agents, VS Code, Jira (each tested end to end) */}
        <div data-section="integrations"><WorksWhereYouWork /></div>

        {/* The release gate: repo → findings → failed build */}
        <div data-section="workflow"><WorkflowSteps /></div>

        <div data-section="fix-demo"><FixPromptsDemo /></div>

        <div data-section="capabilities"><ProductCapabilities /></div>

        {/* Published benchmark: what we catch and what we miss */}
        <div data-section="benchmark"><BenchmarkSection compact /></div>

        <div data-section="competitors"><CompetitorComparison /></div>

        {/* Positioning: quiet gate, audience, and the failure categories it stops */}
        <div data-section="why"><WhyZelsis /></div>

        <div data-section="pricing"><ComparisonTable /></div>

        <div data-section="faq"><FaqSection /></div>

        <FinalCta />

        <Footer />
      </div>
    </SmoothScroll>
  );
}
