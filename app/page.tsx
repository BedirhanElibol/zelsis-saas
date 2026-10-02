import { SmoothScroll } from '@/components/SmoothScroll';
import { Navbar } from '@/components/Navbar';
import { SaasHero } from '@/components/saas/SaasHero';
import { WorkflowSteps } from '@/components/saas/WorkflowSteps';
import { ProductCapabilities } from '@/components/saas/ProductCapabilities';
import { BenchmarkSection } from '@/components/saas/BenchmarkSection';
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

        <WorkflowSteps />

        <ProductCapabilities />

        {/* Published benchmark: what we catch and what we miss */}
        <BenchmarkSection />

        <ComparisonTable />

        <FaqSection />

        <FinalCta />

        <Footer />
      </div>
    </SmoothScroll>
  );
}
