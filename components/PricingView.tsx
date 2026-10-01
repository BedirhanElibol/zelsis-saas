'use client';

import React from 'react';
import { PricingSection } from '@/components/ui/pricing';
import { useRouter } from 'next/navigation';

export const PricingView: React.FC = () => {
  const router = useRouter();

  const handleSelectPlan = (planId: string) => {
    if (planId === 'free') {
      router.push('/dashboard');
      return;
    }
    router.push(`/checkout?plan=${planId}`);
  };

  return (
    <PricingSection onSelectPlan={handleSelectPlan} />
  );
};
