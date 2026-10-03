'use client';

import { m } from 'framer-motion';
import React, { useState, useEffect } from 'react';
import { Check, Clock } from 'lucide-react';
import NumberFlow from '@number-flow/react';
import { ZELSIS_PRICING_PLANS } from '@/data/pricing-plans';

interface PricingProps {
  onSelectPlan?: (planId: string) => void;
}

export function PricingSection({ onSelectPlan }: PricingProps) {
  const [plans, setPlans] = useState(ZELSIS_PRICING_PLANS);

  useEffect(() => {
    // Fetch live pricing from Polar
    const fetchPricing = async () => {
      try {
        const res = await fetch('/api/v1/products');
        if (res.ok) {
          const products = await res.json();
          // Map products to existing plans based on name or metadata
          const updatedPlans = ZELSIS_PRICING_PLANS.map(plan => {
            const matchedProduct = products.find((p: any) => p.name.toLowerCase().includes(plan.name.toLowerCase().replace('zelsis ', '')));
            if (matchedProduct && matchedProduct.prices) {
              const monthlyPriceObj = matchedProduct.prices.find((p: any) => p.recurring_interval === 'month');

              return {
                ...plan,
                priceMonthly: monthlyPriceObj ? monthlyPriceObj.price_amount / 100 : plan.priceMonthly,
              };
            }
            return plan;
          });
          setPlans(updatedPlans);
        }
      } catch (err) {
        console.error('Failed to fetch live pricing from Polar', err);
      }
    };
    fetchPricing();
  }, []);

  return (
    <div className="flex flex-col items-center gap-10 py-8 max-w-6xl mx-auto w-full px-4">
      {/* Header */}
      <div className="text-center flex flex-col items-center gap-3">
        <div className="px-3 py-1 rounded-full bg-white/5 border border-white/10 text-white text-xs font-mono font-bold uppercase tracking-wider">
          <span>Release Gatekeeper Plans</span>
        </div>
        <h2 className="text-3xl sm:text-4xl font-extrabold text-[#EDEDED]">
          Simple, Predictable Pricing
        </h2>
        <p className="text-sm text-[#A1A1AA] max-w-xl">
          Deploy with confidence. Start free with core AST checks, upgrade when your team needs automated release gating and compliance.
        </p>
        <p className="text-xs text-[#A1A1AA] font-mono">Billed monthly. Cancel anytime.</p>
      </div>

      {/* 3 Pricing Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full max-w-6xl mx-auto">
        {plans.length === 0 ? (
          <div className="col-span-3 p-8 text-center bg-[#141414] border border-white/10 rounded-xl text-xs text-[#A1A1AA]">
            No pricing tiers available right now. Please try again shortly.
          </div>
        ) : (
          plans.map((plan) => {
            const displayPrice = plan.priceMonthly;

            return (
              <m.div
                key={plan.id}
                whileHover={{ y: -4 }}
                transition={{ duration: 0.15 }}
                className={`bg-[#141414] border rounded-xl p-6 sm:p-7 flex flex-col justify-between relative ${
                  plan.isPopular
                    ? 'border-white/30 shadow-xl'
                    : 'border-white/10'
                }`}
              >
                {plan.isPopular && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-emerald-500 text-black text-xs font-bold px-3 py-0.5 rounded-full uppercase tracking-wider shadow">
                    <span>Most popular</span>
                  </div>
                )}

                <div>
                  <h3 className="text-xl font-extrabold text-white">
                    {plan.name}
                  </h3>
                  <p className="text-xs text-[#A1A1AA] mt-1 min-h-[36px]">
                    {plan.description}
                  </p>

                  {/* Price Counter */}
                  <div className="my-6 flex items-baseline gap-1">
                    <span className="text-2xl font-extrabold text-white">$</span>
                    <span className="text-4xl font-extrabold text-white">
                      <NumberFlow value={displayPrice} />
                    </span>
                    <span className="text-xs text-[#A1A1AA] font-bold">
                      {displayPrice === 0 ? 'forever free' : '/ mo'}
                    </span>
                  </div>

                  {/* Features List */}
                  <div className="space-y-3 pt-4 border-t border-white/10">
                    {plan.features.map((feature, idx) => (
                      <div key={idx} className="flex items-center gap-2.5 text-xs text-[#EDEDED]">
                        <Check size={14} className="text-white shrink-0" />
                        <span>{feature}</span>
                      </div>
                    ))}
                    {plan.comingSoon?.map((feature) => (
                      <div key={feature} className="flex items-center gap-2.5 text-xs text-[#A1A1AA]">
                        <Clock size={14} className="text-[#A1A1AA] shrink-0" />
                        <span>{feature}</span>
                        <span className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-[0.6rem] font-mono uppercase tracking-wider shrink-0">Coming soon</span>
                      </div>
                    ))}
                  </div>
                </div>

                <button
                  onClick={() => onSelectPlan && onSelectPlan(plan.id)}
                  className={`btn w-full py-3 rounded-lg text-xs font-bold uppercase tracking-wider transition-all mt-4 ${
                    plan.isPopular
                      ? 'btn-primary'
                      : 'btn-secondary'
                  }`}
                >
                  {plan.buttonText}
                </button>
              </m.div>
            );
          })
        )}
      </div>
    </div>
  );
}
