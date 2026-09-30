'use client';

import { motion } from 'framer-motion';
import React, { useState, useEffect } from 'react';
import { Check, Star as LucideStar, ShieldCheck } from 'lucide-react';
import NumberFlow from '@number-flow/react';
import { ZELSIS_PRICING_PLANS } from '@/data/pricing-plans';

interface PricingProps {
  onSelectPlan?: (planId: string, isAnnual: boolean) => void;
}

export function PricingSection({ onSelectPlan }: PricingProps) {
  const [isAnnual, setIsAnnual] = useState(false);
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
              const annualPriceObj = matchedProduct.prices.find((p: any) => p.recurring_interval === 'year');
              
              return {
                ...plan,
                priceMonthly: monthlyPriceObj ? monthlyPriceObj.price_amount / 100 : plan.priceMonthly,
                priceAnnual: annualPriceObj ? Math.floor((annualPriceObj.price_amount / 100) / 12) : plan.priceAnnual,
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

        {/* Monthly / Annual Toggle Button */}
        <div className="flex items-center gap-3 mt-4 bg-[#0A0A0A] p-1.5 rounded-xl border border-white/10">
          <button
            type="button"
            onClick={() => setIsAnnual(false)}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all ${
              !isAnnual
                ? 'bg-white text-black shadow'
                : 'text-[#A1A1AA] hover:text-white'
            }`}
          >
            Monthly Billing
          </button>

          <button
            type="button"
            onClick={() => setIsAnnual(true)}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
              isAnnual
                ? 'bg-white text-black shadow'
                : 'text-[#A1A1AA] hover:text-white'
            }`}
          >
            <span>Annual Billing</span>
            <span
              className={`px-1.5 py-0.5 rounded text-[0.65rem] font-mono font-extrabold transition-colors ${
                isAnnual
                  ? 'bg-neutral-900 text-emerald-400'
                  : 'bg-white/10 text-emerald-400'
              }`}
            >
              SAVE 20%
            </span>
          </button>
        </div>
      </div>

      {/* 3 Pricing Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full max-w-6xl mx-auto">
        {plans.length === 0 ? (
          <div className="col-span-3 p-8 text-center bg-[#141414] border border-white/10 rounded-xl text-xs text-[#A1A1AA]">
            No pricing tiers available. Contact sales@zelsis.com for enterprise quotes.
          </div>
        ) : (
          plans.map((plan) => {
            const displayPrice = isAnnual ? plan.priceAnnual : plan.priceMonthly;

            return (
              <motion.div
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
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-white text-black text-[0.68rem] font-bold px-3 py-0.5 rounded-full uppercase tracking-wider shadow">
                    <span>MOST POPULAR CHOICE</span>
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
                      {displayPrice === 0 ? 'forever free' : `/ mo ${isAnnual ? '(billed annually)' : ''}`}
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
                  </div>
                </div>

                <button
                  onClick={() => onSelectPlan && onSelectPlan(plan.id, isAnnual)}
                  className={`btn w-full py-3 rounded-lg text-xs font-bold uppercase tracking-wider transition-all mt-4 ${
                    plan.isPopular
                      ? 'btn-primary'
                      : 'btn-secondary'
                  }`}
                >
                  {plan.buttonText}
                </button>
              </motion.div>
            );
          })
        )}
      </div>
    </div>
  );
}
