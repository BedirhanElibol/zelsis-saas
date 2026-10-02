'use client';

import React, { useEffect } from 'react';

export const SmoothScroll: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  useEffect(() => {
    if (typeof window === 'undefined') return;

    // Respect OS prefers-reduced-motion accessibility preference (F-34); touch devices keep native
    // scrolling, which is smoother there and avoids a permanent animation-frame loop.
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || window.matchMedia('(pointer: coarse)').matches) {
      return;
    }

    let lenis: any;
    let animationId: number;

    import('lenis').then((LenisModule) => {
      // Re-verify in case accessibility preference changed
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        return;
      }

      const Lenis = LenisModule.default;
      lenis = new Lenis({
        duration: 1.2,
        easing: (t: number) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
        orientation: 'vertical',
        gestureOrientation: 'vertical',
        smoothWheel: true,
        wheelMultiplier: 1,
        touchMultiplier: 2,
      });

      function raf(time: number) {
        if (lenis) lenis.raf(time);
        animationId = requestAnimationFrame(raf);
      }

      animationId = requestAnimationFrame(raf);
    }).catch(err => console.error("Lenis smooth scroll error:", err));

    return () => {
      if (animationId) cancelAnimationFrame(animationId);
      if (lenis && typeof lenis.destroy === 'function') lenis.destroy();
    };
  }, []);

  return <>{children}</>;
};
