'use client';

import { LazyMotion, MotionConfig, domAnimation } from 'framer-motion';
import type { ReactNode } from 'react';

/**
 * Honors prefers-reduced-motion for framer-motion animations, which the global CSS rule cannot reach,
 * and loads only the DOM animation features so components using `m.` stay light.
 */
export function ReducedMotion({ children }: { children: ReactNode }) {
  return (
    <LazyMotion features={domAnimation}>
      <MotionConfig reducedMotion="user">{children}</MotionConfig>
    </LazyMotion>
  );
}
