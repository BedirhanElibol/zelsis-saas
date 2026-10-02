'use client';

import { MotionConfig } from 'framer-motion';
import type { ReactNode } from 'react';

/** Honors prefers-reduced-motion for framer-motion animations, which the global CSS rule cannot reach. */
export function ReducedMotion({ children }: { children: ReactNode }) {
  return <MotionConfig reducedMotion="user">{children}</MotionConfig>;
}
