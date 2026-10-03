'use client';

import React, { useState, useEffect } from 'react';
import Image from 'next/image';

interface UserAvatarProps {
  src?: string | null;
  name?: string | null;
  size?: number;
  className?: string;
  alt?: string;
}

/**
 * Production User Avatar component with zero-layout-shift and defensive error fallback.
 * Adheres to UI_ENGINEERING_STANDARDS.md (Rule 5: Avatar & Image Fallbacks).
 * Never displays broken browser graphic placeholders if Google/external CDN 403s or fails.
 */
export const UserAvatar: React.FC<UserAvatarProps> = ({
  src,
  name,
  size = 28,
  className = '',
  alt
}) => {
  const [hasError, setHasError] = useState(false);

  // Reset error state whenever the avatar source prop changes
  useEffect(() => {
    setHasError(false);
  }, [src]);

  const cleanInitial = (name || 'U').trim().charAt(0).toUpperCase() || 'U';
  const effectiveAlt = alt || name || 'User Avatar';

  if (!src || hasError) {
    return (
      <div
        style={{ width: `${size}px`, height: `${size}px` }}
        className={`rounded-full bg-white/10 border border-white/20 flex items-center justify-center font-bold text-white shrink-0 select-none ${className}`}
        role="img"
        aria-label={effectiveAlt}
      >
        <span aria-hidden="true" style={{ fontSize: `${Math.max(10, Math.floor(size * 0.38))}px` }}>
          {cleanInitial}
        </span>
      </div>
    );
  }

  return (
    <Image
      src={src}
      alt={effectiveAlt}
      width={size}
      height={size}
      unoptimized
      onError={() => setHasError(true)}
      style={{ width: `${size}px`, height: `${size}px` }}
      className={`rounded-full object-cover border border-white/20 shrink-0 ${className}`}
    />
  );
};
