import * as React from "react"

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "secondary" | "destructive" | "outline"
}
export function Badge({ className, variant = "default", ...props }: BadgeProps) {
  return <div className={className} {...props} />
}
