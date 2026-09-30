import * as React from "react"

export const Alert = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(({ className, ...props }, ref) => <div ref={ref} className={className} {...props} />)
Alert.displayName = "Alert"
export const AlertTitle = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLHeadingElement>>(({ className, ...props }, ref) => <h5 ref={ref} className={className} {...props} />)
AlertTitle.displayName = "AlertTitle"
export const AlertDescription = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(({ className, ...props }, ref) => <div ref={ref} className={className} {...props} />)
AlertDescription.displayName = "AlertDescription"
