import * as React from "react"

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, ...props }, ref) => {
    return (
      <input
        type={type}
        className={className}
        ref={ref}
        aria-label={props["aria-label"] || props.name || "Input"}
        {...props}
      />
    )
  }
)
Input.displayName = "Input"
