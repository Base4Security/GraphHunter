import React from "react";
import { LoadingSpinner } from "./LoadingSpinner";

interface LoadingButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  loading?: boolean;
  loadingText?: string;
  spinnerSize?: "sm" | "md";
}

export function LoadingButton({
  loading = false,
  loadingText,
  spinnerSize = "sm",
  children,
  className = "",
  disabled,
  ...props
}: LoadingButtonProps) {
  return (
    <button
      className={`${className}${loading ? " btn-loading" : ""}`}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <>
          <LoadingSpinner size={spinnerSize} />
          {loadingText && <span style={{ marginLeft: 6 }}>{loadingText}</span>}
        </>
      ) : (
        children
      )}
    </button>
  );
}
