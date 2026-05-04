import { Loader2 } from "lucide-react";

const sizes = { sm: 14, md: 18, lg: 24 } as const;

interface LoadingSpinnerProps {
  size?: keyof typeof sizes;
  className?: string;
}

export function LoadingSpinner({ size = "sm", className = "" }: LoadingSpinnerProps) {
  return (
    <span className={`loading-spinner ${className}`}>
      <Loader2 size={sizes[size]} />
    </span>
  );
}
