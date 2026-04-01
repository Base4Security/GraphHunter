import { LoadingSpinner } from "./LoadingSpinner";

interface SectionLoaderProps {
  message?: string;
  size?: "sm" | "md" | "lg";
}

export function SectionLoader({ message, size = "md" }: SectionLoaderProps) {
  return (
    <div className="section-loader">
      <LoadingSpinner size={size} />
      {message && <span className="section-loader-text">{message}</span>}
    </div>
  );
}
