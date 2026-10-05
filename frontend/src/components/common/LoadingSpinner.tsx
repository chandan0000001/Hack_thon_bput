import { Loader2 } from 'lucide-react';

interface LoadingSpinnerProps {
  text?: string;
  className?: string;
}

export default function LoadingSpinner({
  text = 'Generating AI explanation...',
  className = '',
}: LoadingSpinnerProps) {
  return (
    <div
      className={`flex items-center gap-2.5 py-3 text-xs text-zinc-400 ${className}`}
      data-testid="explanation-loading-spinner"
    >
      <Loader2 className="h-4 w-4 animate-spin text-red-500" />
      <span>{text}</span>
    </div>
  );
}

export { LoadingSpinner };
