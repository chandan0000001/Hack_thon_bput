import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';

interface LoadingSpinnerProps {
  text?: string;
  fallbackText?: string;
  timeoutMs?: number;
  dynamic?: boolean;
  className?: string;
}

export default function LoadingSpinner({
  text = 'Generating AI explanation...',
  fallbackText = 'Generating heuristic explanation...',
  timeoutMs = 10000,
  dynamic = true,
  className = '',
}: LoadingSpinnerProps) {
  const [currentText, setCurrentText] = useState<string>(text);

  useEffect(() => {
    setCurrentText(text);
    if (!dynamic) return;

    const timer = setTimeout(() => {
      setCurrentText(fallbackText);
    }, timeoutMs);

    return () => clearTimeout(timer);
  }, [text, fallbackText, timeoutMs, dynamic]);

  return (
    <div
      className={`flex items-center gap-2.5 py-3 text-xs text-zinc-400 ${className}`}
      data-testid="explanation-loading-spinner"
    >
      <Loader2 className="h-4 w-4 animate-spin text-red-500" />
      <span>{currentText}</span>
    </div>
  );
}

export { LoadingSpinner };
