import { Check, Copy } from 'lucide-react';

/** Small mono copy button with a green "Copied" flash state. */
export default function CopyButton({
  copied,
  onClick,
  testid,
}: {
  copied: boolean;
  onClick: () => void;
  testid?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      data-testid={testid}
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 font-mono text-[10px] transition ${
        copied
          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
          : 'border-zinc-700 bg-zinc-950 text-zinc-400 hover:text-zinc-200'
      }`}
    >
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
      <span>{copied ? 'Copied' : 'Copy'}</span>
    </button>
  );
}
