import React from 'react';
import { AlertCircle, ArrowRight } from 'lucide-react';
import { formatAuthError, type AuthErrorInfo } from './authError.ts';

export type { AuthErrorInfo };

export interface AuthErrorBannerProps {
  errorInfo: AuthErrorInfo | string | null;
  onAction?: () => void;
  actionText?: string;
  className?: string;
}

export const AuthErrorBanner: React.FC<AuthErrorBannerProps> = ({
  errorInfo,
  onAction,
  actionText,
  className = '',
}) => {
  const formatted = formatAuthError(errorInfo, actionText);
  if (!formatted) return null;

  const isStacked = formatted.hint === 'use_org_mode';

  return React.createElement(
    'div',
    {
      role: 'alert',
      'data-testid': 'auth-error-banner',
      className: `rounded-lg border border-red-500/30 bg-red-500/10 p-3.5 text-sm text-red-300 transition-all ${className}`,
    },
    isStacked
      ? React.createElement(
          'div',
          { className: 'flex flex-col gap-2.5' },
          React.createElement(
            'div',
            { className: 'flex items-start gap-2.5' },
            React.createElement(AlertCircle, { className: 'mt-0.5 h-4 w-4 shrink-0 text-red-400' }),
            React.createElement('p', { className: 'font-medium text-red-200 leading-snug' }, formatted.message)
          ),
          onAction
            ? React.createElement(
                'div',
                { className: 'pl-6' },
                React.createElement(
                  'button',
                  {
                    type: 'button',
                    onClick: onAction,
                    'data-testid': 'auth-error-banner-action',
                    className:
                      'inline-flex items-center gap-1.5 rounded-md bg-red-600/30 hover:bg-red-600/50 border border-red-500/40 px-3 py-1.5 text-xs font-semibold text-red-100 transition focus:outline-none focus:ring-1 focus:ring-red-400',
                  },
                  React.createElement('span', null, formatted.actionText),
                  React.createElement(ArrowRight, { className: 'h-3 w-3' })
                )
              )
            : null
        )
      : React.createElement(
          'div',
          { className: 'flex items-start justify-between gap-3' },
          React.createElement(
            'div',
            { className: 'flex items-start gap-2.5' },
            React.createElement(AlertCircle, { className: 'mt-0.5 h-4 w-4 shrink-0 text-red-400' }),
            React.createElement('p', { className: 'font-medium text-red-200 leading-snug' }, formatted.message)
          ),
          onAction
            ? React.createElement(
                'button',
                {
                  type: 'button',
                  onClick: onAction,
                  'data-testid': 'auth-error-banner-action',
                  className:
                    'inline-flex shrink-0 items-center gap-1.5 rounded-md bg-red-500/20 px-3 py-1 text-xs font-semibold text-red-200 transition hover:bg-red-500/30 focus:outline-none focus:ring-1 focus:ring-red-400',
                },
                React.createElement('span', null, formatted.actionText),
                React.createElement(ArrowRight, { className: 'h-3 w-3' })
              )
            : null
        )
  );
};
