export interface AuthErrorInfo {
  error?: string;
  message: string;
  hint?: 'sign_in' | 'sign_in_then_create_org' | 'check_invite' | string;
}

export class AuthApiError extends Error {
  status: number;
  code?: string;
  hint?: string;

  constructor(message: string, status: number, code?: string, hint?: string) {
    super(message);
    this.name = 'AuthApiError';
    this.status = status;
    this.code = code;
    this.hint = hint;
  }
}

export function formatAuthError(
  errorInfo: AuthErrorInfo | string | null,
  customActionText?: string
): {
  message: string;
  actionText: string;
  hint?: string;
} | null {
  if (!errorInfo) return null;

  let message = typeof errorInfo === 'string' ? errorInfo : errorInfo.message;
  const hint = typeof errorInfo === 'string' ? undefined : errorInfo.hint;
  let actionText = customActionText || 'Sign in';

  if (hint === 'sign_in') {
    message = 'An account with this email already exists.';
    actionText = customActionText || 'Sign in instead';
  } else if (hint === 'sign_in_then_create_org') {
    message = 'This email already has an account. Sign in to create or join an organization.';
    actionText = customActionText || 'Sign in';
  } else if (hint === 'check_invite') {
    message = 'You have a pending organization invitation! Check your email or sign in to accept.';
    actionText = customActionText || 'Sign in';
  }

  return { message, actionText, hint };
}
