import { describe, it } from 'node:test';
import assert from 'node:assert';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AuthErrorBanner, type AuthErrorInfo } from '../components/common/AuthErrorBanner.ts';
import { AuthApiError } from '../components/common/authError.ts';

describe('ORG-IDENTITY: Frontend Graceful Auth UX & 409 Error Banner Tests', () => {
  it('1 AuthErrorBanner renders null when errorInfo is null', () => {
    const html = renderToStaticMarkup(
      React.createElement(AuthErrorBanner, { errorInfo: null })
    );
    assert.strictEqual(html, '');
  });

  it('2 AuthErrorBanner renders generic string error without action', () => {
    const html = renderToStaticMarkup(
      React.createElement(AuthErrorBanner, { errorInfo: 'Invalid credentials' })
    );
    assert.ok(/Invalid credentials/.test(html));
    assert.ok(!/data-testid="auth-error-banner-action"/.test(html));
  });

  it('3 hint="sign_in" renders expected message and "Sign in instead" action button', () => {
    const errorInfo: AuthErrorInfo = {
      error: 'email_exists',
      message: 'Original message',
      hint: 'sign_in',
    };
    const html = renderToStaticMarkup(
      React.createElement(AuthErrorBanner, {
        errorInfo,
        onAction: () => {},
      })
    );
    assert.ok(/An account with this email already exists\./.test(html));
    assert.ok(/Sign in instead/.test(html));
    assert.ok(/data-testid="auth-error-banner-action"/.test(html));
  });

  it('4 hint="sign_in_then_create_org" renders org-create message and "Sign in" button', () => {
    const errorInfo: AuthErrorInfo = {
      error: 'email_exists',
      message: 'Original message',
      hint: 'sign_in_then_create_org',
    };
    const html = renderToStaticMarkup(
      React.createElement(AuthErrorBanner, {
        errorInfo,
        onAction: () => {},
      })
    );
    assert.ok(/This email already has an account\. Sign in to create or join an organization\./.test(html));
    assert.ok(/>Sign in</.test(html));
    assert.ok(/data-testid="auth-error-banner-action"/.test(html));
  });

  it('5 hint="check_invite" renders pending invitation message and "Sign in" button', () => {
    const errorInfo: AuthErrorInfo = {
      error: 'email_exists',
      message: 'Original message',
      hint: 'check_invite',
    };
    const html = renderToStaticMarkup(
      React.createElement(AuthErrorBanner, {
        errorInfo,
        onAction: () => {},
      })
    );
    assert.ok(/You have a pending organization invitation! Check your email or sign in to accept\./.test(html));
    assert.ok(/>Sign in</.test(html));
    assert.ok(/data-testid="auth-error-banner-action"/.test(html));
  });

  it('6 AuthApiError preserves status, code, and hint for 409 conflict handling', () => {
    const err = new AuthApiError(
      'An account with this email already exists.',
      409,
      'email_exists',
      'sign_in_then_create_org'
    );
    assert.strictEqual(err.status, 409);
    assert.strictEqual(err.code, 'email_exists');
    assert.strictEqual(err.hint, 'sign_in_then_create_org');
    assert.strictEqual(err.message, 'An account with this email already exists.');
    assert.strictEqual(err.name, 'AuthApiError');
  });
});
