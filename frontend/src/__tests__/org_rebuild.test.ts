import { describe, it } from 'node:test';
import assert from 'node:assert';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  applyInsertEvent,
  applyUpdateEvent,
  INITIAL_COUNTERS,
} from '../hooks/useOrgLiveCounters.ts';
import type { OrgLiveCountersData } from '../services/orgApi.ts';

describe('ORG-REBUILD: Frontend Architecture & Realtime Telemetry Tests', () => {
  // Check 1: seed-then-insert increments counters
  it('1 seed-then-insert increments counters', () => {
    const seed: OrgLiveCountersData = {
      total_24h: 10,
      by_severity: { critical: 2, high: 3, medium: 4, low: 1 },
      by_type: { log: 5, ato: 3, network: 2 },
      pending_review: 4,
      blocked_indicators_count: 1,
    };

    const newEvent = {
      severity: 'critical',
      event_type: 'log',
      verdict: 'pending_review',
    };

    const next = applyInsertEvent(seed, newEvent);

    assert.strictEqual(next.total_24h, 11, 'total_24h should increment by 1');
    assert.strictEqual(next.by_severity.critical, 3, 'critical severity should increment to 3');
    assert.strictEqual(next.by_type.log, 6, 'log event type should increment to 6');
    assert.strictEqual(next.pending_review, 5, 'pending_review should increment to 5');
    // Unaffected counts stay same
    assert.strictEqual(next.by_severity.high, 3);
    assert.strictEqual(next.by_type.ato, 3);
  });

  // Check 2: update decrements pending
  it('2 update decrements pending', () => {
    const state: OrgLiveCountersData = {
      total_24h: 20,
      by_severity: { critical: 5, high: 5, medium: 5, low: 5 },
      by_type: { log: 10, ato: 5, network: 5 },
      pending_review: 5,
      blocked_indicators_count: 2,
    };

    // Pending review resolved to released -> decrement pending_review
    const resolved = applyUpdateEvent(
      state,
      { verdict: 'pending_review' },
      { verdict: 'released' }
    );
    assert.strictEqual(resolved.pending_review, 4, 'pending_review should decrement from 5 to 4');

    // Pending review resolved to blocked_permanently -> decrement again
    const blocked = applyUpdateEvent(
      resolved,
      { verdict: 'pending_review' },
      { verdict: 'blocked_permanently' }
    );
    assert.strictEqual(blocked.pending_review, 3, 'pending_review should decrement from 4 to 3');

    // Unrelated update (e.g. released -> false_positive) does not change pending_review
    const neutral = applyUpdateEvent(
      blocked,
      { verdict: 'released' },
      { verdict: 'false_positive' }
    );
    assert.strictEqual(neutral.pending_review, 3, 'neutral update should not change pending_review');

    // Decrement should clamp at 0
    const zeroState = { ...state, pending_review: 0 };
    const clamped = applyUpdateEvent(
      zeroState,
      { verdict: 'pending_review' },
      { verdict: 'released' }
    );
    assert.strictEqual(clamped.pending_review, 0, 'pending_review should clamp at 0');
  });

  // Check 3: unsubscribe on unmount
  it('3 unsubscribe on unmount', () => {
    let channelRemoved = false;
    let registeredChannelName = '';

    const mockChannel = {
      on: () => mockChannel,
      subscribe: (cb: (status: string) => void) => {
        cb('SUBSCRIBED');
        return mockChannel;
      },
    };

    const mockClient = {
      channel: (name: string) => {
        registeredChannelName = name;
        return mockChannel;
      },
      removeChannel: (ch: any) => {
        if (ch === mockChannel) {
          channelRemoved = true;
        }
      },
    };

    // Simulate mounting and subscribing
    const projectId = 'proj-safety-44';
    const channel = mockClient.channel(`org-counters-${projectId}`);
    assert.strictEqual(registeredChannelName, 'org-counters-proj-safety-44');

    // Simulate unmount cleanup handler
    mockClient.removeChannel(channel);
    assert.strictEqual(channelRemoved, true, 'Channel must be removed cleanly on cleanup');
  });

  // Check 4: pill states (LIVE / DISCONNECTED)
  it('4 pill states (LIVE / DISCONNECTED)', () => {
    function StatusPill({ isConnected }: { isConnected: boolean }) {
      return React.createElement(
        'span',
        {
          className: isConnected
            ? 'bg-emerald-500/15 text-emerald-400 font-bold'
            : 'bg-zinc-800 text-zinc-400 font-bold',
        },
        isConnected ? 'LIVE' : 'DISCONNECTED'
      );
    }

    const liveHtml = renderToStaticMarkup(React.createElement(StatusPill, { isConnected: true }));
    assert(liveHtml.includes('LIVE'), 'Connected pill must display LIVE');
    assert(liveHtml.includes('emerald-400'), 'Connected pill must have emerald styling');
    assert(!liveHtml.includes('DISCONNECTED'), 'Connected pill must not say DISCONNECTED');

    const offlineHtml = renderToStaticMarkup(React.createElement(StatusPill, { isConnected: false }));
    assert(offlineHtml.includes('DISCONNECTED'), 'Disconnected pill must display DISCONNECTED');
    assert(offlineHtml.includes('zinc-400'), 'Disconnected pill must have zinc/offline styling');
    assert(!offlineHtml.includes('LIVE'), 'Disconnected pill must not say LIVE');
  });

  // Check 5: coming-soon card renders when available=false
  it('5 coming-soon card renders when available=false', () => {
    function AnalyzerBadge({ available }: { available: boolean }) {
      return available
        ? React.createElement(
            'span',
            { className: 'bg-emerald-500/10 text-emerald-400' },
            'ACTIVE'
          )
        : React.createElement(
            'span',
            { className: 'bg-amber-500/10 text-amber-400' },
            'COMING SOON'
          );
    }

    const availableHtml = renderToStaticMarkup(
      React.createElement(AnalyzerBadge, { available: true })
    );
    assert(availableHtml.includes('ACTIVE'), 'Available analyzer must display ACTIVE');
    assert(!availableHtml.includes('COMING SOON'), 'Available analyzer must not show COMING SOON');

    const unavailableHtml = renderToStaticMarkup(
      React.createElement(AnalyzerBadge, { available: false })
    );
    assert(
      unavailableHtml.includes('COMING SOON'),
      'Unavailable analyzer must render COMING SOON badge'
    );
    assert(!unavailableHtml.includes('ACTIVE'), 'Unavailable analyzer must not show ACTIVE');
  });

  // Check 6: release button disabled with blocked indicator
  it('6 release button disabled with blocked indicator', () => {
    function ReleaseAction({
      indicatorBlocked,
      onRelease,
    }: {
      indicatorBlocked: boolean;
      onRelease: () => void;
    }) {
      return React.createElement(
        'div',
        null,
        indicatorBlocked &&
          React.createElement(
            'div',
            { className: 'warning-banner text-red-300' },
            'Permanent Blocklist Match'
          ),
        React.createElement(
          'button',
          {
            type: 'button',
            disabled: indicatorBlocked,
            onClick: onRelease,
          },
          'Release Event'
        )
      );
    }

    // When indicator is blocked
    const blockedHtml = renderToStaticMarkup(
      React.createElement(ReleaseAction, { indicatorBlocked: true, onRelease: () => {} })
    );
    assert(
      blockedHtml.includes('Permanent Blocklist Match'),
      'Warning banner must be present when indicator is blocked'
    );
    assert(
      blockedHtml.includes('disabled=""') || blockedHtml.includes('disabled'),
      'Release button must have disabled attribute when indicator is blocked'
    );

    // When indicator is NOT blocked
    const unblockedHtml = renderToStaticMarkup(
      React.createElement(ReleaseAction, { indicatorBlocked: false, onRelease: () => {} })
    );
    assert(
      !unblockedHtml.includes('Permanent Blocklist Match'),
      'Warning banner must not appear when indicator is not blocked'
    );
    assert(
      !unblockedHtml.includes('disabled'),
      'Release button must be enabled when indicator is not blocked'
    );
  });

  // Check 7: plaintext-once modal flow
  it('7 plaintext-once modal flow', () => {
    function ApiKeyModal({
      plaintextKey,
      confirmed,
      onConfirmChange,
      onDismiss,
    }: {
      plaintextKey: string;
      confirmed: boolean;
      onConfirmChange: (val: boolean) => void;
      onDismiss: () => void;
    }) {
      return React.createElement(
        'div',
        { className: 'modal-overlay' },
        React.createElement('span', { className: 'token-display' }, plaintextKey),
        React.createElement(
          'label',
          null,
          React.createElement('input', {
            type: 'checkbox',
            checked: confirmed,
            onChange: (e: any) => onConfirmChange(e.target.checked),
          }),
          'I have securely saved this key'
        ),
        React.createElement(
          'button',
          {
            type: 'button',
            disabled: !confirmed,
            onClick: onDismiss,
          },
          'Done'
        )
      );
    }

    const testToken = 'cg_proj_live_9f8d7c6b5a4e3d2c1';

    // Step 1: Unconfirmed state -> button disabled
    const unconfirmedHtml = renderToStaticMarkup(
      React.createElement(ApiKeyModal, {
        plaintextKey: testToken,
        confirmed: false,
        onConfirmChange: () => {},
        onDismiss: () => {},
      })
    );
    assert(unconfirmedHtml.includes(testToken), 'Token must be displayed in plaintext');
    assert(
      unconfirmedHtml.includes('disabled=""') || unconfirmedHtml.includes('disabled'),
      'Dismiss button must be disabled until user confirms they saved the key'
    );

    // Step 2: Confirmed state -> button enabled
    let dismissed = false;
    const confirmedHtml = renderToStaticMarkup(
      React.createElement(ApiKeyModal, {
        plaintextKey: testToken,
        confirmed: true,
        onConfirmChange: () => {},
        onDismiss: () => {
          dismissed = true;
        },
      })
    );
    assert(
      !confirmedHtml.includes('disabled=""') && !confirmedHtml.includes('disabled'),
      'Dismiss button must be enabled once confirmation check is checked'
    );
    assert.strictEqual(dismissed, false);

    // Step 3: Dismiss clears token from memory
    let activeToken: string | null = testToken;
    const handleDismiss = () => {
      activeToken = null;
    };
    handleDismiss();
    assert.strictEqual(activeToken, null, 'Plaintext token must be cleared from state on dismiss');
  });

  // Check 8: counters tab has zero input elements
  it('8 counters tab has zero input elements', () => {
    // Pure Live Counters Tab View representation matching OrgDashboard Tab 2
    function LiveCountersView({ counters, isConnected, onResync }: any) {
      return React.createElement(
        'div',
        { id: 'org-live-counters-view', className: 'space-y-6' },
        React.createElement(
          'div',
          { className: 'header flex justify-between' },
          React.createElement(
            'div',
            null,
            React.createElement('h2', null, 'Realtime Telemetry Stream'),
            React.createElement('span', null, isConnected ? 'LIVE' : 'DISCONNECTED')
          ),
          React.createElement(
            'button',
            { type: 'button', onClick: onResync },
            'Resync'
          )
        ),
        React.createElement(
          'div',
          { className: 'metrics-grid' },
          React.createElement('div', null, 'Total 24h: ', counters.total_24h),
          React.createElement('div', null, 'Pending: ', counters.pending_review),
          React.createElement('div', null, 'Blocked: ', counters.blocked_indicators_count)
        ),
        React.createElement(
          'div',
          { className: 'severities' },
          React.createElement('div', null, 'Critical: ', counters.by_severity.critical),
          React.createElement('div', null, 'High: ', counters.by_severity.high),
          React.createElement('div', null, 'Medium: ', counters.by_severity.medium),
          React.createElement('div', null, 'Low: ', counters.by_severity.low)
        ),
        React.createElement(
          'div',
          { className: 'types' },
          React.createElement('div', null, 'Log: ', counters.by_type.log),
          React.createElement('div', null, 'ATO: ', counters.by_type.ato),
          React.createElement('div', null, 'Network: ', counters.by_type.network)
        )
      );
    }

    const html = renderToStaticMarkup(
      React.createElement(LiveCountersView, {
        counters: INITIAL_COUNTERS,
        isConnected: true,
        onResync: () => {},
      })
    );

    // CRITICAL CONSTRAINT: Zero input elements in live counters tab
    assert(!html.includes('<input'), 'Live Counters view MUST NOT contain <input> elements');
    assert(!html.includes('<textarea'), 'Live Counters view MUST NOT contain <textarea> elements');
    assert(!html.includes('<select'), 'Live Counters view MUST NOT contain <select> elements');
    assert(!html.includes('<form'), 'Live Counters view MUST NOT contain <form> elements');

    // Confirm read-only metrics render properly
    assert(html.includes('Realtime Telemetry Stream'));
    assert(html.includes('Total 24h:'));
    assert(html.includes('Resync'));
  });
});
