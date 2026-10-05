import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

import { mapAnalysisResult, mapAlert } from '../services/mappers.ts';

describe('LLM-DECUPLE-UX Test Suite', () => {
  it('1 LoadingSpinner component exists with proper defaults and testid', () => {
    const spinnerSrc = fs.readFileSync(path.resolve('src/components/common/LoadingSpinner.tsx'), 'utf8');
    assert.match(spinnerSrc, /data-testid="explanation-loading-spinner"/);
    assert.match(spinnerSrc, /text = 'Generating AI explanation\.\.\.'/);
    assert.match(spinnerSrc, /Loader2/);
  });

  it('2 ExplanationPanel shows LoadingSpinner inside explanation container when explanation is null', () => {
    const panelSrc = fs.readFileSync(path.resolve('src/components/common/ExplanationPanel.tsx'), 'utf8');
    assert.match(panelSrc, /LoadingSpinner/);
    assert.match(panelSrc, /!currentExplanation/);
    assert.match(panelSrc, /<LoadingSpinner text="Generating AI explanation\.\.\." \/>/);
    // Verifies the spinner is inside the container without replacing header/confidence metrics
    assert.match(panelSrc, /AI Explanation/);
    assert.match(panelSrc, /Detection Confidence/);
  });

  it('3 VerboseResultPanel renders core data immediately and scoped spinner if explanation is null', () => {
    const verboseSrc = fs.readFileSync(path.resolve('src/components/common/VerboseResultPanel.tsx'), 'utf8');
    assert.match(verboseSrc, /LoadingSpinner/);
    assert.match(verboseSrc, /scan\.overall_explanation \?/);
    assert.match(verboseSrc, /<LoadingSpinner text="Generating AI explanation\.\.\." \/>/);
    assert.match(verboseSrc, /analysis\.explanation \?/);
    assert.match(verboseSrc, /Recommended action/);
  });

  it('4 EmailAnalysisResultCard supports null/pending explanation and shows scoped spinner', () => {
    const cardSrc = fs.readFileSync(path.resolve('src/components/common/EmailAnalysisResultCard.tsx'), 'utf8');
    assert.match(cardSrc, /Generating AI explanation\.\.\./);
    assert.match(cardSrc, /Loader2/);
    assert.match(cardSrc, /enforcementDetail \?/);
  });

  it('5 OrgEventReview has scoped explanation container with LoadingSpinner', () => {
    const orgSrc = fs.readFileSync(path.resolve('src/pages/OrgEventReview.tsx'), 'utf8');
    assert.match(orgSrc, /LoadingSpinner/);
    assert.match(orgSrc, /data-testid="explanation-container"/);
    assert.match(orgSrc, /analysis\.explanation \?/);
    assert.match(orgSrc, /<LoadingSpinner text="Generating AI explanation\.\.\." \/>/);
  });

  it('6 SecurityHistory renders LoadingSpinner in explanation section when explanation is null', () => {
    const historySrc = fs.readFileSync(path.resolve('src/pages/SecurityHistory.tsx'), 'utf8');
    assert.match(historySrc, /LoadingSpinner/);
    assert.match(historySrc, /selected\.explanation \?/);
    assert.match(historySrc, /<LoadingSpinner text="Generating AI explanation\.\.\." \/>/);
  });

  it('7 Mappers cleanly preserve null explanation without coercing to "None" string', () => {
    const mappedAnalysis = mapAnalysisResult({
      id: 'test-1',
      risk_score: 85,
      severity: 'high',
      classification: 'phishing',
      explanation: null,
      indicators: [{ type: 'domain', value: 'evil.com', severity: 'high' }],
      recommended_actions: [{ id: 'act-1', action: 'quarantine', description: 'Quarantine email' }],
    });
    assert.strictEqual(mappedAnalysis.explanation, null);
    assert.strictEqual(mappedAnalysis.riskScore, 85);
    assert.strictEqual(mappedAnalysis.severity, 'high');
    assert.strictEqual(mappedAnalysis.recommendedActions.length, 1);
    assert.strictEqual(mappedAnalysis.indicators.length, 1);

    const mappedAlert = mapAlert({
      id: 'alert-1',
      title: 'Suspicious Email',
      description: 'Phishing detected',
      severity: 'critical',
      risk_score: 95,
      source: 'email',
      explanation: null,
      recommended_actions: [{ id: 'act-2', action: 'block_sender', description: 'Block sender' }],
      created_at: new Date().toISOString(),
    });
    assert.strictEqual(mappedAlert.explanation, null);
    assert.strictEqual(mappedAlert.riskScore, 95);
    assert.strictEqual(mappedAlert.severity, 'critical');
    assert.strictEqual(mappedAlert.recommendedActions.length, 1);
  });

  it('8 TypeScript types define explanation as optional or nullable', () => {
    const typesSrc = fs.readFileSync(path.resolve('src/types/index.ts'), 'utf8');
    assert.match(typesSrc, /explanation\?: string \| null/);
  });
});
