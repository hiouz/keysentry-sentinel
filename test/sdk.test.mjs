import test from 'node:test';
import assert from 'node:assert/strict';
import { createKeySentryClient, KeySentryBlockedError, KeySentryReviewRejectedError } from '../sdk/keysentry.mjs';

function clientWith(verdict) { return createKeySentryClient({ baseUrl: 'https://keysentry.example', fetchImpl: async () => ({ ok: true, json: async () => verdict }) }); }
test('SDK never invokes wallet submit when KeySentry blocks', async () => { const client = clientWith({ decision: 'BLOCK', decisionId: 'decision_block', requiresExplicitReview: false }); let submitted = false; await assert.rejects(() => client.protectSignature({ accountId: 'demo.testnet', transaction: { actions: [] }, submit: async () => { submitted = true; } }), KeySentryBlockedError); assert.equal(submitted, false); });
test('SDK requires an affirmative review before wallet submit', async () => { const client = clientWith({ decision: 'REVIEW', decisionId: 'decision_review', requiresExplicitReview: true }); await assert.rejects(() => client.protectSignature({ accountId: 'demo.testnet', transaction: { actions: [] }, submit: async () => {} }), KeySentryReviewRejectedError); const result = await client.protectSignature({ accountId: 'demo.testnet', transaction: { actions: [] }, approveReview: async () => true, submit: async () => 'wallet-tx-id' }); assert.equal(result.submission, 'wallet-tx-id'); });
