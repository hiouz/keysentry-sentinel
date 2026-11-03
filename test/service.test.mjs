import test from 'node:test';
import assert from 'node:assert/strict';
import { KeySentryService } from '../server/service.mjs';

test('manual scan preserves an existing watch interval', async () => {
  const store = { data: { watches: {}, alerts: [] }, save: async () => {} };
  const rpc = { snapshot: async (accountId) => ({ accountId, scannedAt: '2026-01-01T00:00:00.000Z', blockHeight: 1, codeHash: 'hash', keys: [] }) };
  const service = new KeySentryService({ store, rpc, now: () => new Date('2026-01-01T00:00:00.000Z') });
  await service.addWatch('demo.testnet', 300);
  const result = await service.scan('demo.testnet');
  assert.equal(result.watch.intervalSec, 300);
  assert.equal(result.snapshot.accountId, 'demo.testnet');
});

test('a new watch receives restrictive default policy', async () => {
  const store = { data: { watches: {}, alerts: [], audit: [] }, save: async () => {} };
  const service = new KeySentryService({ store, rpc: { snapshot: async () => ({}) } });
  const watch = await service.addWatch('policy.testnet');
  assert.equal(watch.policy.blockNewFullAccessKey, true);
  assert.equal(watch.policy.blockCodeDeployment, true);
});

test('one-time check does not persist the account ID, audit record, or watch', async () => {
  const store = { data: { watches: {}, alerts: [], audit: [] }, save: async () => { throw new Error('one-time check must not save'); } };
  const rpc = { snapshot: async (accountId) => ({ accountId, scannedAt: '2026-01-01T00:00:00.000Z', blockHeight: 1, codeHash: 'hash', keys: [] }) };
  const service = new KeySentryService({ store, rpc });
  const result = await service.check('private.testnet');
  assert.equal(result.snapshot.accountId, 'private.testnet');
  assert.deepEqual(store.data, { watches: {}, alerts: [], audit: [] });
});
