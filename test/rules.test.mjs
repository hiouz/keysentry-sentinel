import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeActions } from '../dist/rules.mjs';

test('blocks a full-access key addition', () => {
  const result = analyzeActions({actions:[{type:'AddKey', permission:'FullAccess'}]});
  assert.equal(result.decision, 'BLOCK');
  assert.equal(result.findings[0].id, 'KS-TX-001');
});

test('requires review for a restricted function-call key', () => {
  const result = analyzeActions({actions:[{type:'AddKey', permission:'FunctionCall'}]});
  assert.equal(result.decision, 'REVIEW');
  assert.equal(result.findings[0].id, 'KS-TX-002');
});

test('fails closed for an unknown action', () => {
  const result = analyzeActions({actions:[{type:'MysteryAction'}]});
  assert.equal(result.decision, 'REVIEW');
  assert.equal(result.findings[0].id, 'KS-TX-999');
});

test('blocks an empty payload', () => {
  const result = analyzeActions({actions:[]});
  assert.equal(result.decision, 'BLOCK');
  assert.equal(result.findings[0].id, 'KS-TX-000');
});

test('controlled self-transfer remains review-only, never silently allowed', () => {
  const result = analyzeActions({ receiver_id: 'demo.testnet', actions: [{ type: 'Transfer', amount: '1 yoctoNEAR' }] });
  assert.equal(result.decision, 'REVIEW');
  assert.equal(result.findings[0].id, 'KS-TX-005');
});
