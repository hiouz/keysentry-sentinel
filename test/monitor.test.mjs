import test from 'node:test';
import assert from 'node:assert/strict';
import { appendAuditEvent, compareSnapshots, normalizeKey, riskScore, verifyAuditTrail } from '../server/monitor.mjs';
import { assessAttackPaths } from '../server/attack-paths.mjs';

const full = normalizeKey({ public_key: 'ed25519:new', permission: 'FullAccess' });
const limited = normalizeKey({ public_key: 'ed25519:limited', permission: { FunctionCall: { receiver_id: 'safe.testnet', method_names: ['vote'] } } });
const baseline = { codeHash: 'old', keys: [] };
test('new full-access key is critical and carries exact public-key evidence', () => { const findings = compareSnapshots(baseline, { codeHash: 'old', keys: [full] }); assert.equal(findings[0].ruleId, 'KS-KEY-001'); assert.equal(findings[0].severity, 'CRITICAL'); assert.equal(findings[0].evidence.publicKey, 'ed25519:new'); });
test('method-restricted function key is not labelled unscoped', () => { const findings = compareSnapshots(baseline, { codeHash: 'old', keys: [limited] }); assert.equal(findings[0].ruleId, 'KS-KEY-003'); assert.equal(findings[0].severity, 'MEDIUM'); });
test('normalizes the actual NEAR RPC access_key permission shape', () => { const key = normalizeKey({ public_key: 'ed25519:rpc', access_key: { permission: 'FullAccess' } }); assert.deepEqual(key.permission, { kind: 'FullAccess' }); });
test('code change gets a separate evidence-backed alert', () => { const findings = compareSnapshots({ codeHash: 'one', keys: [] }, { codeHash: 'two', keys: [] }); assert.deepEqual(findings[0].evidence, { baselineCodeHash: 'one', currentCodeHash: 'two' }); assert.equal(riskScore(findings), 30); });
test('audit records expose tampering instead of silently accepting it', () => { const trail = []; appendAuditEvent(trail, { accountId: 'demo.testnet', type: 'SCAN_COMPLETED', details: {}, recordedAt: '2026-01-01T00:00:00.000Z' }); appendAuditEvent(trail, { accountId: 'demo.testnet', type: 'BASELINE_APPROVED', details: {}, recordedAt: '2026-01-01T00:01:00.000Z' }); assert.equal(verifyAuditTrail(trail).valid, true); trail[0].details.changed = true; assert.equal(verifyAuditTrail(trail).valid, false); });
test('attack-path model distinguishes full control from a bounded function key', () => { const model = assessAttackPaths({ scannedAt: '2026-01-01T00:00:00.000Z', codeHash: 'one', keys: [full, limited] }); assert.equal(model.paths[0].id, 'KS-PATH-001'); assert.equal(model.paths[0].severity, 'CRITICAL'); assert.ok(model.paths.some((item) => item.id === 'KS-PATH-005')); assert.match(model.boundary, /does not execute actions/); });
test('attack-path model flags code change without calling it an exploit', () => { const model = assessAttackPaths({ codeHash: 'new', keys: [] }, { codeHash: 'old', keys: [] }); const change = model.paths.find((item) => item.id === 'KS-PATH-007'); assert.equal(change.severity, 'HIGH'); assert.match(change.explanation, /may have changed/); });
