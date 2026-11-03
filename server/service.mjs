import { appendAuditEvent, compareSnapshots, riskScore, verifyAuditTrail } from './monitor.mjs';
import { assessAttackPaths } from './attack-paths.mjs';
import { evaluateTransaction } from './decision.mjs';
import { createHash } from 'node:crypto';

const ACCOUNT = /^[a-z0-9][a-z0-9._-]{1,62}$/;

const DEFAULT_POLICY = Object.freeze({ blockNewFullAccessKey: true, blockCodeDeployment: true, reviewKeyRemoval: true, allowedReceivers: [] });

export class KeySentryService {
  constructor({ store, rpc, notifier = null, now = () => new Date() }) { this.store = store; this.rpc = rpc; this.notifier = notifier; this.now = now; }
  validateAccount(accountId) {
    if (!ACCOUNT.test(accountId || '')) throw new Error('Use a valid NEAR account ID (2–63 lowercase characters).');
    return accountId;
  }
  listWatches() { return Object.values(this.store.data.watches); }
  /** Public one-time check: no watch, audit event, alert, or account ID is written to the store. */
  async check(accountId) {
    accountId = this.validateAccount(accountId);
    const snapshot = await this.rpc.snapshot(accountId);
    return { snapshot, findings: [], riskScore: 0, attackPaths: assessAttackPaths(snapshot) };
  }
  async addWatch(accountId, intervalSec = 60) {
    accountId = this.validateAccount(accountId);
    const safeInterval = Math.max(45, Math.min(3600, Number(intervalSec) || 60));
    const old = this.store.data.watches[accountId] || {};
    const watch = { accountId, intervalSec: safeInterval, createdAt: old.createdAt || this.now().toISOString(), baseline: old.baseline || null, latest: old.latest || null, lastScanAt: old.lastScanAt || null, lastError: null, nextScanAt: old.nextScanAt || null, policy: { ...DEFAULT_POLICY, ...(old.policy || {}) } };
    this.store.data.watches[accountId] = watch;
    if (!old.accountId) this.audit(accountId, 'WATCH_CREATED', { intervalSec: safeInterval });
    await this.store.save();
    return watch;
  }
  async removeWatch(accountId) { accountId = this.validateAccount(accountId); delete this.store.data.watches[accountId]; this.audit(accountId, 'WATCH_REMOVED', {}); await this.store.save(); }
  async updatePolicy(accountId, policy) {
    accountId = this.validateAccount(accountId); const watch = this.store.data.watches[accountId] || await this.addWatch(accountId);
    watch.policy = { ...DEFAULT_POLICY, ...watch.policy, ...sanitizePolicy(policy) }; this.audit(accountId, 'POLICY_UPDATED', { policy: watch.policy }); await this.store.save(); return watch;
  }
  audit(accountId, type, details) { return appendAuditEvent(this.store.data.audit || (this.store.data.audit = []), { accountId, type, details, recordedAt: this.now().toISOString() }); }
  async scan(accountId) {
    accountId = this.validateAccount(accountId);
    const watch = this.store.data.watches[accountId] || await this.addWatch(accountId);
    try {
      const snapshot = await this.rpc.snapshot(accountId);
      const findings = compareSnapshots(watch.baseline, snapshot);
      watch.latest = snapshot; watch.lastScanAt = this.now().toISOString(); watch.lastError = null;
      watch.nextScanAt = new Date(this.now().getTime() + watch.intervalSec * 1000).toISOString();
      const seen = new Set(this.store.data.alerts.filter((a) => a.accountId === accountId && a.status === 'open').map((a) => a.dedupeKey));
      for (const item of findings) {
        const dedupeKey = `${accountId}:${item.ruleId}:${item.fingerprint}`;
        if (!seen.has(dedupeKey)) {
          const alert = { id: `alert_${item.fingerprint}`, dedupeKey, accountId, status: 'open', delivery: 'not-configured', detectedAt: this.now().toISOString(), ...item };
          this.store.data.alerts.unshift(alert); this.audit(accountId, 'ALERT_OPENED', { ruleId: item.ruleId, severity: item.severity, evidence: item.evidence });
          if (this.notifier?.configured) {
            try { await this.notifier.send(alert); alert.delivery = 'delivered'; this.audit(accountId, 'ALERT_DELIVERED', { alertId: alert.id }); }
            catch (error) { alert.delivery = 'failed'; alert.deliveryError = error.message; this.audit(accountId, 'ALERT_DELIVERY_FAILED', { alertId: alert.id, reason: error.message }); }
          }
        }
      }
      this.audit(accountId, 'SCAN_COMPLETED', { blockHeight: snapshot.blockHeight, keyCount: snapshot.keys.length, findingCount: findings.length, codeHash: snapshot.codeHash });
      await this.store.save();
      return { watch, snapshot, findings, riskScore: riskScore(findings), attackPaths: assessAttackPaths(snapshot, watch.baseline) };
    } catch (error) {
      watch.lastError = error.message; watch.nextScanAt = new Date(this.now().getTime() + watch.intervalSec * 1000).toISOString(); this.audit(accountId, 'SCAN_FAILED', { reason: error.message });
      await this.store.save();
      throw error;
    }
  }
  async baseline(accountId) {
    const result = await this.scan(accountId);
    result.watch.baseline = result.snapshot;
    this.audit(accountId, 'BASELINE_APPROVED', { blockHeight: result.snapshot.blockHeight, keyCount: result.snapshot.keys.length, codeHash: result.snapshot.codeHash });
    await this.store.save();
    return result.watch;
  }
  alerts(accountId) { return this.store.data.alerts.filter((alert) => !accountId || alert.accountId === accountId); }
  policyFor(accountId) { return this.store.data.watches[this.validateAccount(accountId)]?.policy || { ...DEFAULT_POLICY }; }
  auditTrail(accountId) { return (this.store.data.audit || []).filter((record) => !accountId || record.accountId === accountId); }
  auditIntegrity() { return verifyAuditTrail(this.store.data.audit || []); }
  attackPaths(accountId) {
    accountId = this.validateAccount(accountId);
    const watch = this.store.data.watches[accountId];
    if (!watch?.latest) throw new Error('Scan this account before requesting its attack-path model.');
    return assessAttackPaths(watch.latest, watch.baseline);
  }
  async assessTransaction(accountId, transaction) {
    accountId = this.validateAccount(accountId);
    const scan = await this.scan(accountId);
    const preflight = evaluateTransaction(transaction, scan.watch.policy);
    const id = `decision_${createHash('sha256').update(JSON.stringify({ accountId, transaction, blockHeight: scan.snapshot.blockHeight, codeHash: scan.snapshot.codeHash })).digest('hex').slice(0, 20)}`;
    const result = { decisionId: id, accountId, snapshot: { blockHeight: scan.snapshot.blockHeight, codeHash: scan.snapshot.codeHash, scannedAt: scan.snapshot.scannedAt }, decision: preflight.decision, requiresExplicitReview: preflight.decision === 'REVIEW', preflight, attackPaths: scan.attackPaths, boundary: 'This decision evaluates an unsigned preview and public account state. It does not sign, submit, or guarantee the safety of a contract call.' };
    this.audit(accountId, 'SIGNATURE_DECISION_ISSUED', { decisionId: id, decision: result.decision, actionCount: Array.isArray(transaction?.actions) ? transaction.actions.length : 0, blockHeight: scan.snapshot.blockHeight });
    await this.store.save();
    return result;
  }
  async assessOneTimeTransaction(accountId, transaction) {
    accountId = this.validateAccount(accountId);
    const check = await this.check(accountId);
    const preflight = evaluateTransaction(transaction, { ...DEFAULT_POLICY });
    const id = `decision_${createHash('sha256').update(JSON.stringify({ transaction, blockHeight: check.snapshot.blockHeight, codeHash: check.snapshot.codeHash })).digest('hex').slice(0, 20)}`;
    return { decisionId: id, snapshot: { blockHeight: check.snapshot.blockHeight, codeHash: check.snapshot.codeHash, scannedAt: check.snapshot.scannedAt }, decision: preflight.decision, requiresExplicitReview: preflight.decision === 'REVIEW', preflight, attackPaths: check.attackPaths, boundary: 'One-time private check: the account ID and decision are not stored by KeySentry. This does not sign, submit, or guarantee the safety of a contract call.' };
  }
  async pollDue() {
    const now = this.now().getTime();
    const due = this.listWatches().filter((watch) => !watch.nextScanAt || new Date(watch.nextScanAt).getTime() <= now);
    return Promise.allSettled(due.map((watch) => this.scan(watch.accountId)));
  }
}

function sanitizePolicy(policy = {}) {
  const clean = {};
  for (const key of ['blockNewFullAccessKey', 'blockCodeDeployment', 'reviewKeyRemoval']) if (typeof policy[key] === 'boolean') clean[key] = policy[key];
  if (Array.isArray(policy.allowedReceivers)) clean.allowedReceivers = policy.allowedReceivers.filter((value) => ACCOUNT.test(value)).slice(0, 30);
  return clean;
}
