import { createHash } from 'node:crypto';

export function normalizeKey(key) {
  // RPC returns permission under access_key; tests and imported snapshots may use permission directly.
  const rawPermission = key.permission ?? key.access_key?.permission;
  const permission = rawPermission === 'FullAccess' ? { kind: 'FullAccess' } : {
    kind: 'FunctionCall',
    receiverId: rawPermission?.FunctionCall?.receiver_id || '',
    methodNames: [...(rawPermission?.FunctionCall?.method_names || [])].sort(),
    allowance: rawPermission?.FunctionCall?.allowance ?? null
  };
  return { publicKey: key.public_key, permission };
}

export function keyFingerprint(key) {
  return `${key.publicKey}:${JSON.stringify(key.permission)}`;
}

export function compareSnapshots(baseline, current) {
  if (!baseline) return [];
  const prior = new Map(baseline.keys.map((key) => [keyFingerprint(key), key]));
  const now = new Map(current.keys.map((key) => [keyFingerprint(key), key]));
  const findings = [];
  for (const [fingerprint, key] of now) {
    if (prior.has(fingerprint)) continue;
    if (key.permission.kind === 'FullAccess') {
      findings.push(finding('KS-KEY-001', 'CRITICAL', `New full-access key ${key.publicKey}`, { publicKey: key.publicKey, permission: key.permission }));
    } else if (!key.permission.methodNames.length) {
      findings.push(finding('KS-KEY-002', 'HIGH', `New function-call key ${key.publicKey} has no method restriction`, { publicKey: key.publicKey, permission: key.permission }));
    } else {
      findings.push(finding('KS-KEY-003', 'MEDIUM', `New function-call key ${key.publicKey}`, { publicKey: key.publicKey, permission: key.permission }));
    }
  }
  for (const [fingerprint, key] of prior) {
    if (!now.has(fingerprint)) findings.push(finding('KS-KEY-004', 'HIGH', `Baseline key ${key.publicKey} was removed`, { publicKey: key.publicKey, permission: key.permission }));
  }
  if (baseline.codeHash !== current.codeHash) {
    findings.push(finding('KS-CODE-001', 'HIGH', 'Public deployed-code hash changed since baseline', { baselineCodeHash: baseline.codeHash, currentCodeHash: current.codeHash }));
  }
  return findings;
}

function finding(ruleId, severity, message, evidence) {
  const fingerprint = createHash('sha256').update(JSON.stringify({ ruleId, evidence })).digest('hex').slice(0, 16);
  return { ruleId, severity, message, evidence, fingerprint };
}

export function riskScore(findings) {
  const points = { CRITICAL: 55, HIGH: 30, MEDIUM: 14, LOW: 5 };
  return Math.min(100, findings.reduce((score, item) => score + (points[item.severity] || 20), 0));
}

/** A chained local record makes silent edits detectable during verification. It is not a blockchain. */
export function appendAuditEvent(trail, event) {
  const previousHash = trail.at(-1)?.integrityHash || 'GENESIS';
  const record = { sequence: trail.length + 1, recordedAt: event.recordedAt, accountId: event.accountId, type: event.type, details: event.details, previousHash };
  record.integrityHash = createHash('sha256').update(JSON.stringify(record)).digest('hex');
  trail.push(record);
  return record;
}

export function verifyAuditTrail(trail) {
  let previousHash = 'GENESIS';
  for (const record of trail) {
    const { integrityHash, ...payload } = record;
    const expected = createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    if (record.previousHash !== previousHash || integrityHash !== expected) return { valid: false, brokenAt: record.sequence };
    previousHash = integrityHash;
  }
  return { valid: true, records: trail.length, headHash: previousHash };
}
