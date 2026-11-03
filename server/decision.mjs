import { analyzeActions } from '../dist/rules.mjs';

/** Apply deterministic account policy to an unsigned transaction preview. */
export function evaluateTransaction(transaction, policy) {
  const result = analyzeActions(transaction);
  const actions = Array.isArray(transaction?.actions) ? transaction.actions : [];
  const add = (id, severity, message) => result.findings.push({ id, severity, evidence: 'KeySentry account policy', message, points: 100 });
  if (policy?.blockNewFullAccessKey && actions.some((action) => String(action?.type).toLowerCase().includes('addkey') && String(action.permission).toLowerCase().includes('full'))) add('KS-POL-001', 'CRITICAL', 'Account policy blocks adding a full-access key.');
  if (policy?.blockCodeDeployment && actions.some((action) => String(action?.type).toLowerCase().includes('deploy'))) add('KS-POL-002', 'CRITICAL', 'Account policy blocks contract-code deployment.');
  if (policy?.reviewKeyRemoval && actions.some((action) => String(action?.type).toLowerCase().includes('deletekey'))) add('KS-POL-003', 'HIGH', 'Account policy requires review before removing an access key.');
  if (policy?.allowedReceivers?.length && transaction?.receiver_id && !policy.allowedReceivers.includes(transaction.receiver_id)) add('KS-POL-004', 'HIGH', `Receiver ${transaction.receiver_id} is not in this account's approved receiver list.`);
  if (result.findings.some((finding) => finding.id.startsWith('KS-POL-'))) { result.score = 100; result.decision = 'BLOCK'; }
  return result;
}
