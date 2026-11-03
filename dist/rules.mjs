/** Deterministic, evidence-bearing structural checks. Unknown actions fail closed. */
export function analyzeActions(transaction) {
  const actions = Array.isArray(transaction?.actions) ? transaction.actions : [];
  if (!actions.length) return { score: 100, decision: 'BLOCK', findings: [{id:'KS-TX-000', severity:'CRITICAL', evidence:'No parseable actions', message:'The action preview is empty or malformed. Do not sign an unknown payload.'}] };
  const findings = [];
  const add = (id, severity, evidence, message, points) => findings.push({id, severity, evidence, message, points});
  for (const action of actions) {
    const type = String(action?.type || '').toLowerCase();
    if (type.includes('addkey')) {
      const full = String(action.permission || '').toLowerCase().includes('full');
      add(full ? 'KS-TX-001' : 'KS-TX-002', full ? 'CRITICAL' : 'HIGH', JSON.stringify(action), full ? 'Adds a full-access key. That key can control the account.' : 'Adds a function-call key. Verify its contract, method list, and allowance.', full ? 86 : 52);
    } else if (type.includes('deploy')) add('KS-TX-003', 'CRITICAL', JSON.stringify(action), 'Deploys or replaces contract code.', 90);
    else if (type.includes('deletekey')) add('KS-TX-004', 'HIGH', JSON.stringify(action), 'Deletes an access key and may reduce recovery options.', 48);
    else if (type.includes('transfer')) add('KS-TX-005', 'MEDIUM', JSON.stringify(action), `Moves assets${action.amount ? ` (${action.amount})` : ''}.`, 34);
    else if (type.includes('function')) add('KS-TX-006', 'LOW', JSON.stringify(action), `Calls ${transaction.receiver_id || 'a contract'}${action.method_name ? `.${action.method_name}()` : ''}; contract semantics need independent review.`, 8);
    else add('KS-TX-999', 'HIGH', JSON.stringify(action), `Unknown action type '${action?.type || 'missing'}'. Fail closed and require manual review.`, 70);
  }
  const score = Math.min(100, 4 + findings.reduce((sum, finding) => sum + finding.points, 0));
  const decision = score >= 80 ? 'BLOCK' : score >= 35 ? 'REVIEW' : 'ALLOW WITH CAUTION';
  return {score, decision, findings};
}
