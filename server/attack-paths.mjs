/**
 * Public-metadata reachability analysis. This does not execute a transaction,
 * inspect private data, or claim that a contract path is exploitable.
 */
const SENSITIVE_METHOD = /(^|_)(withdraw|transfer|ft_transfer|nft_transfer|delete|remove_key|add_key|set_owner|upgrade|deploy)(_|$)/i;

export function assessAttackPaths(snapshot, baseline = null) {
  const keys = Array.isArray(snapshot?.keys) ? snapshot.keys : [];
  const paths = [];
  for (const key of keys) {
    if (key.permission?.kind === 'FullAccess') {
      paths.push(path('KS-PATH-001', 'CRITICAL', 90, 'Direct account-control path',
        'This public key has FullAccess permission, so compromise of its holder could authorize account-level actions.',
        [key.publicKey, 'account-level actions'], { publicKey: key.publicKey, permission: key.permission }));
      continue;
    }
    const permission = key.permission || {};
    const methods = permission.methodNames || [];
    if (!permission.receiverId) {
      paths.push(path('KS-PATH-002', 'HIGH', 65, 'Malformed function-key scope',
        'The public permission metadata has no receiver contract. Treat this key as needing manual verification.',
        [key.publicKey, 'receiver unresolved'], { publicKey: key.publicKey, permission }));
    } else if (!methods.length) {
      paths.push(path('KS-PATH-003', 'HIGH', 60, 'Unbounded contract-method surface',
        'This key is restricted to one receiver but has no method allowlist. It may call any public method exposed by that receiver.',
        [key.publicKey, permission.receiverId, 'any public method'], { publicKey: key.publicKey, receiverId: permission.receiverId, methods }));
    } else {
      const sensitive = methods.filter((method) => SENSITIVE_METHOD.test(method));
      paths.push(path(sensitive.length ? 'KS-PATH-004' : 'KS-PATH-005', sensitive.length ? 'MEDIUM' : 'LOW', sensitive.length ? 28 : 8,
        sensitive.length ? 'Sensitive method surface' : 'Bounded function path',
        sensitive.length ? `The allowlist includes security-sensitive-looking method name(s): ${sensitive.join(', ')}. Verify their contract semantics.` : 'This key has an explicit receiver and method allowlist. Contract semantics still require independent review.',
        [key.publicKey, permission.receiverId, methods.join(', ')], { publicKey: key.publicKey, receiverId: permission.receiverId, methods, sensitiveMethods: sensitive }));
    }
    if (permission.allowance == null) {
      paths.push(path('KS-PATH-006', 'LOW', 6, 'No gas allowance cap recorded',
        'The function-call permission has no allowance value in public metadata. This is not a transfer limit; verify expected call costs and lifecycle.',
        [key.publicKey, 'allowance: none'], { publicKey: key.publicKey, receiverId: permission.receiverId, allowance: null }));
    }
  }
  if (baseline?.codeHash && snapshot?.codeHash && baseline.codeHash !== snapshot.codeHash) {
    paths.push(path('KS-PATH-007', 'HIGH', 55, 'Contract semantics changed after approval',
      'The deployed-code hash differs from the approved baseline. Revalidate existing function-key paths because receiver behavior may have changed.',
      ['baseline code', 'current code'], { baselineCodeHash: baseline.codeHash, currentCodeHash: snapshot.codeHash }));
  }
  const score = Math.min(100, paths.reduce((total, item) => total + item.points, 0));
  return {
    model: 'public-permission-reachability-v1',
    assessedAt: snapshot?.scannedAt || null,
    score,
    posture: score >= 80 ? 'CRITICAL REVIEW' : score >= 40 ? 'REVIEW REQUIRED' : 'LIMITED VISIBLE EXPOSURE',
    paths: paths.sort((a, b) => b.points - a.points || a.id.localeCompare(b.id)),
    boundary: 'Public-metadata reachability model only. It does not execute actions, prove exploitability, identify key owners, or audit contract code.'
  };
}

function path(id, severity, points, title, explanation, route, evidence) {
  return { id, severity, points, title, explanation, route, evidence };
}
