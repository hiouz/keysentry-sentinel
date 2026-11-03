export class KeySentryBlockedError extends Error {
  constructor(verdict) { super(`KeySentry blocked this signature request: ${verdict.decisionId}`); this.name = 'KeySentryBlockedError'; this.verdict = verdict; }
}

export class KeySentryReviewRejectedError extends Error {
  constructor(verdict) { super(`KeySentry review was not approved: ${verdict.decisionId}`); this.name = 'KeySentryReviewRejectedError'; this.verdict = verdict; }
}

/**
 * Calls a KeySentry deployment before a wallet is asked to sign. The SDK never
 * receives a private key: submit is supplied by the consuming wallet or dApp.
 */
export function createKeySentryClient({ baseUrl, fetchImpl = fetch }) {
  const base = String(baseUrl || '').replace(/\/$/, '');
  if (!base) throw new Error('baseUrl is required.');
  async function assess({ accountId, transaction }) {
    const response = await fetchImpl(`${base}/api/decisions`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ accountId, transaction }) });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || 'KeySentry decision request failed.');
    return body;
  }
  async function protectSignature({ accountId, transaction, submit, approveReview = async () => false }) {
    if (typeof submit !== 'function') throw new Error('submit must be the wallet or dApp signing callback.');
    const verdict = await assess({ accountId, transaction });
    if (verdict.decision === 'BLOCK') throw new KeySentryBlockedError(verdict);
    if (verdict.requiresExplicitReview && !(await approveReview(verdict))) throw new KeySentryReviewRejectedError(verdict);
    return { verdict, submission: await submit(transaction) };
  }
  return { assess, protectSignature };
}
