import { normalizeKey } from './monitor.mjs';

const RPC_URL = process.env.NEAR_RPC_URL || 'https://rpc.testnet.near.org';

export function createNearRpc(fetchImpl = fetch) {
  async function query(params) {
    const response = await fetchImpl(RPC_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: `keysentry-${Date.now()}`, method: 'query', params })
    });
    if (!response.ok) throw new Error(`NEAR RPC returned HTTP ${response.status}`);
    const body = await response.json();
    if (body.error) throw new Error(body.error.message || 'NEAR RPC query failed');
    return body.result;
  }

  return {
    async snapshot(accountId) {
      const [keys, account, code] = await Promise.all([
        query({ request_type: 'view_access_key_list', finality: 'final', account_id: accountId, limit: 100 }),
        query({ request_type: 'view_account', finality: 'final', account_id: accountId }),
        query({ request_type: 'view_code', finality: 'final', account_id: accountId })
      ]);
      return {
        accountId,
        scannedAt: new Date().toISOString(),
        blockHeight: account.block_height || keys.block_height || code.block_height || null,
        codeHash: code.hash || 'NO_DEPLOYED_CODE',
        keys: (keys.keys || []).map(normalizeKey)
      };
    }
  };
}
