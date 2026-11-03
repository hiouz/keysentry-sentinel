# KeySentry Signature Guard SDK

This zero-dependency ESM SDK places KeySentry's decision API before an existing wallet signing callback. It does not import a wallet library and never receives a seed phrase or private key.

```js
import { createKeySentryClient } from './sdk/keysentry.mjs';

const guard = createKeySentryClient({ baseUrl: 'https://your-keysentry.example' });
const { verdict, submission } = await guard.protectSignature({
  accountId: 'treasury.testnet',
  transaction: { receiver_id: 'safe-contract.testnet', actions: [{ type: 'FunctionCall', method_name: 'withdraw' }] },
  approveReview: async (verdict) => window.confirm(`Review required: ${verdict.decisionId}`),
  submit: async (transaction) => wallet.signAndSendTransaction(transaction)
});
```

`BLOCK` never invokes `submit`. `REVIEW` needs an explicit affirmative callback. `ALLOW WITH CAUTION` proceeds. The API response includes the fresh block height, code hash, deterministic preflight findings, public-permission attack paths, and the proof boundary.
