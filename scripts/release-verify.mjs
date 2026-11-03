import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

const port = 4199;
const server = spawn(process.execPath, ['server/index.mjs'], {
  env: { ...process.env, HOST: '127.0.0.1', PORT: String(port), KEYSENTRY_DATA: '/tmp/keysentry-release-state.json' },
  stdio: ['ignore', 'pipe', 'pipe'],
});

function waitForStart() {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Release server did not start within 10 seconds.')), 10_000);
    server.stdout.on('data', (chunk) => {
      if (chunk.toString().includes('KeySentry listening')) { clearTimeout(timer); resolve(); }
    });
    server.once('error', reject);
    server.stderr.on('data', (chunk) => process.stderr.write(chunk));
  });
}

try {
  await waitForStart();
  const health = await fetch(`http://127.0.0.1:${port}/api/health`);
  assert.equal(health.status, 200, 'health endpoint must be available');
  const decision = await fetch(`http://127.0.0.1:${port}/api/decisions`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ accountId: 'guest-book.testnet', transaction: { receiver_id: 'guest-book.testnet', actions: [{ type: 'AddKey', permission: 'FullAccess' }] } }),
  });
  assert.equal(decision.status, 200, 'decision endpoint must be available');
  const body = await decision.json();
  assert.equal(body.decision, 'BLOCK', 'full-access key demo must be blocked');
  assert.equal(Object.hasOwn(body, 'accountId'), false, 'one-time decision must not return account ID');
  console.log(`release verification passed: ${body.decision} at testnet block ${body.snapshot.blockHeight}`);
} finally {
  server.kill('SIGTERM');
}
