import { setupWalletSelector } from '@near-wallet-selector/core';
import { setupModal } from '@near-wallet-selector/modal-ui-js';
import { setupMyNearWallet } from '@near-wallet-selector/my-near-wallet';
import { setupMeteorWallet } from '@near-wallet-selector/meteor-wallet';

const TESTNET_CONTRACT = 'guest-book.testnet';
const memory = new Map();
const memoryStorage = {
  async getItem(key) { return memory.get(key) ?? null; },
  async setItem(key, value) { memory.set(key, value); },
  async removeItem(key) { memory.delete(key); },
};
const $ = (selector) => document.querySelector(selector);
let selector;
let modal;
let wallet;
let activeAccountId = '';

function setResult(kind, title, message) {
  const node = $('#walletResult');
  node.className = `wallet-result ${kind}`;
  node.replaceChildren(Object.assign(document.createElement('strong'), { textContent: title }), Object.assign(document.createElement('p'), { textContent: message }));
  node.hidden = false;
}

function setStatus() {
  const node = $('#walletStatus');
  const safe = $('#sendSafeTest');
  if (activeAccountId) {
    node.textContent = `CONNECTED: ${activeAccountId} · TESTNET · THIS TAB ONLY`;
    safe.disabled = false;
  } else {
    node.textContent = 'NO WALLET CONNECTED · KEYSENTRY DOES NOT STORE A WALLET SESSION';
    safe.disabled = true;
  }
}

async function syncWallet() {
  const state = selector.store.getState();
  const account = state.accounts.find((item) => item.active) ?? state.accounts[0];
  if (!account || !state.selectedWalletId) return;
  activeAccountId = account.accountId;
  wallet = await selector.wallet(state.selectedWalletId);
  setStatus();
  setResult('ok', 'TESTNET WALLET CONNECTED', 'The account name is held only in this tab. Refreshing KeySentry clears this app session. Your external wallet controls its own separate session.');
}

async function assess(transaction) {
  const response = await fetch('/api/decisions', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ accountId: activeAccountId || 'keysentry-demo.testnet', transaction }),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'KeySentry preflight failed');
  return data;
}

async function runBlockDemo() {
  try {
    const transaction = { receiver_id: activeAccountId || 'keysentry-demo.testnet', actions: [{ type: 'AddKey', permission: 'FullAccess', public_key: 'ed25519:DEMO_ONLY_NEVER_SENT' }] };
    const result = await assess(transaction);
    if (result.decision !== 'BLOCK') throw new Error(`Expected BLOCK, got ${result.decision}`);
    setResult('blocked', 'BLOCKED BEFORE WALLET', `Decision ${result.decisionId}: a full-access key was detected. KeySentry did not initialize, invoke, or send any signing request to the wallet.`);
  } catch (error) { setResult('error', 'DEMO CHECK FAILED', error.message); }
}

async function sendSafeTest() {
  if (!activeAccountId || !wallet) return;
  try {
    const transaction = { receiver_id: activeAccountId, actions: [{ type: 'Transfer', amount: '1 yoctoNEAR' }] };
    const result = await assess(transaction);
    if (result.decision === 'BLOCK') { setResult('blocked', 'BLOCKED BEFORE WALLET', `Decision ${result.decisionId} blocked this action. No signing request was made.`); return; }
    const approve = window.confirm(`KeySentry classified this as ${result.decision}. Send exactly 1 yoctoNEAR to your own testnet account? Your wallet will show the final transaction and gas cost.`);
    if (!approve) { setResult('review', 'EXPLICIT REVIEW DECLINED', 'No signing request was made.'); return; }
    setResult('review', 'AWAITING WALLET CONFIRMATION', 'KeySentry has completed its preflight. Review the recipient and 1 yoctoNEAR amount again inside your wallet before approving.');
    const outcome = await wallet.signAndSendTransaction({ signerId: activeAccountId, receiverId: activeAccountId, actions: [{ type: 'Transfer', params: { deposit: '1' } }] });
    const hash = outcome?.transaction?.hash || outcome?.transaction_outcome?.id;
    setResult('ok', 'TESTNET SIGNATURE REQUEST COMPLETED', hash ? `Wallet returned transaction ${hash}. Verify the final status in your wallet or a NEAR testnet explorer.` : 'Wallet completed its signing flow. Verify the final status in your wallet or a NEAR testnet explorer.');
  } catch (error) { setResult('error', 'WALLET FLOW STOPPED', error.message || 'The wallet did not complete the request. No claim of an on-chain result is made.'); }
}

async function ensureWalletAdapter() {
  if (selector) return;
  selector = await setupWalletSelector({ network: 'testnet', modules: [setupMyNearWallet(), setupMeteorWallet()], storage: memoryStorage });
  modal = setupModal(selector, { contractId: TESTNET_CONTRACT, theme: 'dark', description: 'KeySentry testnet signing lab' });
  selector.on('signedIn', syncWallet);
  selector.on('accountsChanged', syncWallet);
  modal.on('onHide', () => { void syncWallet(); });
  await syncWallet();
}

async function connectWallet() {
  try {
    await ensureWalletAdapter();
    modal.show();
  } catch (error) { setResult('error', 'TESTNET WALLET UNAVAILABLE', error.message); }
}

$('#connectWallet').addEventListener('click', connectWallet);
$('#runBlockDemo').addEventListener('click', runBlockDemo);
$('#sendSafeTest').addEventListener('click', sendSafeTest);
setStatus();
