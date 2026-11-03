import { analyzeActions } from './rules.mjs';

const $ = (s) => document.querySelector(s);
let current = null;
let simulated = false;
function short(value = '', head = 12, tail = 8) { return value.length > head + tail ? `${value.slice(0, head)}…${value.slice(-tail)}` : value; }
function escapeHtml(value = '') { return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]); }
async function api(path, options = {}) { const response = await fetch(path, { ...options, headers: { 'content-type': 'application/json', ...(options.headers || {}) } }); const body = await response.json(); if (!response.ok) throw new Error(body.error || 'Request failed.'); return body; }
function rawKey(key) { return { public_key: key.publicKey, permission: key.permission.kind === 'FullAccess' ? 'FullAccess' : { FunctionCall: { receiver_id: key.permission.receiverId, method_names: key.permission.methodNames, allowance: key.permission.allowance } } }; }
function permission(key) { return key.permission === 'FullAccess' ? { type: 'FULL', detail: 'Full account authority', full: true, unscoped: false } : { type: 'CALL', detail: `${key.permission.FunctionCall.receiver_id} · ${key.permission.FunctionCall.method_names?.length ? key.permission.FunctionCall.method_names.join(', ') : 'all methods'}`, full: false, unscoped: !key.permission.FunctionCall.method_names?.length }; }
function keyId(key) { return `${key.public_key}:${JSON.stringify(key.permission)}`; }

async function scan(event) {
  event?.preventDefault(); const account = $('#account').value.trim(); if (!account) return;
  $('#loading').hidden = false; $('#error').hidden = true; $('#scanResults').hidden = true;
  try {
    const result = await api('/api/check', { method: 'POST', body: JSON.stringify({ accountId: account }) });
    current = { account, keys: result.snapshot.keys.map(rawKey), block: result.snapshot.blockHeight, codeHash: result.snapshot.codeHash, baseline: null, findings: result.findings, attackPaths: result.attackPaths, watched: false };
    simulated = false; render();
  } catch (error) { $('#error').textContent = `Scan failed: ${error.message}. Try a valid testnet account such as guest-book.testnet.`; $('#error').hidden = false; }
  finally { $('#loading').hidden = true; }
}
function render() {
  const state = simulated ? { ...current, keys: [...current.keys, { public_key: 'ed25519:SIMULATED_NEW_FULL_ACCESS_KEY', permission: 'FullAccess', simulated: true }] } : current;
  const perms = state.keys.map(permission); const full = perms.filter((p) => p.full).length; const calls = perms.filter((p) => !p.full).length; const unscoped = perms.filter((p) => p.unscoped).length;
  const previous = new Set(state.baseline?.keys || []); const drift = simulated ? 1 : state.baseline ? state.keys.filter((key) => !previous.has(keyId(key))).length : 0;
  const score = Math.max(12, 92 - full * 13 - unscoped * 7 - drift * 17); const mode = score < 50 ? 'danger' : score < 75 ? 'warning' : '';
  $('#score').textContent = score; $('#scoreRing').className = `score-ring ${mode}`; $('#posture').textContent = score < 50 ? 'Critical review needed' : score < 75 ? 'Review permissions' : 'Visible risk is limited';
  $('#postureText').textContent = 'One-time public-state assessment. This account ID and result are not saved by KeySentry.';
  $('#block').textContent = state.block || '—'; $('#codeHash').textContent = short(state.codeHash); $('#fullAccess').textContent = full; $('#functionKeys').textContent = calls; $('#unscopedKeys').textContent = unscoped; $('#driftCount').textContent = drift;
  $('#keyList').innerHTML = state.keys.map((key) => { const p = permission(key); const isDrift = state.baseline && !previous.has(keyId(key)); const cls = `${p.full ? 'full' : ''} ${p.unscoped ? 'unscoped' : ''} ${isDrift ? 'drift' : ''}`; const risk = isDrift ? 'NEW VS BASELINE' : p.full ? 'FULL CONTROL' : p.unscoped ? 'REVIEW SCOPE' : 'RESTRICTED'; return `<article class="key ${cls}"><span class="tag">${isDrift ? 'NEW' : p.type}</span><main><code>${short(key.public_key, 27, 12)}</code><small>${key.simulated ? 'Simulation-only local drift event' : p.detail}</small></main><span class="risk">${risk}</span></article>`; }).join('');
  renderIncident(state, { full, unscoped, drift }); $('#scanResults').hidden = false;
  renderAttackPaths(state.attackPaths);
}
function renderAttackPaths(model) {
  if (!model) return;
  $('#attackScore').textContent = model.score;
  $('#attackBoundary').textContent = `${model.posture} · ${model.boundary}`;
  $('#attackList').innerHTML = model.paths.map((item) => `<article class="attack-path ${item.severity.toLowerCase()}"><div><span>${escapeHtml(item.id)} · ${escapeHtml(item.severity)}</span><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(item.explanation)}</p></div><code>${item.route.map(escapeHtml).join(' → ')}</code></article>`).join('') || '<p class="path-empty">No public access keys were returned for this snapshot.</p>';
}
function renderIncident(state, risks) {
  const panel = $('#incident'); const level = $('#incidentLevel'); const title = $('#incidentTitle'); const copy = $('#incidentCopy'); const response = $('#responseButton');
  $('#watchStatus').textContent = 'ONE-TIME CHECK · NOT STORED'; panel.className = 'incident'; response.hidden = true;
  if (simulated) { panel.classList.add('critical'); level.textContent = 'SIMULATED CHANGE'; title.textContent = 'A local simulated FullAccess key is visible.'; copy.textContent = 'This is a training-only screen state. No NEAR account, account ID, or KeySentry storage was changed.'; response.hidden = false; return; }
  if (!state.baseline) { level.textContent = 'ONE-TIME CHECK COMPLETE'; title.textContent = 'Current public permissions are shown above.'; copy.textContent = 'This result is not retained by KeySentry. Persistent monitoring requires a separate authenticated private workspace.'; return; }
  if (risks.drift || state.findings?.length) { panel.classList.add('critical'); level.textContent = 'CHANGE DETECTED'; title.textContent = `${risks.drift || state.findings.length} evidence-backed change${(risks.drift || state.findings.length) === 1 ? '' : 's'} since baseline.`; copy.textContent = 'Review the public-key or code evidence before taking action. KeySentry cannot identify the owner of a key or decide whether a change was authorized.'; response.hidden = false; return; }
  if (risks.full > 1 || risks.unscoped) { panel.classList.add('warning'); level.textContent = 'REVIEW RECOMMENDED'; title.textContent = 'Broad permissions are present but no baseline drift was found.'; copy.textContent = 'Confirm every key belongs to a person, wallet, or integration you trust.'; response.hidden = false; return; }
  level.textContent = 'NO NEW RISKY CHANGE'; title.textContent = 'Current scan matches the approved baseline.'; copy.textContent = 'This confirms only the public key and code state inspected by this monitor.';
}
function responsePlan() { if (!current) return; const baseline = new Set(current.baseline?.keys || []); const isDrift = simulated || current.keys.some((key) => !baseline.has(keyId(key))); $('#responseTitle').textContent = isDrift ? 'Contain first. Investigate second.' : 'Confirm owner and scope.'; $('#responseText').textContent = isDrift ? 'Unexpected changes can be legitimate recovery or integration actions. Do not blindly delete keys: retain verified recovery access and confirm the change with the account owner.' : 'Broad permissions are not automatically malicious. Verify owner, receiver contract, allowed methods, and whether the key is still needed.'; const steps = isDrift ? ['Pause any pending signature from this account.', 'Verify the new key owner through an independent channel.', 'Confirm one trusted recovery path remains before revoking anything.', 'Use a wallet or account-management tool to remove an unexpected key, then scan again.'] : ['List every key owner and intended integration.', 'Replace unscoped function-call keys with contract-and-method-restricted keys where possible.', 'Remove unused keys only after confirming recovery.', 'Save a fresh baseline after an approved change.']; $('#responseSteps').innerHTML = steps.map((x) => `<li>${x}</li>`).join(''); $('#responsePlan').hidden = !$('#responsePlan').hidden; }
async function preflight() { const out = $('#preflightResult'); try { const input = JSON.parse($('#transaction').value); const verdict = current ? await api('/api/decisions', { method: 'POST', body: JSON.stringify({ accountId: current.account, transaction: input }) }) : null; const result = verdict?.preflight || await api('/api/preflight', { method: 'POST', body: JSON.stringify(input) }); const css = result.decision === 'BLOCK' ? 'danger' : result.decision === 'REVIEW' ? 'warning' : ''; const gateway = verdict ? `<p><b>SIGNATURE GATEWAY:</b> ${verdict.decisionId} checked public state at block ${verdict.snapshot.blockHeight}. ${verdict.decision === 'BLOCK' ? 'A connected KeySentry SDK will not call the wallet signing callback.' : verdict.requiresExplicitReview ? 'A connected SDK needs explicit review approval before signing.' : 'A connected SDK may proceed to its wallet callback.'}</p>` : ''; out.className = `preflight-result ${css}`; out.innerHTML = `<strong>${result.decision} · STRUCTURAL RISK ${result.score}/100</strong><ul>${result.findings.map((f) => `<li><b>${f.id} / ${f.severity}:</b> ${f.message}</li>`).join('')}</ul>${gateway}<p>Evidence is the decoded visible action and active KeySentry policy. This is not proof that a contract is safe.</p>`; out.hidden = false; } catch (error) { out.className = 'preflight-result danger'; out.innerHTML = `<strong>INVALID ACTION PREVIEW</strong><p>${error.message} Paste valid JSON with an actions array.</p>`; out.hidden = false; } }
function resetSessionView() { current = null; simulated = false; $('#scanForm').reset(); $('#account').value = ''; $('#scanResults').hidden = true; $('#loading').hidden = true; $('#error').hidden = true; $('#preflightResult').hidden = true; }
$('#scanForm').addEventListener('submit', scan); $('#simulateDrift').addEventListener('click', () => { if (current) { simulated = !simulated; render(); } }); $('#responseButton').addEventListener('click', responsePlan); $('#analyze').addEventListener('click', preflight); window.addEventListener('pageshow', resetSessionView); resetSessionView();
