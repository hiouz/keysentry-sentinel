import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { evaluateTransaction } from './decision.mjs';

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8' };
const securityHeaders = { 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=(), microphone=(), geolocation=()', 'content-security-policy': "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'" };
const json = (res, status, body) => { res.writeHead(status, { ...securityHeaders, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
const readBody = async (req) => new Promise((resolve, reject) => {
  let text = '';
  req.on('data', (chunk) => { text += chunk; if (text.length > 65536) reject(new Error('Request body is too large.')); });
  req.on('end', () => { try { resolve(text ? JSON.parse(text) : {}); } catch { reject(new Error('Request body must be valid JSON.')); } });
  req.on('error', reject);
});

export function createApp({ service, publicDir, allowPersistentMonitoring = false }) {
  const limits = new Map();
  return createServer(async (req, res) => {
    try {
      if (!allowRequest(limits, req)) return json(res, 429, { error: 'Too many requests. Try again in one minute.' });
      const url = new URL(req.url, 'http://localhost');
      const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
      if (req.method === 'GET' && url.pathname === '/api/health') return json(res, 200, { ok: true, watches: service.listWatches().length, time: new Date().toISOString() });
      if (req.method === 'POST' && url.pathname === '/api/check') { const body = await readBody(req); return json(res, 200, await service.check(body.accountId)); }
      if (allowPersistentMonitoring && req.method === 'GET' && url.pathname === '/api/watches') return json(res, 200, { watches: service.listWatches() });
      if (allowPersistentMonitoring && req.method === 'GET' && url.pathname === '/api/alerts') return json(res, 200, { alerts: service.alerts(url.searchParams.get('accountId')) });
      if (allowPersistentMonitoring && req.method === 'GET' && url.pathname === '/api/audit') return json(res, 200, { records: service.auditTrail(url.searchParams.get('accountId')), integrity: service.auditIntegrity() });
      if (req.method === 'POST' && url.pathname === '/api/preflight') {
        const body = await readBody(req); return json(res, 200, evaluateTransaction(body, body.accountId ? service.policyFor(body.accountId) : null));
      }
      if (req.method === 'POST' && url.pathname === '/api/decisions') {
        const body = await readBody(req);
        return json(res, 200, allowPersistentMonitoring ? await service.assessTransaction(body.accountId, body.transaction) : await service.assessOneTimeTransaction(body.accountId, body.transaction));
      }
      if (allowPersistentMonitoring && req.method === 'POST' && url.pathname === '/api/watches') {
        const body = await readBody(req); const watch = await service.addWatch(body.accountId, body.intervalSec);
        return json(res, 201, { watch });
      }
      if (allowPersistentMonitoring && parts[0] === 'api' && parts[1] === 'watches' && parts[2]) {
        const accountId = parts[2];
        if (req.method === 'GET' && parts[3] === 'attack-paths') return json(res, 200, service.attackPaths(accountId));
        if (req.method === 'DELETE' && parts.length === 3) { await service.removeWatch(accountId); return json(res, 200, { ok: true }); }
        if (req.method === 'GET' && parts[3] === 'policy') return json(res, 200, { policy: service.policyFor(accountId) });
        if (req.method === 'PUT' && parts[3] === 'policy') return json(res, 200, { watch: await service.updatePolicy(accountId, await readBody(req)) });
        if (req.method === 'POST' && parts[3] === 'scan') return json(res, 200, await service.scan(accountId));
        if (req.method === 'POST' && parts[3] === 'baseline') return json(res, 200, { watch: await service.baseline(accountId) });
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { error: 'Method not allowed.' });
      const safePath = normalize(url.pathname === '/' ? '/index.html' : url.pathname).replace(/^([.]{2}[\\/])+/, '');
      const file = join(publicDir, safePath);
      if (!file.startsWith(publicDir)) return json(res, 403, { error: 'Forbidden.' });
      const data = await readFile(file);
      res.writeHead(200, { ...securityHeaders, 'content-type': MIME[extname(file)] || 'application/octet-stream', 'cache-control': 'no-cache' });
      if (req.method === 'GET') res.end(data); else res.end();
    } catch (error) {
      const status = error.code === 'ENOENT' ? 404 : 400;
      json(res, status, { error: error.message || 'Request failed.' });
    }
  });
}

function allowRequest(limits, req) {
  const now = Date.now();
  const key = `${req.socket.remoteAddress || 'unknown'}:${req.url?.startsWith('/api/') ? 'api' : 'asset'}`;
  const bucket = limits.get(key) || { startedAt: now, count: 0 };
  if (now - bucket.startedAt >= 60_000) { bucket.startedAt = now; bucket.count = 0; }
  bucket.count += 1; limits.set(key, bucket);
  return bucket.count <= (key.endsWith(':api') ? 90 : 240);
}
