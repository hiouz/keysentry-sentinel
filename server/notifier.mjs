import { createHmac } from 'node:crypto';

export function createWebhookNotifier({ url = process.env.KEYSENTRY_WEBHOOK_URL, secret = process.env.KEYSENTRY_WEBHOOK_SECRET, fetchImpl = fetch } = {}) {
  return {
    configured: Boolean(url),
    async send(alert) {
      if (!url) return { delivered: false, reason: 'not-configured' };
      const body = JSON.stringify({ source: 'KeySentry', version: 1, alert });
      const headers = { 'content-type': 'application/json', 'x-keysentry-event': 'security-alert' };
      if (secret) headers['x-keysentry-signature'] = `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
      const response = await fetchImpl(url, { method: 'POST', headers, body, signal: AbortSignal.timeout(8000) });
      if (!response.ok) throw new Error(`Webhook returned HTTP ${response.status}`);
      return { delivered: true };
    }
  };
}
