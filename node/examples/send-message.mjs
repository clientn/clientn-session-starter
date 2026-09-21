// Send a private message to a paid ClientN member who signed in to your site.
// Usage: CLIENTN_API_KEY=... CLIENTN_API_SECRET=... CLIENTN_RECIPIENT=CN-XXXXXXXXXXXX node examples/send-message.mjs
import { createHmac } from 'node:crypto';

export async function sendMessage({ apiBase = 'https://clientn.com', apiKey, apiSecret, clientnId, subject, text, category = 'service', idempotencyKey }) {
  const body = JSON.stringify({
    recipient: clientnId,              // the CN- id you received in the login callback for THIS site
    category,                          // 'service' (about their account with you) or 'updates' (opt-in by the person)
    subject, text,
    idempotency_key: idempotencyKey,   // reuse the same key when you retry: never sends twice
    ts: Math.floor(Date.now() / 1000),
  });
  const signature = createHmac('sha256', apiSecret).update(body).digest('hex');   // sign the exact bytes you send
  const res = await fetch(apiBase + '/api/v1/messages', {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { Authorization: 'Bearer ' + apiKey, 'X-ClientN-Signature': signature, 'Content-Type': 'application/json' },
    body,
  });
  return { status: res.status, json: await res.json() };
}

/** 202 accepted does NOT mean delivered. Ask later; 'not_delivered' covers blocked, not a paying member, no consent. ClientN never says which. */
export async function messageStatus({ apiBase = 'https://clientn.com', apiKey, id }) {
  const res = await fetch(apiBase + '/api/v1/messages/' + encodeURIComponent(id), { headers: { Authorization: 'Bearer ' + apiKey }, redirect: 'error' });
  return res.json();
}

if (import.meta.url === new URL(process.argv[1], 'file://').href) {
  const r = await sendMessage({
    apiKey: process.env.CLIENTN_API_KEY, apiSecret: process.env.CLIENTN_API_SECRET, clientnId: process.env.CLIENTN_RECIPIENT,
    subject: 'Your order has shipped', text: 'Order 1042 is on its way.', idempotencyKey: 'order-1042-shipped',
  });
  console.log(r.status, r.json);
}
