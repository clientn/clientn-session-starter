import http from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { loadConfig, assertConfig } from './config.mjs';
import { openStore } from './store.mjs';
import { createClientNSession, getClientNSession } from './clientn.mjs';
import { verifyClientNCallback } from './verify.mjs';

const MAX_CALLBACK_BYTES = 16384;

export function createApp(cfg, store, api = { createClientNSession, getClientNSession }) {
  const P = cfg.secureCookies ? '__Host-' : '';
  const PENDING = P + 'cn_pending', SESSION = P + 'app_session';
  const recoveryTried = new Map();          // session_id -> last recovery attempt (unix s)
  const startHits = new Map();              // ip -> [timestamps]   (tiny in-memory limiter; use your real one in production)
  const now = () => Math.floor(Date.now() / 1000);

  const cookieHeader = (name, value, maxAge) =>
    `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}` + (cfg.secureCookies ? '; Secure' : '');
  const parseCookies = h => Object.fromEntries((h || '').split(';').map(s => s.trim().split(/=(.*)/s).slice(0, 2)).filter(p => p[0]));
  const baseHeaders = {
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
    'Content-Security-Policy': `default-src 'self'; script-src 'self' ${cfg.apiBase}; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'`,
  };
  function send(res, code, body, type = 'application/json', extra = {}) {
    res.writeHead(code, { ...baseHeaders, 'Content-Type': type, 'Cache-Control': 'no-store', ...extra });
    res.end(type === 'application/json' ? JSON.stringify(body) : body);
  }
  const sameOrigin = req => {
    const o = req.headers.origin, s = req.headers['sec-fetch-site'];
    return o === cfg.appOrigin || (!o && (s === 'same-origin'));
  };
  async function readRaw(req, max) {
    const chunks = []; let n = 0;
    for await (const c of req) { n += c.length; if (n > max) return null; chunks.push(c); }
    return Buffer.concat(chunks);
  }
  const hmacOk = (raw, sig) => {
    if (typeof sig !== 'string' || !/^[a-fA-F0-9]{64}$/.test(sig)) return false;
    const exp = createHmac('sha256', cfg.apiSecret).update(raw).digest();
    return timingSafeEqual(exp, Buffer.from(sig, 'hex'));
  };

  /** ONE code path for a ClientN event, whether it arrived as a callback or was fetched during recovery. */
  function acceptEvent(raw, sig, t = now()) {
    if (!hmacOk(raw, sig)) return { code: 401, body: { error: 'bad_signature' } };       // exact raw bytes, constant time
    let sessionId;
    try { sessionId = JSON.parse(raw.toString('utf8'))?.session_id; } catch { return { code: 422, body: { error: 'bad_payload' } }; }
    const row = typeof sessionId === 'string' ? store.pendingBySession(sessionId) : null;
    if (!row) return { code: 404, body: { error: 'unknown_session' } };                   // a login THIS app did not start
    let ev;
    try { ev = verifyClientNCallback(raw, sig, cfg.apiSecret, { sessionId, createdAt: row.created_at, expiresAt: row.expires_at }, t); }
    catch { return { code: 422, body: { error: 'rejected' } }; }                          // schema, freshness, window
    if (store.confirmPending(sessionId, ev, t)) return { code: 200, body: { ok: true } };
    const cur = store.pendingBySession(sessionId);
    if (cur && cur.status !== 'pending' && cur.clientn_id === ev.clientnId) return { code: 200, body: { ok: true, duplicate: true } };  // same event again: no second side effect
    return { code: 409, body: { error: 'conflict' } };                                    // a different identity never replaces the first
  }

  async function maybeRecover(row) {
    const last = recoveryTried.get(row.session_id) || 0, t = now();
    if (t - row.created_at < 8 || t - last < 5) return;
    recoveryTried.set(row.session_id, t);
    try {
      const r = await api.getClientNSession(cfg, row.session_id);
      if (r.status === 200 && r.body?.status === 'confirmed' && typeof r.body.result_raw === 'string' && typeof r.body.signature === 'string') {
        acceptEvent(Buffer.from(r.body.result_raw, 'utf8'), r.body.signature);
      }
    } catch { /* ClientN unreachable: keep waiting, the callback may still arrive */ }
  }

  return async function handler(req, res) {
    try {
      const url = new URL(req.url, cfg.appOrigin);
      const cookies = parseCookies(req.headers.cookie);

      if (req.method === 'GET' && url.pathname === '/healthz') return send(res, 200, { ok: true });

      if (req.method === 'GET' && url.pathname === '/') {
        const me = cookies[SESSION] ? store.appSession(cookies[SESSION]) : null;
        const html = me
          ? `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Signed in</title>
             <body style="font-family:system-ui;max-width:560px;margin:60px auto;padding:0 16px;color:#0f172a;background:#fff">
             <h1>You are signed in</h1><p>Your anonymous ID on this site: <strong>${me.clientnId}</strong></p>
             <p>Verified human badge: <strong>${me.verifiedHuman ? 'yes' : 'no'}</strong></p>
             <form method="post" action="/logout"><button style="padding:10px 18px">Sign out</button></form></body>`
          : `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in</title>
             <body style="font-family:system-ui;max-width:560px;margin:60px auto;padding:0 16px;color:#0f172a;background:#fff">
             <h1>Welcome</h1><p>No passwords. Sign in with ClientN.</p><div id="clientn-signin"></div>
             <script src="${cfg.apiBase}/clientn.js" data-endpoint="/clientn/session" data-status-endpoint="/clientn/status" data-target="#clientn-signin" data-redirect="/"></script></body>`;
        return send(res, 200, html, 'text/html; charset=utf-8');
      }

      // 1. start: server creates the ClientN session and remembers it for THIS browser only
      if (req.method === 'POST' && url.pathname === '/clientn/session') {
        if (!sameOrigin(req)) return send(res, 403, { error: 'bad_origin' });
        const ip = req.socket.remoteAddress || '?', t = now();
        const hits = (startHits.get(ip) || []).filter(x => x > t - 60);
        if (hits.length >= 10) return send(res, 429, { error: 'rate_limited' });
        startHits.set(ip, [...hits, t]);
        const s = await api.createClientNSession(cfg);
        const p = store.createPending(s.session_id);
        return send(res, 201, { session_id: s.session_id, confirm_url: s.confirm_url, qr_png_base64: s.qr_png_base64, match_code: s.match_code, expires_at: s.expires_at },
          'application/json', { 'Set-Cookie': cookieHeader(PENDING, p.token, 600) });
      }

      // 2. callback from ClientN (server to server; no cookies, exact raw bytes are signed)
      if (req.method === 'POST' && url.pathname === '/clientn/callback') {
        const raw = await readRaw(req, MAX_CALLBACK_BYTES);
        if (!raw || raw.length === 0) return send(res, 413, { error: 'bad_size' });
        const r = acceptEvent(raw, req.headers['x-clientn-signature']);
        return send(res, r.code, r.body);
      }

      // 3. the browser that started the login asks whether it may come in now
      if (req.method === 'GET' && url.pathname === '/clientn/status') {
        const token = cookies[PENDING];
        let row = token ? store.pendingByToken(token) : null;
        if (!row || row.status === 'consumed') return send(res, 200, { status: 'none' });
        if (row.status === 'pending') { await maybeRecover(row); row = store.pendingByToken(token); }
        if (row.status === 'confirmed' && row.expires_at + 30 >= now()) {
          if (!store.consumePending(token)) return send(res, 200, { status: 'none' });            // someone else won the race
          const sid = store.startAppSession(row.clientn_id, !!row.verified_human);                // fresh session id
          return send(res, 200, { status: 'confirmed' }, 'application/json',
            { 'Set-Cookie': [cookieHeader(SESSION, sid, 7 * 86400), cookieHeader(PENDING, '', 0)] });
        }
        return send(res, 200, { status: row.expires_at + 30 < now() ? 'expired' : 'pending' });
      }

      if (req.method === 'POST' && url.pathname === '/logout') {
        if (!sameOrigin(req)) return send(res, 403, { error: 'bad_origin' });
        if (cookies[SESSION]) store.endAppSession(cookies[SESSION]);
        return send(res, 303, '', 'text/plain', { Location: '/', 'Set-Cookie': cookieHeader(SESSION, '', 0) });
      }

      return send(res, 404, { error: 'not_found' });
    } catch (e) {
      console.error('[error]', e.message);
      return send(res, 500, { error: 'server_error' });
    }
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  const cfg = loadConfig(); assertConfig(cfg);
  const store = openStore(cfg.dbPath);
  http.createServer(createApp(cfg, store)).listen(cfg.port, cfg.host, () => console.log(`listening on ${cfg.host}:${cfg.port} as ${cfg.appOrigin}`));
}
