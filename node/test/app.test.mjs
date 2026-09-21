import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { createApp } from '../src/server.mjs';
import { openStore } from '../src/store.mjs';
import { createClientNSession, getClientNSession } from '../src/clientn.mjs';

const SECRET = 'cnsk_TEST_ONLY_0123456789abcdef0123456789abcdef01234567';
const KEY = '0123456789abcdef0123456789abcdef';
const ORIGIN = 'http://localhost:3999';
const cfg = { apiBase: 'https://clientn.example', apiKey: KEY, apiSecret: SECRET, appOrigin: ORIGIN, secureCookies: false };
const unix = () => Math.floor(Date.now() / 1000);
const sign = raw => createHmac('sha256', SECRET).update(raw).digest('hex');
let counter = 0;
const nextSessionId = () => `00000000-0000-4000-8000-${String(++counter).padStart(12, '0')}`;
const event = (sessionId, o = {}) => JSON.stringify({ session_id: sessionId, clientn_id: 'CN-ABCDEFGHIJKL', verified_human: false, verified_until: null, match_code: 'AB3K', ts: unix(), ...o });

async function boot(over = {}, apiStub) {
  const store = openStore(':memory:');
  const api = apiStub || {
    createClientNSession: async () => ({ session_id: nextSessionId(), confirm_url: 'https://clientn.example/s/x', qr_png_base64: 'AAAA', match_code: 'AB3K', expires_at: 'x', api_key_leak: KEY }),
    getClientNSession: async () => ({ status: 404, body: { error: 'not_found' } }),
  };
  const server = http.createServer(createApp({ ...cfg, ...over }, store, api));
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const close = () => { server.close(); server.closeAllConnections?.(); store.close(); };
  return { store, base, close };
}
const cookieOf = (res, name) => { const c = res.headers.getSetCookie().find(x => x.startsWith(name + '=')); return c ? c.split(';')[0] : null; };
const start = (app, headers = { Origin: ORIGIN }) => fetch(app.base + '/clientn/session', { method: 'POST', headers });
const callback = (app, raw, sig = sign(raw)) => fetch(app.base + '/clientn/callback', { method: 'POST', body: raw, headers: { 'X-ClientN-Signature': sig, 'Content-Type': 'application/json' } });
const status = (app, cookie) => fetch(app.base + '/clientn/status', { headers: cookie ? { Cookie: cookie } : {} }).then(async r => ({ r, j: await r.json() }));
async function begin(app) { const res = await start(app); const j = await res.json(); return { sid: j.session_id, cookie: cookieOf(res, 'cn_pending'), res, j }; }

test('start: refuses a cross-site request (login CSRF)', async () => {
  const app = await boot();
  assert.equal((await start(app, {})).status, 403);
  assert.equal((await start(app, { Origin: 'https://evil.example' })).status, 403);
  app.close();
});

test('start: pending cookie is HttpOnly + SameSite, and the API key never reaches the browser', async () => {
  const app = await boot();
  const { res, j } = await begin(app);
  assert.equal(res.status, 201);
  const raw = res.headers.getSetCookie().find(c => c.startsWith('cn_pending='));
  assert.match(raw, /HttpOnly/); assert.match(raw, /SameSite=Lax/);
  assert.ok(!JSON.stringify(j).includes(KEY) && !('api_key_leak' in j));
  assert.deepEqual(Object.keys(j).sort(), ['confirm_url', 'expires_at', 'match_code', 'qr_png_base64', 'session_id']);
  app.close();
});

test('secure deployment uses __Host- cookies with Secure', async () => {
  const app = await boot({ appOrigin: 'https://app.example', secureCookies: true });
  const res = await start(app, { Origin: 'https://app.example' });
  const c = res.headers.getSetCookie()[0];
  assert.match(c, /^__Host-cn_pending=/); assert.match(c, /; Secure/); assert.match(c, /Path=\//);
  app.close();
});

test('full login: callback -> status confirmed -> signed in with a fresh session id', async () => {
  const app = await boot();
  const { sid, cookie } = await begin(app);
  assert.equal((await status(app, cookie)).j.status, 'pending');
  assert.equal((await callback(app, event(sid))).status, 200);
  const { r, j } = await status(app, cookie);
  assert.equal(j.status, 'confirmed');
  const sess = cookieOf(r, 'app_session');
  assert.ok(sess && sess.length > 30);
  assert.match(r.headers.getSetCookie().find(c => c.startsWith('app_session=')), /HttpOnly/);
  const home = await fetch(app.base + '/', { headers: { Cookie: sess } }).then(x => x.text());
  assert.match(home, /CN-ABCDEFGHIJKL/); assert.match(home, /badge: <strong>no/);
  app.close();
});

test('callback: bad / missing / tampered signature and oversized body are refused', async () => {
  const app = await boot();
  const { sid, cookie } = await begin(app);
  const raw = event(sid);
  assert.equal((await callback(app, raw, '0'.repeat(64))).status, 401);
  assert.equal((await callback(app, raw, 'zz')).status, 401);
  assert.equal((await fetch(app.base + '/clientn/callback', { method: 'POST', body: raw })).status, 401);
  assert.equal((await callback(app, raw.replace('AB3K', 'AB3L'), sign(raw))).status, 401);
  assert.equal((await callback(app, 'x'.repeat(20000), sign('x'))).status, 413);
  assert.equal((await status(app, cookie)).j.status, 'pending');
  app.close();
});

test('callback: unknown session, stale timestamp, wrong types are refused (correctly signed)', async () => {
  const app = await boot();
  const { sid } = await begin(app);
  assert.equal((await callback(app, event(nextSessionId()))).status, 404);
  assert.equal((await callback(app, event(sid, { ts: unix() - 3600 }))).status, 422);
  assert.equal((await callback(app, event(sid, { verified_human: 'yes' }))).status, 422);
  assert.equal((await callback(app, event(sid, { clientn_id: 'admin' }))).status, 422);
  assert.equal((await callback(app, '{not json')).status, 422);
  app.close();
});

test('another browser cannot take over the login, even knowing the session id', async () => {
  const app = await boot();
  const a = await begin(app), b = await begin(app);
  await callback(app, event(a.sid));
  assert.equal((await status(app, b.cookie)).j.status, 'pending');     // B's own pending is untouched
  assert.equal((await status(app, undefined)).j.status, 'none');        // no cookie at all
  assert.equal((await status(app, 'cn_pending=' + 'A'.repeat(43))).j.status, 'none');
  assert.equal((await status(app, a.cookie)).j.status, 'confirmed');    // the initiating browser succeeds
  app.close();
});

test('single use: second status is none; parallel polls create exactly ONE session', async () => {
  const app = await boot();
  const { sid, cookie } = await begin(app);
  await callback(app, event(sid));
  const results = await Promise.all([1, 2, 3, 4, 5].map(() => status(app, cookie)));
  assert.equal(results.filter(x => x.j.status === 'confirmed').length, 1);
  assert.equal(app.store.db.prepare('SELECT COUNT(*) n FROM app_sessions').get().n, 1);
  assert.equal((await status(app, cookie)).j.status, 'none');
  app.close();
});

test('replay: the same event again is accepted but has no second effect; a conflicting one is refused', async () => {
  const app = await boot();
  const { sid, cookie } = await begin(app);
  const raw = event(sid);
  assert.equal((await callback(app, raw)).status, 200);
  await status(app, cookie);
  const again = await callback(app, raw);
  assert.equal(again.status, 200); assert.equal((await again.json()).duplicate, true);
  assert.equal(app.store.db.prepare('SELECT COUNT(*) n FROM app_sessions').get().n, 1);
  assert.equal((await callback(app, event(sid, { clientn_id: 'CN-ZZZZZZZZZZZZ' }))).status, 409);
  assert.equal(app.store.pendingBySession(sid).clientn_id, 'CN-ABCDEFGHIJKL');
  app.close();
});

test('expired pending: late callback refused, status says expired', async () => {
  const app = await boot();
  const { sid, cookie } = await begin(app);
  app.store.db.prepare('UPDATE pending_logins SET created_at=created_at-1000, expires_at=expires_at-1000 WHERE session_id=?').run(sid);
  assert.equal((await callback(app, event(sid))).status, 422);
  assert.equal((await status(app, cookie)).j.status, 'expired');
  app.close();
});

test('recovery: lost callback is healed from ClientN (signed result verified over the exact bytes)', async () => {
  let session;
  const stub = {
    createClientNSession: async () => { session = nextSessionId(); return { session_id: session, confirm_url: 'u', qr_png_base64: '', match_code: 'AB3K', expires_at: 'x' }; },
    getClientNSession: async () => { const raw = event(session); return { status: 200, body: { status: 'confirmed', result_raw: raw, signature: sign(raw) } }; },
  };
  const app = await boot({}, stub);
  const { cookie, sid } = await begin(app);
  assert.equal((await status(app, cookie)).j.status, 'pending');        // too early: no recovery attempt yet
  app.store.db.prepare('UPDATE pending_logins SET created_at=created_at-20, expires_at=expires_at-20 WHERE session_id=?').run(sid);
  assert.equal((await status(app, cookie)).j.status, 'confirmed');
  app.close();
});

test('recovery: a forged result from a fake ClientN is ignored', async () => {
  let session;
  const stub = {
    createClientNSession: async () => { session = nextSessionId(); return { session_id: session, confirm_url: 'u', qr_png_base64: '', match_code: 'AB3K', expires_at: 'x' }; },
    getClientNSession: async () => ({ status: 200, body: { status: 'confirmed', result_raw: event(session), signature: '0'.repeat(64) } }),
  };
  const app = await boot({}, stub);
  const { cookie, sid } = await begin(app);
  app.store.db.prepare('UPDATE pending_logins SET created_at=created_at-20, expires_at=expires_at-20 WHERE session_id=?').run(sid);
  assert.equal((await status(app, cookie)).j.status, 'pending');
  app.close();
});

test('logout: cross-site refused, real logout ends the session', async () => {
  const app = await boot();
  const { sid, cookie } = await begin(app);
  await callback(app, event(sid));
  const sess = cookieOf((await status(app, cookie)).r, 'app_session');
  assert.equal((await fetch(app.base + '/logout', { method: 'POST', headers: { Cookie: sess, Origin: 'https://evil.example' } })).status, 403);
  assert.match(await fetch(app.base + '/', { headers: { Cookie: sess } }).then(r => r.text()), /signed in/);
  await fetch(app.base + '/logout', { method: 'POST', headers: { Cookie: sess, Origin: ORIGIN }, redirect: 'manual' });
  assert.match(await fetch(app.base + '/', { headers: { Cookie: sess } }).then(r => r.text()), /clientn-signin/);
  app.close();
});

test('pages send CSP + nosniff + frame protection', async () => {
  const app = await boot();
  const r = await fetch(app.base + '/');
  assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  app.close();
});

test('clientn.mjs: sends the Bearer key, refuses non-201, never follows redirects', async () => {
  const seen = [];
  const fake = http.createServer((req, res) => {
    seen.push({ m: req.method, u: req.url, a: req.headers.authorization });
    if (req.url === '/api/v1/sessions') { res.writeHead(201, { 'Content-Type': 'application/json' }); res.end('{"session_id":"s1"}'); }
    else if (req.url === '/api/v1/sessions/redir') { res.writeHead(302, { Location: 'http://127.0.0.1:1/' }); res.end(); }
    else { res.writeHead(403); res.end('{"error":"domain_not_verified"}'); }
  });
  await new Promise(r => fake.listen(0, '127.0.0.1', r));
  const c = { apiBase: `http://127.0.0.1:${fake.address().port}`, apiKey: KEY };
  assert.equal((await createClientNSession(c)).session_id, 's1');
  assert.deepEqual(seen[0], { m: 'POST', u: '/api/v1/sessions', a: 'Bearer ' + KEY });
  assert.equal((await getClientNSession(c, 'abc')).status, 403);
  await assert.rejects(() => getClientNSession(c, 'redir'));
  await assert.rejects(() => createClientNSession({ ...c, apiBase: c.apiBase + '/nope' }));
  fake.close(); fake.closeAllConnections?.();
});
