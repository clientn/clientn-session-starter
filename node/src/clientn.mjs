// Server-to-server calls to the ClientN API. The API key never leaves your server.

async function call(cfg, method, path, payload) {
  const headers = { Authorization: 'Bearer ' + cfg.apiKey, Accept: 'application/json' };
  if (payload !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(cfg.apiBase + path, {
    method,
    headers,
    body: payload === undefined ? undefined : JSON.stringify(payload),
    redirect: 'error',
    signal: AbortSignal.timeout(8000),
  });
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, body };
}

/**
 * Start a sign-in. `opts` is the JSON body: {flow, return_url, code_challenge, end_user_ip, end_user_agent}.
 * Returns {session_id, flow, confirm_url, qr_png_base64, match_code, expires_at}.
 */
export async function createClientNSession(cfg, opts = {}) {
  const r = await call(cfg, 'POST', '/api/v1/sessions', opts);
  if (r.status !== 201 || !r.body?.session_id) throw new Error('ClientN refused to start a session: ' + r.status + ' ' + (r.body?.error || ''));
  return r.body;
}

/** Recovery: ask ClientN what happened to one of YOUR sessions (Bearer key required). */
export async function getClientNSession(cfg, sessionId) {
  return call(cfg, 'GET', '/api/v1/sessions/' + encodeURIComponent(sessionId));
}

/** Redirect flow: trade the one-time code + this browser's verifier for the signed result (works once). */
export async function exchangeClientNSession(cfg, sessionId, code, codeVerifier) {
  return call(cfg, 'POST', '/api/v1/sessions/' + encodeURIComponent(sessionId) + '/exchange', { code, code_verifier: codeVerifier });
}
