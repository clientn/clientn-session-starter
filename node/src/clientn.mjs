// Server-to-server calls to the ClientN API. The API key never leaves your server.

async function call(cfg, method, path) {
  const res = await fetch(cfg.apiBase + path, {
    method,
    headers: { Authorization: 'Bearer ' + cfg.apiKey, Accept: 'application/json' },
    redirect: 'error',
    signal: AbortSignal.timeout(8000),
  });
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, body };
}

/** Start a sign-in. Returns {session_id, confirm_url, qr_png_base64, match_code, expires_at}. */
export async function createClientNSession(cfg) {
  const r = await call(cfg, 'POST', '/api/v1/sessions');
  if (r.status !== 201 || !r.body?.session_id) throw new Error('ClientN refused to start a session: ' + r.status + ' ' + (r.body?.error || ''));
  return r.body;
}

/** Recovery: ask ClientN what happened to one of YOUR sessions (Bearer key required). */
export async function getClientNSession(cfg, sessionId) {
  return call(cfg, 'GET', '/api/v1/sessions/' + encodeURIComponent(sessionId));
}
