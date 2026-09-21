import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const sha256 = s => createHash('sha256').update(s).digest('hex');
export const newToken = () => randomBytes(32).toString('base64url');

export function openStore(path) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS pending_logins (
      token_hash TEXT PRIMARY KEY,           -- sha256 of the random token that lives ONLY in this browser's cookie
      session_id TEXT NOT NULL UNIQUE,       -- ClientN session id; UNIQUE = one pending row per provider session
      created_at INTEGER NOT NULL,           -- unix seconds
      expires_at INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','confirmed','consumed')),
      clientn_id TEXT, verified_human INTEGER, verified_until TEXT
    );
    CREATE TABLE IF NOT EXISTS users (
      clientn_id TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_login INTEGER NOT NULL, verified_human INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS app_sessions (
      id_hash TEXT PRIMARY KEY, clientn_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
  `);
  const q = {
    insPending: db.prepare('INSERT INTO pending_logins (token_hash, session_id, created_at, expires_at) VALUES (?,?,?,?)'),
    byToken: db.prepare('SELECT * FROM pending_logins WHERE token_hash = ?'),
    bySession: db.prepare('SELECT * FROM pending_logins WHERE session_id = ?'),
    // the ONE atomic transition: pending -> confirmed, only if still pending and inside the window
    confirm: db.prepare(`UPDATE pending_logins SET status='confirmed', clientn_id=?, verified_human=?, verified_until=?
                         WHERE session_id=? AND status='pending' AND expires_at + 30 >= ?`),
    // the ONE atomic consumption: confirmed -> consumed; exactly one caller wins
    consume: db.prepare(`UPDATE pending_logins SET status='consumed' WHERE token_hash=? AND status='confirmed'`),
    upsertUser: db.prepare(`INSERT INTO users (clientn_id, first_seen, last_login, verified_human) VALUES (?,?,?,?)
                            ON CONFLICT(clientn_id) DO UPDATE SET last_login=excluded.last_login, verified_human=excluded.verified_human`),
    insSession: db.prepare('INSERT INTO app_sessions (id_hash, clientn_id, created_at, expires_at) VALUES (?,?,?,?)'),
    getSession: db.prepare(`SELECT s.clientn_id, u.verified_human FROM app_sessions s JOIN users u USING (clientn_id) WHERE s.id_hash=? AND s.expires_at > ?`),
    delSession: db.prepare('DELETE FROM app_sessions WHERE id_hash = ?'),
    purge: db.prepare('DELETE FROM pending_logins WHERE expires_at < ?'),
  };
  const now = () => Math.floor(Date.now() / 1000);
  return {
    db,
    createPending(sessionId, ttl = 300) {
      const token = newToken(), t = now();
      q.insPending.run(sha256(token), sessionId, t, t + ttl);
      q.purge.run(t - 3600);
      return { token, createdAt: t, expiresAt: t + ttl };
    },
    pendingByToken: token => q.byToken.get(sha256(token)),
    pendingBySession: id => q.bySession.get(id),
    confirmPending(sessionId, ev, t = now()) {
      return q.confirm.run(ev.clientnId, ev.verifiedHuman ? 1 : 0, ev.verifiedUntil, sessionId, t).changes === 1;
    },
    consumePending: token => q.consume.run(sha256(token)).changes === 1,
    startAppSession(clientnId, verifiedHuman, ttl = 7 * 86400) {
      const t = now();
      q.upsertUser.run(clientnId, t, t, verifiedHuman ? 1 : 0);
      const id = newToken();                       // brand-new id at every login: session fixation is impossible
      q.insSession.run(sha256(id), clientnId, t, t + ttl);
      return id;
    },
    appSession(id) { const r = q.getSession.get(sha256(id), now()); return r ? { clientnId: r.clientn_id, verifiedHuman: !!r.verified_human } : null; },
    endAppSession: id => q.delSession.run(sha256(id)),
    close: () => db.close(),
  };
}
