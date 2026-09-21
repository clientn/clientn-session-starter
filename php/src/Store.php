<?php
declare(strict_types=1);

final class Store
{
    public PDO $db;

    public function __construct(string $path)
    {
        if ($path !== ':memory:' && !is_dir(dirname($path))) { mkdir(dirname($path), 0700, true); }
        $this->db = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS pending_logins (
              token_hash TEXT PRIMARY KEY,          -- sha256 of the random token that lives ONLY in this browser's cookie
              session_id TEXT NOT NULL UNIQUE,      -- ClientN session id; UNIQUE = one pending row per provider session
              created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','confirmed','consumed')),
              clientn_id TEXT, verified_human INTEGER, verified_until TEXT);
            CREATE TABLE IF NOT EXISTS users (clientn_id TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_login INTEGER NOT NULL, verified_human INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS app_sessions (id_hash TEXT PRIMARY KEY, clientn_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
        ");
    }

    public static function token(): string { return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='); }
    private static function h(string $s): string { return hash('sha256', $s); }

    /** @return array{token:string,createdAt:int,expiresAt:int} */
    public function createPending(string $sessionId, int $ttl = 300): array
    {
        $token = self::token(); $t = time();
        $this->db->prepare('INSERT INTO pending_logins (token_hash, session_id, created_at, expires_at) VALUES (?,?,?,?)')->execute([self::h($token), $sessionId, $t, $t + $ttl]);
        $this->db->prepare('DELETE FROM pending_logins WHERE expires_at < ?')->execute([$t - 3600]);
        return ['token' => $token, 'createdAt' => $t, 'expiresAt' => $t + $ttl];
    }
    public function pendingByToken(string $token): ?array { return $this->one('SELECT * FROM pending_logins WHERE token_hash = ?', [self::h($token)]); }
    public function pendingBySession(string $id): ?array { return $this->one('SELECT * FROM pending_logins WHERE session_id = ?', [$id]); }

    /** The ONE atomic transition: pending -> confirmed, only while still pending and inside the window. */
    public function confirmPending(string $sessionId, array $ev, ?int $t = null): bool
    {
        $st = $this->db->prepare("UPDATE pending_logins SET status='confirmed', clientn_id=?, verified_human=?, verified_until=? WHERE session_id=? AND status='pending' AND expires_at + 30 >= CAST(? AS INTEGER)");
        $st->execute([$ev['clientnId'], $ev['verifiedHuman'] ? 1 : 0, $ev['verifiedUntil'], $sessionId, $t ?? time()]);
        return $st->rowCount() === 1;
    }
    /** The ONE atomic consumption: confirmed -> consumed; exactly one caller wins. */
    public function consumePending(string $token): bool
    {
        $st = $this->db->prepare("UPDATE pending_logins SET status='consumed' WHERE token_hash=? AND status='confirmed'");
        $st->execute([self::h($token)]);
        return $st->rowCount() === 1;
    }
    public function startAppSession(string $clientnId, bool $verified, int $ttl = 604800): string
    {
        $t = time();
        $this->db->prepare('INSERT INTO users (clientn_id, first_seen, last_login, verified_human) VALUES (?,?,?,?) ON CONFLICT(clientn_id) DO UPDATE SET last_login=excluded.last_login, verified_human=excluded.verified_human')
            ->execute([$clientnId, $t, $t, $verified ? 1 : 0]);
        $id = self::token();                       // brand-new id at every login: session fixation is impossible
        $this->db->prepare('INSERT INTO app_sessions (id_hash, clientn_id, created_at, expires_at) VALUES (?,?,?,?)')->execute([self::h($id), $clientnId, $t, $t + $ttl]);
        return $id;
    }
    public function appSession(string $id): ?array
    {
        $r = $this->one('SELECT s.clientn_id, u.verified_human FROM app_sessions s JOIN users u USING (clientn_id) WHERE s.id_hash=? AND s.expires_at > ?', [self::h($id), time()]);
        return $r ? ['clientnId' => $r['clientn_id'], 'verifiedHuman' => (bool)$r['verified_human']] : null;
    }
    public function endAppSession(string $id): void { $this->db->prepare('DELETE FROM app_sessions WHERE id_hash = ?')->execute([self::h($id)]); }
    private function one(string $sql, array $args): ?array { $st = $this->db->prepare($sql); $st->execute($args); $r = $st->fetch(); return $r ?: null; }
}
