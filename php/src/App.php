<?php
declare(strict_types=1);
require_once __DIR__ . '/Verify.php';
require_once __DIR__ . '/Store.php';
require_once __DIR__ . '/ClientN.php';

/**
 * The whole integration as a pure function: handle(request) -> response.
 * request  = ['method','path','headers'(lowercase keys),'cookies','body'(raw bytes),'ip']
 * response = ['code','headers','cookies'(Set-Cookie lines),'body']
 */
final class App
{
    private string $pendingName; private string $sessionName;
    private array $recoveryTried = []; private array $startHits = [];

    public function __construct(private array $cfg, private Store $store, private ClientN $api)
    {
        $p = $cfg['secureCookies'] ? '__Host-' : '';
        $this->pendingName = $p . 'cn_pending'; $this->sessionName = $p . 'app_session';
    }

    private function cookie(string $name, string $value, int $maxAge): string
    {
        return "$name=$value; Path=/; HttpOnly; SameSite=Lax; Max-Age=$maxAge" . ($this->cfg['secureCookies'] ? '; Secure' : '');
    }
    private function out(int $code, array|string $body, string $type = 'application/json', array $extra = [], array $cookies = []): array
    {
        $headers = $extra + [
            'Content-Type' => $type, 'Cache-Control' => 'no-store', 'X-Content-Type-Options' => 'nosniff', 'Referrer-Policy' => 'no-referrer', 'X-Frame-Options' => 'DENY',
            'Content-Security-Policy' => "default-src 'self'; script-src 'self' {$this->cfg['apiBase']}; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
        ];
        return ['code' => $code, 'headers' => $headers, 'cookies' => $cookies, 'body' => is_array($body) ? json_encode($body) : $body];
    }
    private function sameOrigin(array $req): bool
    {
        $o = $req['headers']['origin'] ?? null; $s = $req['headers']['sec-fetch-site'] ?? null;
        return $o === $this->cfg['appOrigin'] || ($o === null && $s === 'same-origin');
    }
    private function hmacOk(string $raw, mixed $sig): bool
    {
        return is_string($sig) && preg_match('/\A[a-fA-F0-9]{64}\z/', $sig) === 1
            && hash_equals(hash_hmac('sha256', $raw, $this->cfg['apiSecret']), strtolower($sig));   // exact raw bytes, constant time
    }

    /** ONE code path for a ClientN event, whether it arrived as a callback or was fetched during recovery. */
    public function acceptEvent(string $raw, mixed $sig, ?int $t = null): array
    {
        $t ??= time();
        if (!$this->hmacOk($raw, $sig)) { return [401, ['error' => 'bad_signature']]; }
        $j = json_decode($raw, true);
        $sid = is_array($j) ? ($j['session_id'] ?? null) : null;
        if (!is_array($j)) { return [422, ['error' => 'bad_payload']]; }
        $row = is_string($sid) ? $this->store->pendingBySession($sid) : null;
        if (!$row) { return [404, ['error' => 'unknown_session']]; }                       // a login THIS app did not start
        try {
            $ev = verifyClientNCallback($raw, (string)$sig, $this->cfg['apiSecret'], ['sessionId' => $sid, 'createdAt' => (int)$row['created_at'], 'expiresAt' => (int)$row['expires_at']], $t);
        } catch (InvalidArgumentException) { return [422, ['error' => 'rejected']]; }        // schema, freshness, window
        if ($this->store->confirmPending($sid, $ev, $t)) { return [200, ['ok' => true]]; }
        $cur = $this->store->pendingBySession($sid);
        if ($cur && $cur['status'] !== 'pending' && $cur['clientn_id'] === $ev['clientnId']) { return [200, ['ok' => true, 'duplicate' => true]]; }  // same event again: no second effect
        return [409, ['error' => 'conflict']];                                               // a different identity never replaces the first
    }

    private function maybeRecover(array $row): void
    {
        $t = time(); $last = $this->recoveryTried[$row['session_id']] ?? 0;
        if ($t - (int)$row['created_at'] < 8 || $t - $last < 5) { return; }
        $this->recoveryTried[$row['session_id']] = $t;
        try {
            $r = $this->api->getSession($row['session_id']);
            $b = $r['body'] ?? [];
            if ($r['status'] === 200 && ($b['status'] ?? '') === 'confirmed' && is_string($b['result_raw'] ?? null) && is_string($b['signature'] ?? null)) {
                $this->acceptEvent($b['result_raw'], $b['signature']);
            }
        } catch (Throwable) { /* ClientN unreachable: keep waiting, the callback may still arrive */ }
    }

    public function handle(array $req): array
    {
        try {
            $m = $req['method']; $path = $req['path']; $ck = $req['cookies'];
            if ($m === 'GET' && $path === '/healthz') { return $this->out(200, ['ok' => true]); }

            if ($m === 'GET' && $path === '/') {
                $me = isset($ck[$this->sessionName]) ? $this->store->appSession($ck[$this->sessionName]) : null;
                $head = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ClientN starter</title><body style="font-family:system-ui;max-width:560px;margin:60px auto;padding:0 16px;color:#0f172a;background:#fff">';
                $html = $me
                    ? $head . '<h1>You are signed in</h1><p>Your anonymous ID on this site: <strong>' . htmlspecialchars($me['clientnId']) . '</strong></p><p>Verified human badge: <strong>' . ($me['verifiedHuman'] ? 'yes' : 'no') . '</strong></p><form method="post" action="/logout"><button style="padding:10px 18px">Sign out</button></form></body>'
                    : $head . '<h1>Welcome</h1><p>No passwords. Sign in with ClientN.</p><div id="clientn-signin"></div><script src="' . htmlspecialchars($this->cfg['apiBase']) . '/clientn.js" data-endpoint="/clientn/session" data-status-endpoint="/clientn/status" data-target="#clientn-signin" data-redirect="/"></script></body>';
                return $this->out(200, $html, 'text/html; charset=utf-8');
            }

            // 1. start: server creates the ClientN session and remembers it for THIS browser only
            if ($m === 'POST' && $path === '/clientn/session') {
                if (!$this->sameOrigin($req)) { return $this->out(403, ['error' => 'bad_origin']); }
                $ip = $req['ip'] ?? '?'; $t = time();
                $hits = array_values(array_filter($this->startHits[$ip] ?? [], fn($x) => $x > $t - 60));
                if (count($hits) >= 10) { return $this->out(429, ['error' => 'rate_limited']); }
                $this->startHits[$ip] = [...$hits, $t];     // per-process only: use your real shared rate limiter in production
                $s = $this->api->createSession();
                $p = $this->store->createPending($s['session_id']);
                $body = array_intersect_key($s, array_flip(['session_id', 'confirm_url', 'qr_png_base64', 'match_code', 'expires_at']));
                return $this->out(201, $body, 'application/json', [], [$this->cookie($this->pendingName, $p['token'], 600)]);
            }

            // 2. callback from ClientN (server to server; no cookies, exact raw bytes are signed)
            if ($m === 'POST' && $path === '/clientn/callback') {
                $raw = (string)$req['body'];
                if ($raw === '' || strlen($raw) > 16384) { return $this->out(413, ['error' => 'bad_size']); }
                [$code, $body] = $this->acceptEvent($raw, $req['headers']['x-clientn-signature'] ?? null);
                return $this->out($code, $body);
            }

            // 3. the browser that started the login asks whether it may come in now
            if ($m === 'GET' && $path === '/clientn/status') {
                $token = $ck[$this->pendingName] ?? null;
                $row = $token ? $this->store->pendingByToken($token) : null;
                if (!$row || $row['status'] === 'consumed') { return $this->out(200, ['status' => 'none']); }
                if ($row['status'] === 'pending') { $this->maybeRecover($row); $row = $this->store->pendingByToken($token); }
                if ($row['status'] === 'confirmed' && (int)$row['expires_at'] + 30 >= time()) {
                    if (!$this->store->consumePending($token)) { return $this->out(200, ['status' => 'none']); }   // someone else won the race
                    $sid = $this->store->startAppSession($row['clientn_id'], (bool)$row['verified_human']);         // fresh session id
                    return $this->out(200, ['status' => 'confirmed'], 'application/json', [], [$this->cookie($this->sessionName, $sid, 604800), $this->cookie($this->pendingName, '', 0)]);
                }
                return $this->out(200, ['status' => (int)$row['expires_at'] + 30 < time() ? 'expired' : 'pending']);
            }

            if ($m === 'POST' && $path === '/logout') {
                if (!$this->sameOrigin($req)) { return $this->out(403, ['error' => 'bad_origin']); }
                if (isset($ck[$this->sessionName])) { $this->store->endAppSession($ck[$this->sessionName]); }
                return $this->out(303, '', 'text/plain', ['Location' => '/'], [$this->cookie($this->sessionName, '', 0)]);
            }
            return $this->out(404, ['error' => 'not_found']);
        } catch (Throwable $e) {
            error_log('[error] ' . $e->getMessage());
            return $this->out(500, ['error' => 'server_error']);
        }
    }
}
