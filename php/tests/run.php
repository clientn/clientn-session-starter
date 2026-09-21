<?php
declare(strict_types=1);
// Run: php tests/run.php   (exit code 1 on any failure)
require __DIR__ . '/../src/App.php';

$SECRET = 'cnsk_TEST_ONLY_0123456789abcdef0123456789abcdef01234567';
$KEY = '0123456789abcdef0123456789abcdef';
$ORIGIN = 'http://localhost:3999';
$pass = 0; $fail = 0; $n = 0;
function t(string $name, bool $cond): void { global $pass, $fail; if ($cond) { $pass++; echo "PASS  $name\n"; } else { $fail++; echo "FAIL  $name\n"; } }
function sid(): string { global $n; return sprintf('00000000-0000-4000-8000-%012d', ++$n); }
function sign(string $raw): string { global $SECRET; return hash_hmac('sha256', $raw, $SECRET); }
function ev(string $sid, array $o = []): string { return json_encode($o + ['session_id' => $sid, 'clientn_id' => 'CN-ABCDEFGHIJKL', 'verified_human' => false, 'verified_until' => null, 'match_code' => 'AB3K', 'ts' => time()]); }

class FakeApi extends ClientN {
    public ?string $last = null; public $getter = null;
    public function __construct() {}
    public function createSession(): array { $this->last = sid(); return ['session_id' => $this->last, 'confirm_url' => 'https://clientn.example/s/x', 'qr_png_base64' => 'AAAA', 'match_code' => 'AB3K', 'expires_at' => 'x', 'api_key_leak' => $GLOBALS['KEY']]; }
    public function getSession(string $sessionId): array { return $this->getter ? ($this->getter)($sessionId) : ['status' => 404, 'body' => ['error' => 'not_found']]; }
}
function boot(array $over = []): array {
    global $SECRET, $KEY, $ORIGIN;
    $store = new Store(':memory:'); $api = new FakeApi();
    $app = new App($over + ['apiBase' => 'https://clientn.example', 'apiKey' => $KEY, 'apiSecret' => $SECRET, 'appOrigin' => $ORIGIN, 'secureCookies' => false], $store, $api);
    return [$app, $store, $api];
}
function req(string $method, string $path, array $o = []): array { return $o + ['method' => $method, 'path' => $path, 'headers' => [], 'cookies' => [], 'body' => '', 'ip' => '1.2.3.4']; }
function cookieVal(array $res, string $name): ?string { foreach ($res['cookies'] as $c) { if (str_starts_with($c, $name . '=')) { return explode(';', $c)[0] === $name . '=' ? '' : substr(explode(';', $c)[0], strlen($name) + 1); } } return null; }
function begin(App $app, FakeApi $api): array { global $ORIGIN; $r = $app->handle(req('POST', '/clientn/session', ['headers' => ['origin' => $ORIGIN]])); return ['res' => $r, 'sid' => $api->last, 'tok' => cookieVal($r, 'cn_pending'), 'j' => json_decode($r['body'], true)]; }
function status(App $app, ?string $tok): array { $r = $app->handle(req('GET', '/clientn/status', ['cookies' => $tok ? ['cn_pending' => $tok] : []])); return [$r, json_decode($r['body'], true)['status']]; }
function cb(App $app, string $raw, ?string $sig = null): array { return $app->handle(req('POST', '/clientn/callback', ['body' => $raw, 'headers' => ['x-clientn-signature' => $sig ?? sign($raw)]])); }
function age(Store $s, string $sid, int $by): void { $s->db->prepare('UPDATE pending_logins SET created_at=created_at-?, expires_at=expires_at-? WHERE session_id=?')->execute([$by, $by, $sid]); }

// --- start
[$app, $store, $api] = boot();
t('start: cross-site request refused (login CSRF)', $app->handle(req('POST', '/clientn/session'))['code'] === 403 && $app->handle(req('POST', '/clientn/session', ['headers' => ['origin' => 'https://evil.example']]))['code'] === 403);
$b = begin($app, $api);
$setc = $b['res']['cookies'][0] ?? '';
t('start: 201 + pending cookie HttpOnly + SameSite', $b['res']['code'] === 201 && str_contains($setc, 'HttpOnly') && str_contains($setc, 'SameSite=Lax'));
t('start: API key never reaches the browser; only the allowed fields are returned', !str_contains($b['res']['body'], $KEY) && array_keys($b['j']) === ['session_id', 'confirm_url', 'qr_png_base64', 'match_code', 'expires_at']);
t('same-origin check: Sec-Fetch-Site wins, Origin: null tolerated from no-referrer form posts, cross-site refused',
  $app->handle(req('POST', '/clientn/session', ['headers' => ['sec-fetch-site' => 'same-origin', 'origin' => 'null']]))['code'] === 201
  && $app->handle(req('POST', '/clientn/session', ['headers' => ['sec-fetch-site' => 'cross-site', 'origin' => $ORIGIN]]))['code'] === 403
  && $app->handle(req('POST', '/clientn/session', ['headers' => ['sec-fetch-site' => 'same-site']]))['code'] === 403
  && $app->handle(req('POST', '/clientn/session', ['headers' => ['origin' => 'null']]))['code'] === 403);
[$sapp, , $sapi] = boot(['appOrigin' => 'https://app.example', 'secureCookies' => true]);
$sr = $sapp->handle(req('POST', '/clientn/session', ['headers' => ['origin' => 'https://app.example']]));
t('secure deployment: __Host- cookie with Secure and Path=/', preg_match('/^__Host-cn_pending=.*; Path=\/;.*; Secure/', $sr['cookies'][0]) === 1);

// --- full login
[$app, $store, $api] = boot(); $b = begin($app, $api);
t('status before the callback is pending', status($app, $b['tok'])[1] === 'pending');
t('valid callback -> 200', cb($app, ev($b['sid']))['code'] === 200);
[$r, $s] = status($app, $b['tok']);
$sess = cookieVal($r, 'app_session');
t('status confirmed -> fresh app session cookie (HttpOnly)', $s === 'confirmed' && strlen((string)$sess) > 30 && str_contains(implode('|', $r['cookies']), 'HttpOnly'));
$home = $app->handle(req('GET', '/', ['cookies' => ['app_session' => $sess]]))['body'];
t('home shows the anonymous CN- id and no badge', str_contains($home, 'CN-ABCDEFGHIJKL') && str_contains($home, 'badge: <strong>no'));

// --- callback refusals
[$app, $store, $api] = boot(); $b = begin($app, $api); $raw = ev($b['sid']);
t('callback: wrong signature -> 401', cb($app, $raw, str_repeat('0', 64))['code'] === 401);
t('callback: malformed signature -> 401', cb($app, $raw, 'zz')['code'] === 401);
t('callback: missing signature -> 401', $app->handle(req('POST', '/clientn/callback', ['body' => $raw]))['code'] === 401);
t('callback: body tampered after signing -> 401', cb($app, str_replace('AB3K', 'AB3L', $raw), sign($raw))['code'] === 401);
t('callback: oversized body -> 413', cb($app, str_repeat('x', 20000), sign('x'))['code'] === 413);
t('callback: unknown session (correctly signed) -> 404', cb($app, ev(sid()))['code'] === 404);
t('callback: stale timestamp -> 422', cb($app, ev($b['sid'], ['ts' => time() - 3600]))['code'] === 422);
t('callback: wrong types -> 422', cb($app, ev($b['sid'], ['verified_human' => 'yes']))['code'] === 422 && cb($app, ev($b['sid'], ['clientn_id' => 'admin']))['code'] === 422);
t('callback: not JSON (signed) -> 422', cb($app, '{not json')['code'] === 422);
t('nothing above changed the pending login', status($app, $b['tok'])[1] === 'pending');

// --- binding to the initiating browser
[$app, $store, $api] = boot(); $a = begin($app, $api); $bb = begin($app, $api); cb($app, ev($a['sid']));
t("another browser's pending login is untouched", status($app, $bb['tok'])[1] === 'pending');
t('no cookie / random cookie cannot log in', status($app, null)[1] === 'none' && status($app, str_repeat('A', 43))[1] === 'none');
t('the initiating browser succeeds', status($app, $a['tok'])[1] === 'confirmed');
t('single use: second status is none, exactly one session row', status($app, $a['tok'])[1] === 'none' && (int)$store->db->query('SELECT COUNT(*) FROM app_sessions')->fetchColumn() === 1);

// --- replay / conflict
[$app, $store, $api] = boot(); $b = begin($app, $api); $raw = ev($b['sid']);
t('first delivery accepted', cb($app, $raw)['code'] === 200); status($app, $b['tok']);
$again = cb($app, $raw);
t('same event again: 200 duplicate, no second session', $again['code'] === 200 && str_contains($again['body'], 'duplicate') && (int)$store->db->query('SELECT COUNT(*) FROM app_sessions')->fetchColumn() === 1);
t('conflicting identity -> 409 and the first identity stays', cb($app, ev($b['sid'], ['clientn_id' => 'CN-ZZZZZZZZZZZZ']))['code'] === 409 && $store->pendingBySession($b['sid'])['clientn_id'] === 'CN-ABCDEFGHIJKL');

// --- expiry
[$app, $store, $api] = boot(); $b = begin($app, $api); age($store, $b['sid'], 1000);
t('expired: late callback refused, status expired', cb($app, ev($b['sid']))['code'] === 422 && status($app, $b['tok'])[1] === 'expired');

// --- recovery
[$app, $store, $api] = boot(); $b = begin($app, $api);
$api->getter = function (string $id) { $raw = ev($id); return ['status' => 200, 'body' => ['status' => 'confirmed', 'result_raw' => $raw, 'signature' => sign($raw)]]; };
t('recovery: too early -> still pending', status($app, $b['tok'])[1] === 'pending');
age($store, $b['sid'], 20);
t('recovery: lost callback healed from ClientN (verified over exact bytes)', status($app, $b['tok'])[1] === 'confirmed');
[$app, $store, $api] = boot(); $b = begin($app, $api);
$api->getter = fn(string $id) => ['status' => 200, 'body' => ['status' => 'confirmed', 'result_raw' => ev($id), 'signature' => str_repeat('0', 64)]];
age($store, $b['sid'], 20);
t('recovery: forged result ignored', status($app, $b['tok'])[1] === 'pending');

// --- logout + headers
[$app, $store, $api] = boot(); $b = begin($app, $api); cb($app, ev($b['sid'])); [$r] = status($app, $b['tok']); $sess = cookieVal($r, 'app_session');
t('logout: cross-site refused', $app->handle(req('POST', '/logout', ['cookies' => ['app_session' => $sess], 'headers' => ['origin' => 'https://evil.example']]))['code'] === 403);
$app->handle(req('POST', '/logout', ['cookies' => ['app_session' => $sess], 'headers' => ['origin' => $ORIGIN]]));
t('logout: session ended', str_contains($app->handle(req('GET', '/', ['cookies' => ['app_session' => $sess]]))['body'], 'clientn-signin'));
$h = $app->handle(req('GET', '/'))['headers'];
t('pages send CSP + nosniff + frame protection', str_contains($h['Content-Security-Policy'], "frame-ancestors 'none'") && $h['X-Content-Type-Options'] === 'nosniff');

echo "\n$pass passed, $fail failed\n";
if ($fail) { exit(1); }
echo "\n--- verifier unit tests ---\n";
require __DIR__ . '/verify_test.php';
