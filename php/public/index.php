<?php
declare(strict_types=1);
require __DIR__ . '/../src/App.php';

$apiKey = getenv('CLIENTN_API_KEY') ?: ''; $secret = getenv('CLIENTN_API_SECRET') ?: '';
if (!preg_match('/\A[a-f0-9]{32}\z/', $apiKey) || strlen($secret) < 32) { http_response_code(500); exit('Set CLIENTN_API_KEY and CLIENTN_API_SECRET (see .env.example)'); }
$origin = rtrim(getenv('APP_ORIGIN') ?: 'http://localhost:3000', '/');
$base = rtrim(getenv('CLIENTN_API_BASE') ?: 'https://clientn.com', '/');
$cfg = ['apiBase' => $base, 'apiKey' => $apiKey, 'apiSecret' => $secret, 'appOrigin' => $origin, 'secureCookies' => str_starts_with($origin, 'https://')];

$headers = [];
foreach ($_SERVER as $k => $v) { if (str_starts_with($k, 'HTTP_')) { $headers[strtolower(str_replace('_', '-', substr($k, 5)))] = $v; } }
$app = new App($cfg, new Store(getenv('DB_PATH') ?: __DIR__ . '/../data/app.sqlite'), new ClientN($base, $apiKey));
$res = $app->handle([
    'method' => $_SERVER['REQUEST_METHOD'], 'path' => parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/',
    'headers' => $headers, 'cookies' => $_COOKIE, 'body' => file_get_contents('php://input', false, null, 0, 16385) ?: '', 'ip' => $_SERVER['REMOTE_ADDR'] ?? '?',
]);
http_response_code($res['code']);
foreach ($res['headers'] as $k => $v) { header("$k: $v"); }
foreach ($res['cookies'] as $c) { header('Set-Cookie: ' . $c, false); }
echo $res['body'];
