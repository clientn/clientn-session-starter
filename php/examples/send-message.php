<?php
declare(strict_types=1);
// Send a private message to a paid ClientN member who signed in to your site.
// Usage: CLIENTN_API_KEY=... CLIENTN_API_SECRET=... CLIENTN_RECIPIENT=CN-XXXXXXXXXXXX php examples/send-message.php
function clientn_send_message(string $apiKey, string $apiSecret, string $clientnId, string $subject, string $text,
                              string $idempotencyKey, string $category = 'service', string $apiBase = 'https://clientn.com'): array
{
    $body = json_encode([
        'recipient' => $clientnId,            // the CN- id you received in the login callback for THIS site
        'category' => $category,              // 'service' (about their account with you) or 'updates' (opt-in by the person)
        'subject' => $subject, 'text' => $text,
        'idempotency_key' => $idempotencyKey, // reuse the same key when you retry: never sends twice
        'ts' => time(),
    ], JSON_UNESCAPED_UNICODE);
    $signature = hash_hmac('sha256', $body, $apiSecret);   // sign the exact bytes you send
    $ch = curl_init($apiBase . '/api/v1/messages');
    curl_setopt_array($ch, [
        CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $apiKey, 'X-ClientN-Signature: ' . $signature, 'Content-Type: application/json'],
    ]);
    $out = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return [$status, json_decode((string)$out, true)];
}

/** 202 accepted does NOT mean delivered. 'not_delivered' covers blocked, not a paying member, no consent: ClientN never says which. */
function clientn_message_status(string $apiKey, string $id, string $apiBase = 'https://clientn.com'): ?array
{
    $ch = curl_init($apiBase . '/api/v1/messages/' . rawurlencode($id));
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => false, CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $apiKey]]);
    $out = curl_exec($ch); curl_close($ch);
    return json_decode((string)$out, true);
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    [$status, $json] = clientn_send_message(getenv('CLIENTN_API_KEY'), getenv('CLIENTN_API_SECRET'), getenv('CLIENTN_RECIPIENT'),
        'Your order has shipped', 'Order 1042 is on its way.', 'order-1042-shipped');
    echo $status, ' ', json_encode($json), "\n";
}
