<?php
declare(strict_types=1);

/** Verify only. Caller MUST atomically consume server-held state bound to its browser. */
function verifyClientNCallback(string $rawBody, string $signature, string $secret, array $pending, ?int $now = null): array
{
    $reject = static function (): never { throw new InvalidArgumentException('Invalid ClientN callback'); };
    $now ??= time();
    if (strlen($rawBody) === 0 || strlen($rawBody) > 16384 || strlen($secret) < 32 ||
        !preg_match('/\A[a-fA-F0-9]{64}\z/', $signature)) { $reject(); }
    if (!is_string($pending['sessionId'] ?? null) || !is_int($pending['createdAt'] ?? null) ||
        !is_int($pending['expiresAt'] ?? null) || $pending['expiresAt'] <= $pending['createdAt'] ||
        $pending['expiresAt'] - $pending['createdAt'] > 300) { $reject(); }

    $expected = hash_hmac('sha256', $rawBody, $secret);
    if (!hash_equals($expected, strtolower($signature))) { $reject(); }
    try { $body = json_decode($rawBody, false, 32, JSON_THROW_ON_ERROR); }
    catch (JsonException) { $reject(); }
    if (!($body instanceof stdClass) || ($body->session_id ?? null) !== $pending['sessionId'] ||
        !is_string($body->clientn_id ?? null) || !preg_match('/\ACN-[A-Z2-7]{12}\z/', $body->clientn_id) ||
        !is_bool($body->verified_human ?? null) || !is_int($body->ts ?? null) ||
        !property_exists($body, 'verified_until') ||
        ($body->verified_until !== null && !is_string($body->verified_until))) { $reject(); }

    if ($body->ts > $now + 30 || $body->ts < $now - 300 ||
        $body->ts < $pending['createdAt'] - 30 || $body->ts > $pending['expiresAt'] ||
        $now < $pending['createdAt'] - 30 || $now > $pending['expiresAt'] + 30) { $reject(); }

    return [
        'sessionId' => $body->session_id,
        'clientnId' => $body->clientn_id,
        'verifiedHuman' => $body->verified_human,
        'verifiedUntil' => $body->verified_until,
        'issuedAt' => $body->ts,
    ];
}
