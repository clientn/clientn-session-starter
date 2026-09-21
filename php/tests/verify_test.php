<?php
declare(strict_types=1);
require_once __DIR__ . '/../src/Verify.php';
$secret = 'cnsk_TEST_ONLY_0123456789abcdef0123456789abcdef01234567';
$now = 1800000100;
$pending = ['sessionId'=>'11111111-1111-4111-8111-111111111111','createdAt'=>$now-100,'expiresAt'=>$now+200];
$payload = ['session_id'=>$pending['sessionId'],'clientn_id'=>'CN-ABCDEFGHIJKL','verified_human'=>false,'verified_until'=>null,'match_code'=>'123456','ts'=>$now];
$raw = json_encode($payload, JSON_THROW_ON_ERROR);
$sign = static fn(string $b): string => hash_hmac('sha256', $b, $secret);
$check = static function (array $p) use ($secret, $now, $pending, $sign): array {
    $b = json_encode($p, JSON_THROW_ON_ERROR);
    return verifyClientNCallback($b, $sign($b), $secret, $pending, $now);
};
$count = 0;
function ok(string $name, callable $fn, bool $reject = false): void {
    global $count;
    try { $result = $fn(); }
    catch (InvalidArgumentException $e) {
        if ($reject) { ++$count; echo "PASS $name\n"; return; }
        throw $e;
    }
    if ($reject || $result === false) { throw new RuntimeException("FAIL $name"); }
    ++$count; echo "PASS $name\n";
}
ok('authentic payload', fn() => $check($payload)['clientnId'] === $payload['clientn_id']);
ok('uppercase signature', fn() => verifyClientNCallback($raw, strtoupper($sign($raw)), $secret, $pending, $now));
ok('altered body', fn() => verifyClientNCallback($raw.' ', $sign($raw), $secret, $pending, $now), true);
ok('wrong site secret', fn() => verifyClientNCallback($raw, $sign($raw), $secret.'_other_site', $pending, $now), true);
ok('malformed signature', fn() => verifyClientNCallback($raw, str_repeat('z',64), $secret, $pending, $now), true);
ok('wrong session', fn() => $check(array_replace($payload,['session_id'=>'other-session'])), true);
ok('old timestamp', fn() => $check(array_replace($payload,['ts'=>$now-301])), true);
ok('future timestamp', fn() => $check(array_replace($payload,['ts'=>$now+31])), true);
ok('expired pending', fn() => verifyClientNCallback($raw,$sign($raw),$secret,$pending,$pending['expiresAt']+31), true);
ok('invalid identity', fn() => $check(array_replace($payload,['clientn_id'=>'attacker@example.test'])), true);
ok('string boolean', fn() => $check(array_replace($payload,['verified_human'=>'true'])), true);
ok('malformed JSON', fn() => verifyClientNCallback('{',$sign('{'),$secret,$pending,$now), true);
ok('oversized payload', fn() => verifyClientNCallback(str_repeat(' ',16385),$sign(str_repeat(' ',16385)),$secret,$pending,$now), true);
$missing = $payload; unset($missing['verified_until']);
ok('missing expiry', fn() => $check($missing), true);
ok('replay still needs atomic application storage', fn() => $check($payload) === $check($payload));
echo "$count tests passed\n";
