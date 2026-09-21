import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { verifyClientNCallback as verify } from '../src/verify.mjs';
import { secret, now, pending, payload } from './fixtures.mjs';
const sign = raw => createHmac('sha256', secret).update(raw).digest('hex');
const raw = Buffer.from(JSON.stringify(payload));
const check = body => { const bytes = Buffer.from(JSON.stringify(body)); return verify(bytes, sign(bytes), secret, pending, now); };

test('accepts authentic current payload', () => assert.equal(check(payload).clientnId, payload.clientn_id));
test('accepts uppercase hex signature', () => assert.equal(verify(raw, sign(raw).toUpperCase(), secret, pending, now).verifiedHuman, false));
test('rejects altered body bytes', () => assert.throws(() => verify(Buffer.concat([raw, Buffer.from(' ')]), sign(raw), secret, pending, now)));
test('rejects wrong-site secret', () => assert.throws(() => verify(raw, sign(raw), secret + '_other_site', pending, now)));
test('rejects malformed signature', () => assert.throws(() => verify(raw, 'z'.repeat(64), secret, pending, now)));
test('rejects another pending session', () => assert.throws(() => check({ ...payload, session_id: 'other-session' })));
test('rejects old timestamp', () => assert.throws(() => check({ ...payload, ts: now - 301 })));
test('rejects future timestamp', () => assert.throws(() => check({ ...payload, ts: now + 31 })));
test('rejects expired pending login', () => assert.throws(() => verify(raw, sign(raw), secret, pending, pending.expiresAt + 31)));
test('rejects invalid identity format', () => assert.throws(() => check({ ...payload, clientn_id: 'attacker@example.test' })));
test('rejects string instead of boolean', () => assert.throws(() => check({ ...payload, verified_human: 'true' })));
test('rejects validly signed malformed JSON', () => { const b = Buffer.from('{'); assert.throws(() => verify(b, sign(b), secret, pending, now)); });
test('rejects oversized payload', () => { const b = Buffer.alloc(16385, 32); assert.throws(() => verify(b, sign(b), secret, pending, now)); });
test('rejects missing expiry claim', () => { const p = { ...payload }; delete p.verified_until; assert.throws(() => check(p)); });
test('does not pretend verification alone prevents replay', () => {
  // Both pass cryptography: APPLICATION storage must atomically accept only once.
  assert.deepEqual(check(payload), check(payload));
});
