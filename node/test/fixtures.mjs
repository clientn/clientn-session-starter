// Deliberately synthetic; this is not a production secret, identity or session.
export const secret = 'cnsk_TEST_ONLY_0123456789abcdef0123456789abcdef01234567';
export const now = 1800000100;
export const pending = Object.freeze({ sessionId: '11111111-1111-4111-8111-111111111111', createdAt: now - 100, expiresAt: now + 200 });
export const payload = Object.freeze({ session_id: pending.sessionId, clientn_id: 'CN-ABCDEFGHIJKL', verified_human: false, verified_until: null, match_code: '123456', ts: now });
