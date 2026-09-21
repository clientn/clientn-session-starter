import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Verify a ClientN callback against a SERVER-STORED pending login.
 * Does NOT consume the pending login, stop a valid replay, or log a browser in.
 * The caller must do that atomically and bind the pending login to its browser.
 * Current ClientN signature: HMAC-SHA256 over exact raw bytes, 64 hex characters.
 */
export function verifyClientNCallback(rawBody, signature, secret, pending, now = Math.floor(Date.now() / 1000)) {
  const reject = () => { throw new Error('Invalid ClientN callback'); };
  if (!Buffer.isBuffer(rawBody) || rawBody.length === 0 || rawBody.length > 16384) reject();
  if (typeof secret !== 'string' || secret.length < 32) reject();
  if (typeof signature !== 'string' || !/^[a-fA-F0-9]{64}$/.test(signature)) reject();
  if (!pending || typeof pending.sessionId !== 'string' ||
      !Number.isSafeInteger(pending.createdAt) || !Number.isSafeInteger(pending.expiresAt) ||
      pending.expiresAt <= pending.createdAt || pending.expiresAt - pending.createdAt > 300 ||
      !Number.isSafeInteger(now)) reject();

  const expected = createHmac('sha256', secret).update(rawBody).digest();
  if (!timingSafeEqual(expected, Buffer.from(signature, 'hex'))) reject();

  let body;
  try { body = JSON.parse(rawBody.toString('utf8')); } catch { reject(); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) reject();
  if (body.session_id !== pending.sessionId ||
      typeof body.clientn_id !== 'string' || !/^CN-[A-Z2-7]{12}$/.test(body.clientn_id) ||
      typeof body.verified_human !== 'boolean' || !Number.isSafeInteger(body.ts) ||
      (body.verified_until !== null && typeof body.verified_until !== 'string')) reject();

  // 30s clock/delivery tolerance; pending state is a five-minute one-time window.
  if (body.ts > now + 30 || body.ts < now - 300 ||
      body.ts < pending.createdAt - 30 || body.ts > pending.expiresAt ||
      now < pending.createdAt - 30 || now > pending.expiresAt + 30) reject();

  return Object.freeze({
    sessionId: body.session_id,
    clientnId: body.clientn_id,
    verifiedHuman: body.verified_human,
    verifiedUntil: body.verified_until,
    issuedAt: body.ts,
  });
}
