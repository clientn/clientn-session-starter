# ClientN session starter

Working "Sign in with ClientN" integrations for **Node.js** and **PHP**, with tests. Copy one of them, put in your keys, and adapt the storage to your own app.

ClientN gives your visitors an anonymous, per-site ID (`CN-…`) after they confirm with a passkey on clientn.com. No app, no password, no email address reaches you. Docs: <https://clientn.com/docs> · Live demo: <https://clientn.com/demo> · API description: [`openapi.yaml`](openapi.yaml)

> This is a reference integration, not an SDK. Signing someone in needs **server-side work in your app** (create a session, receive a signed callback, log the right browser in). These two apps show a complete, tested way to do it. They are small on purpose: read them.

> The older repository `clientn/clientn-anonymous-id` is a different, offline library (local key derivation). It is not the hosted product described here.

## How it works

Every approval needs a fresh passkey check on clientn.com (fingerprint, face or device PIN), tied to that one request. Two flows, both in these apps:

**Same-device sign-in (default, recommended)**
1. The button POSTs `{"flow":"redirect"}` to your `/clientn/session`. Your server makes a random `code_verifier`, keeps it **server-side, bound to this browser's pending cookie**, and calls `POST /api/v1/sessions` with `flow`, `return_url` and `code_challenge = base64url(SHA-256(verifier))`.
2. The browser goes to ClientN, the person confirms with their passkey, and ClientN sends the browser back to `/clientn/return?cn_session=…&cn_code=…`.
3. Your server claims the pending row for **this** browser once, calls `POST /api/v1/sessions/{id}/exchange` with the code and verifier, verifies the signature over `result_raw`, and starts a fresh app session. A forwarded confirm link signs nobody in: the code lands in the approver's browser, and only the starting browser has the verifier.

**QR sign-in (a phone confirms for a computer)** — the "Use my phone instead" link
1. Your server calls `POST /api/v1/sessions` with `flow: "qr"` plus `end_user_ip` / `end_user_agent`, stores a pending login bound to this browser, and returns the QR + code.
2. On the phone the person sees "Chrome on Windows · Egypt" (with a warning when countries differ), picks the code shown on your page out of three (one wrong pick cancels), and confirms with their passkey.
3. ClientN POSTs a **signed callback**. You verify the exact raw bytes, check it belongs to a pending login you started, and mark it confirmed in one atomic step.
4. The browser that holds the pending cookie polls **your** `/clientn/status`, consumes the pending login once, and gets a **fresh** session id.

## Run it

You need a site registered on <https://clientn.com/dev> and its **domain verified** (a DNS TXT record or a file under `/.well-known/`; the page shows the exact values). Sessions are refused until then.

ClientN calls your callback over HTTPS on port 443, on your verified domain or a subdomain, resolved to a public address. Redirects are not followed. So run the app on a real HTTPS host, for example a staging subdomain such as `staging.example.com`, and register `https://staging.example.com/clientn/callback`.

```sh
# Node 22.5+ (uses the built-in node:sqlite; no dependencies)
cd node && cp .env.example .env    # fill in your key and secret
npm start
npm test

# PHP 8.1+ with pdo_sqlite and curl
cd php && export CLIENTN_API_KEY=... CLIENTN_API_SECRET=... APP_ORIGIN=https://staging.example.com
php -S 127.0.0.1:3000 -t public public/index.php     # put a real HTTPS web server or proxy in front
php tests/run.php
```

## What the tests prove

Both apps are tested against the same list: cross-site start is refused (login CSRF); the API key never reaches the browser; bad, missing, tampered and oversized callbacks are refused; unknown, stale and wrongly typed events are refused; another browser cannot take over a login even if it knows the session id; a login is consumed exactly once (five parallel polls create one session); the same event twice has no second effect; a conflicting identity never replaces the first; expired logins are refused; a lost callback is recovered from ClientN and a forged recovery answer is ignored; logout is same-origin only; security headers are sent.

## Things to know

- **Status semantics.** ClientN's public status (`pending`, `confirmed`, `expired`) only says the person approved with a passkey. Your app is logged in only after *your server* accepted the signed callback. That is why `clientn.js` polls your `data-status-endpoint`, not ClientN.
- **Callback retries.** ClientN tries 3 times, 5 seconds each. Answer 2xx as soon as the event is recorded. A repeat of the same event should also get 2xx and have no second effect.
- **Keys.** One key and secret per site. There are **no scopes** yet: a key can start sessions, read your own sessions, redeliver, and send messages for that one site. **Rotate** on <https://clientn.com/dev> ("Rotate API key + secret"): the old pair stops working at once, and sign-ins in progress must be restarted. Store keys in your secret store, never in the repository.
- **`verified_human`.** An authenticated claim from ClientN, not by itself proof that two accounts are different people. Do not let it override your own authorization rules.
- **Identity.** `clientn_id` is stable for one person on your site and different on every other site.
- **Shared limits.** These apps keep their tiny rate limiter in memory. Use your real shared limiter in production.

## Private messages (paid members)

A member who signed in to your site can receive private messages from you through ClientN, without you ever seeing their email address. See [`node/examples/send-message.mjs`](node/examples/send-message.mjs) and [`php/examples/send-message.php`](php/examples/send-message.php).

- Requests are signed: header `X-ClientN-Signature` = hex HMAC-SHA256(secret, the exact body you send), plus a fresh `ts` and a unique `idempotency_key`.
- `202 accepted` says nothing about delivery. Ask `GET /api/v1/messages/{id}` later: `delivered`, `queued` or `not_delivered`.
- **Blocking.** The member can block your site at any time in their ClientN inbox. After that, your sends still return `202`, and the status becomes `not_delivered`. ClientN never tells you why (blocked, not a paying member, or no consent look identical), so nobody can be probed.
- Categories: `service` (about their account with you) and `updates` (only after the member opts in).

## Continuous integration

[`ci/github-actions.yml`](ci/github-actions.yml) runs both test suites (Node 22, PHP 8.2). Copy it to `.github/workflows/ci.yml` in your own fork or project.

## License

MIT, see [`LICENSE`](LICENSE).
