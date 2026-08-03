---
title: Gatery — Elysia 1.4.18 signed-cookie verification bypass → forged session
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Gatery
app: Gatery
category: web
difficulty: very easy
type: writeup
status: complete
mitre:
  - T1190
  - T1606.001
  - T1550.004
tags:
  - writeup
  - HTB
  - Web_App_Security
  - Security
  - auth-bypass
  - session-forgery
  - cookie-signing
related:
  - "[[HTB]]"
aliases:
  - Gatery
  - CA2026 Gatery
created: 2026-07-24T17:54:39.949Z
updated: 2026-07-24T17:57:35.068Z
---

# Gatery — Elysia Signed-Cookie Verification Bypass

> [!success] Scope
> Authorized HTB event challenge, Cyber Apocalypse CTF 2026. Bun + Elysia API behind nginx, React/Canvas front end. Ephemeral instance `154.57.164.77:32689`. Solved 2026-07-24.

**Flag:** `HTB{w3lc0me_b3y0nd_th3_g4t3_3d3e42cf2f9faba65314e74f4079876c}`

---

## 1. Where the bug is not

The challenge logic is sound. `app/index.ts` gates three states on one signed cookie:

| Endpoint | Requires |
|---|---|
| `POST /api/gate/open` | `session.value` ∈ {`admin`, `inside`} |
| `POST /api/gate/enter` | same, then sets `session = inside` |
| `POST /api/flag` | `session.value === 'inside'` |

`/api/login` is unattackable: the only DB user is `admin`, seeded with `randomBytes(24).toString('base64url')` at bcrypt cost 12, and there is no registration endpoint. `nginx.conf` is a plain SPA + `/api/` reverse proxy with no access control of its own. The entire React client is decoration — every gate is server-side.

## 2. The actual defect — upstream, in Elysia

The server pins `elysia@1.4.18` exactly and configures cookie signing with an **array**:

```ts
new Elysia({ cookie: { secrets: [sessionSecret], sign: [sessionCookie] } })
```

`secrets` being an array selects a different branch of `parseCookie` than a string does. From `elysia@1.4.18/dist/cookies.mjs`:

```js
} else {
  let decoded = !0;                              // ← initialised TRUE
  for (let i = 0; i < secrets.length; i++) {
    const temp = await unsignCookie(value, secrets[i]);
    if (temp !== !1) { decoded = !0, value = temp; break; }
  }
  if (!decoded) throw new InvalidCookieSignature(name);   // ← unreachable
}
```

`decoded` starts `true` and is only ever reassigned `true`. When no secret validates the signature the loop simply falls through, `!decoded` is false, nothing throws — and `value` is still the **raw attacker-supplied string**. The string-secret branch immediately above is correct (`if (temp === false) throw`). Only the array branch is broken.

`unsignCookie('inside', secret)` fails *quietly* rather than throwing: with no `.` in the input, `lastIndexOf` returns -1, `slice(0, -1)` yields `insid`, the re-signed value doesn't match, and it returns `false`. There is no error path left to catch the failure.

## 3. Verification before exploitation

Ran the real `parseCookie` out of the pinned package against three cases:

```
ARRAY  secrets, forged cookie -> session.value = "inside"
STRING secrets, forged cookie -> THREW InvalidCookieSignature
ARRAY  secrets, valid cookie  -> session.value = "admin"
```

Legitimate signed sessions still work, which is why the flaw is invisible in normal use.

## 4. Exploit

`/api/flag` only checks the string. No login, no `/api/gate/enter` — one request:

```bash
curl -si -X POST http://154.57.164.77:32689/api/flag \
  -H 'content-type: application/json' \
  -H 'Cookie: session=inside' -d '{}'
```

Send the value bare. A quoted `"inside"` fails the `!==` comparison, and anything wrapped in `{}` or `[]` is JSON-parsed by the block above the signature check and won't match either.

---

## Tools & techniques
`npm pack` (pulling the pinned dependency to read shipped source) · Node ESM harness against the library's own `parseCookie` · curl
Concepts: signed-cookie forgery · authentication bypass via dependency defect · inverted-sentinel logic error

## MITRE ATT&CK
- **T1190** Exploit Public-Facing Application
- **T1606.001** Forge Web Credentials: Web Cookies
- **T1550.004** Use Alternate Authentication Material: Web Session Cookie

## Detection / blue-team & fix notes
- **Fix (app-side):** pass `secrets` as a string rather than a single-element array — that routes to the correct branch. Upgrading Elysia past 1.4.18 is the durable fix. *(Inference from the code paths; not confirmed against upstream release notes.)*
- **Fix (design):** a session value that is a bare role string (`admin` / `inside`) means signature verification is the *only* control. An opaque random session ID resolved server-side would have survived this bug entirely.
- **Detection:** requests bearing a session cookie with no signature suffix, or a session value that is a human-readable role name, are the signature. Sudden privileged access with no preceding successful `/api/login` is the behavioural tell.

## Blind alleys (recorded to save the next reader)
- `/api/login` — bcryptjs 2.4.3 with a `randomBytes(24)` password. Not attackable; the work factor and the decoy `role !== 'admin'` check are misdirection.
- `nginx.conf` path/proxy confusion — `location /api/` with a bare `proxy_pass` origin passes the URI through unchanged. Nothing there.
- Client-side gate logic in `App.jsx` — the canvas collision checks, gate lane, and NPC proximity are all cosmetic; the server never trusts them.
- No SQLi: `findUser` is a parameterised `bun:sqlite` prepared statement.

## Gotchas
- The bug is **branch-specific**. Reading Elysia's signature code casually suggests it's safe — the correct `throw` is right there, four lines above the broken copy. Read the branch the app actually takes.
- Pinned exact dependency versions in `package.json` (`"elysia": "1.4.18"`, no caret) are a signal that the version itself is the challenge.

## Cross-references
- [[HTB]]

## Change Log
- 2026-07-24 — Initial write-up. Source excerpt, PoC output, and exploit request preserved from the live analysis.
- 2026-07-24 — Flag confirmed against the live instance (HTTP 200, `{"ok":true,...}`) and written in. Placeholder removed.
