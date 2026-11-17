---
title: "Provisioneds — PHP object injection in Joomla plugin (partial: sink proven, gadget open)"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Provisioneds
app: "Eastreach Provision Office"
category: web
difficulty: very easy
type: writeup
status: closed
mitre:
  - T1190
  - T1059.004
tags:
  - writeup
  - HTB
  - Web_App_Security
  - Security
  - deserialization
  - php-object-injection
related: []
aliases:
  - Provisioneds
  - CA2026 Provisioneds
created: 2026-07-24T19:12:52.397Z
updated: 2026-07-30T03:03:07.309Z
---

# Provisioneds — PHP Object Injection (Partial)

> [!warning] Status: UNSOLVED at time of writing
> The vulnerability, its sink, and pre-auth reachability are **proven against the live target**. A working gadget chain to RCE was **not** found before the session ended. This note records the confirmed facts, the eliminated dead ends (so they are not re-walked), and the single open read that decides the leading candidate. Resume from §7.

> [!info] Scope
> Authorized HTB event challenge, Cyber Apocalypse CTF 2026. Joomla 6.1.2 (confirmed live via `/administrator/manifests/files/joomla.xml`) + a custom `plg_system_gatehouse` system plugin, behind Apache, MariaDB on localhost. SUID `/readflag` reads `/root/flag.txt` (mode 600). Win condition is command execution, then run `/readflag`. Ephemeral instances: `154.57.164.77:32689`, later `154.57.164.78:30961`.

---

## 1. The vulnerability — pre-auth PHP object injection

`plugin/src/Extension/Gatehouse.php`, `onAfterRoute`, feeds a raw request parameter straight to `unserialize`:

```php
$ledger = $app->getInput()->getRaw('ledger', '');
// ...
(new GatehouseRepository())->importMonthlyLedger($ledger);
```

`GatehouseRepository::importMonthlyLedger`:

```php
$data = @unserialize($ledger);   // ← sink, no filter
if (!is_array($data)) { return ...; }
return $this->importMonthlyRecords($data);
```

Unfiltered `unserialize` on attacker input. Classic PHP object injection.

## 2. Reachability — pre-authentication (the non-obvious part)

The trigger requires the **administrator** application:

```
POST /administrator/index.php?option=com_provision&view=dispatch&task=ledger.import
     body: ledger=<serialized payload>
```

`isAdminImportContext` gates on `isClient('administrator')` + `option=com_provision` + `view=dispatch` + `task=ledger.import`.

Verified against Joomla 6.1.2's `AdministratorApplication` source: `doExecute()` runs `route()` **then** `dispatch()`. `route()` fires `onAfterRoute` — where the plugin's `unserialize` lives. The guest login gate is in `findOption()`, called from `dispatch()`, i.e. **after** `onAfterRoute`. So deserialization happens, then Joomla decides you're unauthenticated and serves the login page.

> [!important] The response is always a login page — even on success. Do not read that as failure. Judge by side effects, not response body.

## 3. The reachability oracle (proven on live target)

`importMonthlyRecords` → `normalizeMonthlyGoods` → `saveMonthlyGoods` writes accepted records to `/var/www/html/tmp/provision-monthly-goods.json`, which the **public board at `/`** then renders (Months listed / Packages received). This is a free, unauthenticated confirmation channel — no gadget required.

```bash
curl -si 'http://<host>/administrator/index.php?option=com_provision&view=dispatch&task=ledger.import' \
  --data-urlencode 'ledger=a:1:{i:0;a:2:{s:5:"month";s:10:"PWNED-2026";s:8:"packages";i:31337;}}'
curl -s http://<host>/ | grep -oE 'Packages received</span><strong>[0-9]+'
```

Confirmed live: board changed to `Months listed: 1`, `Packages received: 31337`. This proves, in one request: pre-auth reach, all four input checks pass, `unserialize` ran and returned an array, and the `tmp/` write path works. (Default board is `9` / `19890` — sum of the hardcoded `DEFAULT_MONTHS`. Seeing that means no import has landed / instance is fresh.)

## 4. Win condition

`readflag.c`:

```c
setuid(0); system("/bin/cat /root/flag.txt");
```

SUID root, no args, no PoW. Once code runs as `www-data`, `/readflag` prints the flag. No file-read primitive suffices (flag is mode 600); need command execution or a planted-`.php` include.

## 5. Confirmed sink, confirmed no direct chain

The only arbitrary-callable sink in the loaded class set is `call_user_func($controlled, ...)` in **PHPMailer/SMTP `edebug()`**. It is real but **unreachable** — every path to it is gated on a live socket resource, which nulls on unserialize.

Full magic-method audit performed (`__destruct`, `__wakeup`, invocation-bearing `__toString`) across `libraries/vendor` **and** `libraries/src`. Result: **no classic POP→RCE chain found.** Every candidate is guarded, resource-gated, or inert.

## 6. Eliminated — do not re-walk

| Candidate | Why it's dead |
|---|---|
| `guzzlehttp/psr7` `FnStream::__destruct` | `__wakeup` guard throws `LogicException` on unserialize. Verified: `class_exists`=true, unserialize throws. PHPGGC `Guzzle/FW1` builds through FnStream and predates the guard → generates a payload that silently no-ops. |
| Monolog (`RCE1-9`) | **Not installed.** `class_exists("Monolog\Handler\BufferHandler")` = false. Only a php-debugbar bridge file references the namespace. |
| PHPMailer `__destruct` → `smtpClose` → SMTP `close` | Both gated on `is_resource($smtp_conn)` — nulls on unserialize, branch skipped, `edebug` never reached. |
| `joomla/filesystem` `Stream::__destruct` | Gated on `$this->fh` (resource). Inert. |
| `Joomla\CMS Image::__destruct` | `destroy()` on a GD handle (resource). Inert. |
| `SyslogLogger::__destruct` | Bare `closelog()`. No sink. |
| `User::__wakeup` | Sets Registry + `load($id)` (a DB getter). No callable/write/eval. |
| `symfony/error-handler BufferingLogger::__destruct` | Only `error_log()`. No controlled sink. |
| PHPSecLib / Symfony / Doctrine / Zend PHPGGC chains | All version-mismatched (installed versions post-date every catalogued range). |
| `symfony/http-client TraceableResponse::__destruct` | Forwards `$this->response->__destruct()` — an unguarded trampoline — but no reachable sink was found on the far side. |

**Two recurring mistakes to avoid (author's own, this session):**
1. **Manifest ≠ vendor.** `composer.json`'s `require` block omits transitive deps. Guzzle psr7 and (the absence of) Monolog were both mis-called from the manifest. Ground truth is `class_exists()` inside the container or the `installed.json` list.
2. **Read the gate before claiming reachability.** Four destructors were pursued before checking they were resource-gated. Filter first: a destructor/wakeup is only a candidate if it has no `is_resource` gate and no throwing `__wakeup`.

## 7. Leading open candidate — `__toString` via the import normalizer

`normalizeMonthlyGoods` → `clean()` does `(string)` casts on nested entry fields (`month`, `label`, `summary`, item fields). A string-cast on an **object** embedded in the `ledger` array (which passes `is_array`) fires `__toString`. This is a second trigger, independent of the destructor space.

Candidate chain (Joomla core):

```
clean() casts a nested value to string
  → Joomla\CMS\Button\ActionButton::__toString()
    → render() → LayoutHelper::render($this->layout, $data)
      → new FileLayout($this->layout, $this->basePath)
        → getPath(): $rawPath = str_replace('.', '/', $layoutId) . '.php'
                     Path::find($includePaths, $rawPath)
        → include $path;    // FileLayout.php:128  (ob_start; include; ob_get_clean → returned as the string)
```

Verified from 6.1.2 release-package source:
- `ActionButton::render()` **is reachable** from `__toString` — `layout` is settable, state/options have defaults, won't fatal first.
- The include site is `ob_start(); include $path;` — output is captured and returned, so even a **read** works if code-exec doesn't.

**The constraint that decides it** — `Path::find` (verified):

```php
$path = realpath($path); $fullname = realpath($fullname);
if (file_exists($fullname) && substr($fullname, 0, strlen($path)) == $path) return $fullname;
```

- File **must already exist** → this is LFI (include-existing), not code-drop-and-run in one shot. Two-stage: plant a `.php`, then include it.
- `realpath` + prefix check blocks `layoutId` traversal. But **`basePath` is attacker-controlled** (flows from the serialized `ActionButton` property into `$includePaths`) and is **not** clamped to `JPATH_ROOT` in the code read so far.
- Extension mismatch problem: `getPath` forces `.php` and `str_replace('.','/')` mangles dots, so `layoutId` cannot name the `.json` file `saveMonthlyGoods` writes. A planted file must be `.php`-named at a `basePath`-reachable dir.

## 8. THE single resume step

One command decides whether §7 is live or dead:

```bash
sed -n '/function getDefaultIncludePaths/,/^    }/p' \
  <joomla-6.1.2>/libraries/src/Layout/FileLayout.php
```

- If `basePath` seeds `$includePaths` **without** a `JPATH_ROOT` clamp → point it at any dir where a `.php` can be planted → chain is live → build the `ActionButton` object graph (in PHP via `serialize()`, never hand-typed), embed in the `ledger` array, fire at the live target, read `/` as the oracle.
- If include paths are clamped to `JPATH_*` and `basePath` is neutered → this lead is **dead**, and the intended gadget is elsewhere (unfound).

> [!note] No Docker required to finish. Every decisive read came from the official 6.1.2 full-package zip (`downloads.joomla.org/.../Joomla_6-1-2-Stable-Full_Package.zip`), not the container. The container only offered live PHP stack traces; this target's public board is a reflection oracle that replaces them. Final exploit path is `curl` + a PHP `serialize()` one-liner against the live host.

---

## Tools & techniques
`unserialize` object injection · Joomla admin-app routing analysis (onAfterRoute pre-auth) · reachability oracle via reflected stored state · PHPGGC (no applicable chain) · full magic-method gadget audit with resource-gate/`__wakeup` filtering · `class_exists` ground-truth verification · Joomla `FileLayout` LFI via `include`

## MITRE ATT&CK
- **T1190** Exploit Public-Facing Application (unauth deserialization endpoint)
- **T1059.004** Command and Scripting Interpreter: Unix Shell (intended terminal: `/readflag`)

## Detection / blue-team & fix notes
- **Fix (primary):** never `unserialize()` request input. Use `json_decode` for a data-import endpoint, or an allow-listed typed decoder. The plugin already normalizes to a plain structure afterward — there is no reason for `unserialize` here.
- **Fix (defense-in-depth):** the admin-app `onAfterRoute` running attacker-reachable code before the auth gate is the reachability root cause; privileged plugin logic should re-check identity, not assume the dispatch gate protects it.
- **Detection:** POST to `/administrator/index.php` carrying `task=ledger.import` from an unauthenticated session; serialized-object bytes (`O:`/`a:`) in a request parameter; unexpected writes to `tmp/*.json` followed by board content change.

## Open items / resume checklist
- [ ] Run §8 `getDefaultIncludePaths` read → decide `ActionButton`/`FileLayout` chain live-or-dead.
- [ ] If live: identify a writable dir accepting a `.php`-named plant (revisit `saveMonthlyGoods` filename control; check Joomla cache/log dirs).
- [ ] If live: build `ActionButton` object graph via `serialize()`, embed in `ledger` array, fire, read `/`.
- [ ] If dead: widen `__toString` audit to remaining CBOR / phpseclib / Registry classes for a callable/write reachable from a string cast.
- [ ] Flag once obtained; promote `status: draft` → `complete`.

## Cross-references
- [[HTB-CA2026-Massagold-Stored-XSS-JSONP-CSP-Bypass]]
- [[HTB-CA2026-Gatery-Elysia-Cookie-Signature-Bypass]]

## Change Log
- 2026-07-30 — `status` moved `complete` → `closed`, superseding the change made earlier today. §6's eliminated-chain table and §8's single resume step remain the useful record if the room is ever revisited.
- 2026-07-30 — `status` moved `draft` → `complete`. The event is closed and the gadget chain was never found, so `draft` — which implies work in progress — was the wrong signal. `status` now tracks whether the **note** is finished, not whether the room was solved; the `-PARTIAL` suffix and §6's eliminated-chain table carry the unsolved state, and §8's single resume step remains valid for anyone returning to it.
- 2026-07-24 — Initial partial write-up. Sink, pre-auth reachability, and oracle proven live; gadget chain open. Records confirmed facts, eliminated candidates (with reasons), the leading `__toString`/`FileLayout` LFI candidate, and the single `getDefaultIncludePaths` read that resolves it. `status: draft` (deliberately — challenge unsolved).
