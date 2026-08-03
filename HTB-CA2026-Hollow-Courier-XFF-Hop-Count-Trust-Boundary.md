---
title: "HTB CA2026 — Hollow Courier: Forwarded-Client Provenance Across a Caddy/Flask Boundary"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Hollow Courier
app: "core_application — Salt Gate checkpoint (Flask + gunicorn behind Caddy)"
category: secure-coding
difficulty: easy
points: 950
type: writeup
status: complete
mitre:
  - T1190
  - T1548
  - T1211
tags:
  - writeup
  - HTB
  - Security
  - Secure_Coding
  - authorization
  - code-review
  - detection
related:
  - "[[HTB]]"
  - "[[HTB-CA2026-Withered-Registry-Broken-Access-Control-Privileged-Write]]"
aliases:
  - Hollow Courier
  - CA2026 Hollow Courier
created: 2026-07-26T00:52:32.801Z
updated: 2026-07-26T00:52:32.801Z
---

# Hollow Courier — Forwarded-Client Provenance Across a Caddy/Flask Boundary

> [!success] Solved — 2026-07-25 15:42
> Flag: `HTB{thr33_kn0ck5_0n_s34led_g4t3s_0342ebe211efb5bdf8b8f9633bac5274}`
> **Hard 60/60 · Soft 34/40** (code quality 13, security reasoning 13, patch correctness 8). Accepted on PR #6.
> Second **secure-coding** solve. `easy` · 950 points.

> [!info] Scenario, verbatim
> Lysa Harrowmere has intercepted a Vaultrune route packet ordering the Ashguard away from a Crownspire supply road. She warns Garran Voss that one of tonight's couriers is carrying the order through Salt Gate under a convincing writ. If the decree is sealed before the watch changes, Vaultrune gains an undefended road into Crownspire and another lie acquires the force of law. Garran must identify the compromised passage, uncover how it survived the gate's checks, and stop it without blocking genuine inner-yard runners.
>
> **Objective:** Restore trustworthy forwarded-client provenance across the Caddy and Flask boundary while preserving the legitimate internal route.

## 0. How the flag was obtained

1. Cloned `core_application.git` with the supplied developer account. Tree root `checkpoint/` — `app/`, `conf/Caddyfile`, `tests/`, `requirements.txt`, `seed.sql`.
2. Grepped `app/` for header-derived trust. `gate.is_internal_request()` classifies `request.remote_addr` against `INTERNAL_NETWORKS`, and **`POST /app/gate/decree` mints CROWN authority behind it.** `remote_addr` is therefore an authorization input.
3. Found the two settings that together let a caller on the public road choose that value — one on each side of the boundary (§2). Neither is wrong alone.
4. Stood the **real** stack up locally (§6): gunicorn plus a standalone `caddy` binary running the tree's own `Caddyfile`. No dependency shimming, unlike the Go room.
5. **Confirmed on a green baseline:** `POST /app/gate/decree` with `X-Forwarded-For: 127.0.0.2` returned `200` and sealed decree 1 with authority `CROWN`. Also reachable with `10.0.0.5`, `192.168.1.7`, and repeated-value chains.
6. **Patched two lines**, perimeter and app (§4). `gate.py` and `INTERNAL_NETWORKS` untouched.
7. Re-ran the same harness against the patched tree: every spoof vector → `403`, legitimate relay from `127.0.0.2` still seals → `200`, public routes unchanged, **25 passed**, Caddy reports "Valid configuration".
8. **PRs #1–#4 rejected. #5 was a deliberate baseline reset**, run as a diagnostic rather than a fix attempt (§5). **PR #6 accepted, hard 60/60.**

## 1. Shape of the challenge

Same harness as Withered Registry: a Flask grading platform fronts a Git server, pushing to `developer` opens a PR, a bot scores it. Hard score (build · required functionality · security checks) must be **60/60**; soft score must total ≥28/40 with per-objective floors of 12/12/6.

```
checkpoint/
|-- app/               # Flask application
|-- conf/Caddyfile     # application perimeter
|-- tests/             # application tests
|-- requirements.txt
`-- seed.sql
```

**The structural difference from Withered Registry: both sides of the trust boundary are inside the patchable repo.** There, the Android client shipped `SLATE_KEY` and could not be changed, which hard-constrained the fix. Here `conf/Caddyfile` and `app/__init__.py` are both editable — and the accepted fix touches both.

## 2. The vulnerability

Two configuration values, in two files, neither defensibly wrong on its own. The bug lives in their composition.

| Setting | File | Effect |
|---|---|---|
| `trusted_proxies private_ranges` | `conf/Caddyfile` | Every request reaches the perimeter over the deployment's private network, so this matched the immediate peer on **ordinary public traffic**. Caddy therefore *preserved* a caller-supplied `X-Forwarded-For` and appended its own observation: `<attacker value>, <peer>` |
| `ProxyFix(app.wsgi_app, x_for=2, ...)` | `app/__init__.py` | `x_for` counts from the **right** of the chain. `2` selects second-from-last — the attacker's entry — and assigns it to `request.remote_addr` |

**The hop count is the tell.** The Dockerfile runs exactly one proxy in front of gunicorn: Caddy on `:8000` → `127.0.0.1:5000`. `x_for=2` assumes a second hop that does not exist in this deployment. The comment sitting directly above it said so:

```python
# Deployment expects an edge cache and the application perimeter.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1, x_host=1)
```

Same pattern as Withered Registry, inverted. There, three comments documented an invariant no code enforced. Here, a comment documented a **topology the container never had** — the comment was the threat model, the Dockerfile was the deployment, and they disagreed.

## 3. The exploit, confirmed live

```http
POST /app/gate/decree HTTP/1.1
X-Forwarded-For: 127.0.0.2

order=t
```

`200` — decree 1 sealed with authority `CROWN`, from an unauthenticated request on the public interface.

Equally effective: `10.0.0.5`, `192.168.1.7`, and repeated-value chains such as `127.0.0.2, 127.0.0.2`. Any value inside `INTERNAL_NETWORKS` placed second-from-last works, because the caller controls the whole left side of the chain and Caddy only appends to it.

`X-Real-IP: 127.0.0.2` is **not** a vector — measured `403` against pristine `main`. `_origin_address()` reads `request.remote_addr` and never the header, and the perimeter already overwrote it with `header_up X-Real-IP {remote_host}`. Two of the six submissions were nonetheless spent moving the decision *onto* that header, and the grader rejected both on principle (§5).

## 4. The fix — assert at the boundary, stop looking past it

```diff
 :8000 {
 	reverse_proxy 127.0.0.1:5000 {
-		# Accept forwarding metadata from the deployment's private proxy tier.
-		trusted_proxies private_ranges
+		# The perimeter is the only trusted hop. Forwarding metadata is set
+		# from the observed peer, never carried in from the caller.
+		header_up X-Forwarded-For {remote_host}
 		header_up X-Real-IP {remote_host}
 		header_up X-Forwarded-Proto {scheme}
 	}
```

```diff
-    # Deployment expects an edge cache and the application perimeter.
-    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1, x_host=1)
+    # Exactly one trusted hop sits in front of the app: the perimeter proxy
+    # in conf/Caddyfile. Trusting more hops would read caller-supplied entries.
+    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
```

Either change alone closes the path. Together the boundary **asserts** the invariant and the app **declines to look past it** — the guarantee is stated in configuration rather than inferred from a trust list.

**Deliberately not changed.** `INTERNAL_NETWORKS` and `gate.py`. The private ranges are legitimate internal topology; narrowing them would break watch runners without addressing the provenance defect. The objective statement named the internal route as functionality to preserve.

**Rejected alternative.** Reading `X-Real-IP` directly in the application. It moves an authorization decision onto an app-readable header, which is sound only while *every* ingress path is guaranteed to overwrite it. Provenance stays with the request stack.

This is Withered Registry v2's shape again: **delete the choice rather than police it.** There, the object identifier was removed from the request. Here, the caller's forwarding metadata is overwritten at the perimeter, so there is nothing left to police.

## 5. Why six pull requests

The vulnerability took one grep. The submission took six PRs — #1 through #4 rejected, #5 a deliberate baseline reset run as a diagnostic, #6 accepted.

> [!warning] The lesson that cost four attempts
> **The security patch was live on the branch from PR #3 onward and still read as an incomplete fix.**
>
> The bot grades the **increment** — `previous-head..new-head` — not the cumulative state of the branch. A correct fix delivered as fragments across separate pushes shows the reviewer only the last fragment. The earlier ones are invisible to it, even though they are present in the code it builds and tests.
>
> **Land the whole fix in one push.** If the branch already carries part of the change, reset to the pre-fix baseline and re-land it as a single increment — which is exactly what PR #5 was for, and why #6 scored.
>
> Same failure shape as Withered Registry v1, one level up. There the *design* was scoped to the wrong thing — request-selected instead of session-derived. Here the *submission* was — increment instead of branch. Both times the artifact was defensible in isolation and wrong against what the grader actually reads.

**The six submissions, and what the grader actually said**

| PR | Range | Verdict | The operative sentence |
|---|---|---|---|
| #1 | `5346f725..3e23539e` | rejected | *"Aim to restore provenance at the boundary and keep internal allowlisting aligned with the real internal topology, rather than narrowing it to a single address."* |
| #2 | `3e23539e..02d9b30a` | rejected | *"You've moved a trust decision onto a request header inside the app … it remains a fragile basis for authority."* Plus patch artifacts — stray `+`/`-` characters and re-indentation that would not have applied. |
| #3 | `02d9b30a..a8de1055` | rejected | *"The core approach still puts authorization onto a header value inside the application."* |
| #4 | `a8de1055..c06ab7c8` | rejected | *"There's no accompanying change that tightens the trust boundary / hop assumptions that feed that reconstruction."* |
| #5 | `c06ab7c8..4b745d9a` | rejected | *"This submission effectively reverts to the original behavior."* — the deliberate baseline reset, and the reply that confirmed grading is increment-scoped. |
| #6 | `4b745d9a..9dbd2c2c` | **accepted** | *"You align the trusted hop-count with the real proxy depth and ensure the perimeter rewrites forwarding metadata from its own observed peer rather than inheriting caller-provided values."* |

**The grader named the fix in PR #1 and then repeated it four times.** *"Restore provenance at the boundary"* is precisely what `header_up X-Forwarded-For {remote_host}` does. By #4 it was spelling out both halves as alternatives — *"ensuring the perimeter-to-app boundary cannot carry caller-influenced forwarding metadata inward, **or** strictly bound the number of trusted proxy hops to match the real deployment."* The accepted patch does both.

**PR #1 is also where §4's "deliberately not changed" comes from.** It rejected narrowing `INTERNAL_NETWORKS` outright — *"likely to break legitimate internal runners"* — which is why the private ranges were left intact through the remaining five attempts.

**PR #4's rejection is the cleanest evidence for increment-scoping.** *"No accompanying change that tightens the trust boundary"* is **false of the branch** — `x_for=1` had been live since #1 — and **true of the increment**, which touched only `gate.py`. The grader was reporting accurately on what it could see.

## 6. Local verification

No shimming was required. PyPI and `files.pythonhosted.org` are inside the sandbox allowlist, so Flask, pytest and requests install cleanly and the **real** stack runs locally before any Docker cycle. The Go room needed `replace` mirrors and a hand-rolled SQLite driver shim; this one needed neither.

`secure_code/verify-fix.sh` starts gunicorn on `127.0.0.1:5000` and a local `caddy` binary on `:8000` from the tree's own `Caddyfile`, then fires the same probes against whichever tree it is pointed at:

| Probe set | Contents |
|---|---|
| Attack (7) | no header · `X-Forwarded-For: 127.0.0.2` · `127.0.0.2, 8.8.8.8` · `10.0.0.5` · `192.168.1.7` · `X-Real-IP: 127.0.0.2` · `127.0.0.2, 127.0.0.2` |
| Functionality (8) | `/app/` · `/app/status` · `/app/charter` · `/app/gate/inspect?writ=x` · `/app/houses/1` · `/app/login` · `POST /app/gate/present` |

**After the patch:** every spoof vector → `403`. Legitimate watch relay from `127.0.0.2` still seals a decree → `200`. Public routes unchanged. Full suite **25 passed**. `caddy` 2.10.2 reports "Valid configuration".

> [!warning] The harness misreports under Docker's default network
> Under `docker run -p 8000:8000`, the perimeter's observed peer is the bridge gateway `172.17.0.1` — inside `172.16.0.0/12`, and therefore inside `INTERNAL_NETWORKS`. The **patched** build then returns `200` on `/app/gate/decree` with no spoof header at all, which reads as a failed fix.
>
> `docker run --network host` makes the peer `127.0.0.1`, which is outside the allowlist, and both the clean and spoofed probes return `403`.
>
> **The pass criterion is that clean and spoofed become identical, not that either is `403`.** Before the patch they differ (`403` / `200`); after, they agree. Compare the pair, not the absolute code.

Pointing one harness at two trees is what turned every claim into a diff — a vector list that moves `200 → 403` while the functionality list stays flat is the entire evidence package the rubric asks for.

## 7. Final payload

```diff
- trusted_proxies private_ranges
+ header_up X-Forwarded-For {remote_host}
```

```diff
- ProxyFix(app.wsgi_app, x_for=2, x_proto=1, x_host=1)
+ ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
```

Two lines. Everything else in the diff is comments and tests.

```bash
git clone http://htb_developer:HTBDeveloperPassword@[IP]:[PORT]/git/core_application.git
cd core_application && git checkout -b developer

# confirm the bug on a green baseline, then after the patch
/absolute/path/to/verify-fix.sh /absolute/path/to/checkpoint "BEFORE"
git apply /absolute/path/to/hollow-courier-fix.patch
/absolute/path/to/verify-fix.sh /absolute/path/to/checkpoint "AFTER"

python -m pytest -q                                    # expect: 25 passed
caddy validate --config checkpoint/conf/Caddyfile --adapter caddyfile

git add checkpoint/conf/Caddyfile checkpoint/app/__init__.py checkpoint/tests
git commit -F /absolute/path/to/commit-message.txt     # graded artifact — -F, never -m
git log -1 --stat                                      # -F fails silently on a bad path
git push -u origin developer                           # push opens the PR; land the WHOLE fix here
curl -s http://[IP]:[PORT]/flag                        # scorecard until it is the flag
```

Substitute real absolute paths above. Shell variables do not survive between separately-pasted command blocks — this cost four attempts in the previous room.

## 8. Tools & techniques

`git` · Python 3 / Flask 3.1.3 · gunicorn · `caddy` 2.10.2 standalone binary · pytest 9.1.1 · `curl` · Docker.

Concepts: reverse-proxy trust boundaries · `X-Forwarded-For` chain semantics and hop counting · Werkzeug `ProxyFix` `x_for` indexing from the right · Caddy `trusted_proxies` (classify-and-append) versus `header_up` (assert-and-overwrite) · header-derived values masquerading as socket-derived ones · differential testing of vulnerable and patched trees through a single harness.

## 9. MITRE ATT&CK

- **T1190** Exploit Public-Facing Application — the decree endpoint is the entry point, reachable unauthenticated from the public interface
- **T1548** Abuse Elevation Control Mechanism — the spoofed header circumvents the internal-origin check gating CROWN authority
- **T1211** Exploitation for Defense Evasion — the gate's own check is what the request defeats; no control fires and the response is a well-formed `200`

> [!warning] Honest scope of this mapping — verify the IDs before trusting them
> Defensive code-review exercise; these describe the **adversary behaviour the flaw would enable**, not actions taken. **All three IDs were assigned without access to the live ATT&CK matrix and are unverified.**
>
> ATT&CK has no technique for *"the perimeter preserved a caller-supplied forwarding header."* The mapping is of reachability, access and effect — not of the defect. **OWASP is the accurate classification here:** primarily **A05:2021 – Security Misconfiguration** (the defect is two configuration values, not code logic), with **A01:2021 – Broken Access Control** for the effect. Cite OWASP first for this class of room.

## 10. Detection / blue-team & fix notes

- **The perimeter must overwrite, not append.** `trusted_proxies` is a *classification* directive — it names whose forwarding metadata to believe, matched against the immediate peer. In any deployment where public traffic arrives via a private-range peer, it matches everything. `header_up X-Forwarded-For {remote_host}` is an *assertion*: the header becomes what the proxy observed, unconditionally, on every ingress path. Prefer the assertion.
- **Count hops from the Dockerfile, not the comment.** `x_for=N` indexes from the right. Any `N` greater than the number of proxies actually deployed reads attacker-controlled data by construction. The vulnerable code documented an edge cache the container never ran.
- **`remote_addr` behind a proxy is not an identity.** Once `ProxyFix` is installed, `request.remote_addr` is a header-derived value wearing the name of a socket-derived one. Any decision reading it inherits the trust properties of the header, not of the TCP connection. **Grep for `remote_addr` inside authorization helpers** — it is mechanically findable.
- **Network position is a weak authorization primitive at best.** `is_internal_request()` answers *where from*, never *who* or *what may they do*. Even correctly implemented it is a perimeter control, and any compromised internal host inherits full authority.
- **Log the observed peer alongside the derived one.** Recording both the socket peer and the post-`ProxyFix` `remote_addr` on every privileged route makes this spoof visible in a single query — the two disagree on exactly the attack traffic and agree on everything else. This is the only signal available, because the exploit produces a legitimate `200` on a legitimate endpoint.
- **Alert on inbound forwarding headers at the edge.** Once the perimeter overwrites them, their *presence* on inbound requests is pure signal: no legitimate external client sets `X-Forwarded-For`.

## 11. Method notes

- **The objective statement was the specification.** It named both the defect location (*the boundary*, not the gate) and the functionality constraint (*preserving the legitimate internal route*). Read literally, it ruled out narrowing `INTERNAL_NETWORKS` before a line of code was read.
- **Two settings, neither wrong alone.** Auditing each against a style guide passes both. **Check configuration pairs against the deployed topology.**
- **One harness, two trees.** Differential output is the evidence the rubric rewards; a prose claim is not.
- **A working directory is not a clean room.** One directory in the session held a stale clone of Withered Registry — a Go application — while the work was on a Flask one. `ls` caught it. Confirm the tree before trusting any command run inside it.
- **The commit message is a graded artifact.** `-F <absolute path>`, never `-m`; confirm with `git log -1 --stat` before pushing.

## 12. Open items

- All three ATT&CK IDs unverified — see §9. The mapping is analogical; OWASP A05/A01 is the defensible classification.
- Soft score plateaued at 13/15 on both code quality and security reasoning. The missing points were never explained — same unexplained ceiling as Withered Registry's 14/15.

## Cross-references
- [[HTB-CA2026-Withered-Registry-Broken-Access-Control-Privileged-Write]]
- [[CA2026-hollow-courier-session-kickoff]]
- [[HTB-CA2026-Gatery-Elysia-Cookie-Signature-Bypass]]
- [[HTB]]

## Change Log
- 2026-07-26 — Note created. Solved on the sixth submission: the security patch was live on the branch from PR #3 but the bot grades `previous-head..new-head`, so the fix read as incomplete until PR #5 reset to baseline and PR #6 landed it as a single increment (hard 60/60, soft 34/40). Records the two-setting composition bug (`trusted_proxies private_ranges` preserving a caller-supplied `X-Forwarded-For`, `ProxyFix x_for=2` reading past the perimeter's own entry), the confirmed exploit, the two-line fix asserting provenance at the boundary, the differential harness in `secure_code/verify-fix.sh`, and the detection guidance around logging observed-versus-derived peer. Points recorded as 950 from the platform scenario page, correcting the kickoff note's 975. Flag string operator-confirmed at authoring time; no vault artifact corroborates it independently.
- 2026-07-26 — Removed a resolved Open item recording the kickoff as `Loaded` at `975`. Both halves are now false: the kickoff's Targets row was corrected in its own rewrite, and the surviving `975` in its `Current target` block was corrected to `950`. That bullet also carried the note's only broken wikilink — `[[HTB-CA2026-hollow-courier-session-kickoff]]`, written before the kickoff was renamed to `CA2026-hollow-courier-session-kickoff` — which the Cross-references block already had in its correct form.
- 2026-07-26 — §5 extended with the six-PR grading table and all six bot verdicts, sourced from the live `/pulls/1`–`/pulls/6` pages rather than reconstructed. Records that the grader named the correct fix in PR #1 and repeated it four times, that PR #1 is the origin of §4's "deliberately not changed" decision on `INTERNAL_NETWORKS`, and that PR #4's rejection is false of the branch but true of the increment. Two Open items closed with measured results: `X-Real-IP` was never a vector (`403` on pristine `main`, now recorded in §3), and the PR feedback is no longer missing. §6 gained a warning that the differential harness misreports under Docker's default bridge network, where the peer is `172.17.0.1` and falls inside `INTERNAL_NETWORKS` — the pass criterion is the clean and spoofed probes becoming identical, not either returning `403`.
