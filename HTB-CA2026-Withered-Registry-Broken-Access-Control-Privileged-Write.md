---
title: "HTB CA2026 — Withered Registry: Broken Access Control on a Privileged Write"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Withered Registry
app: "core_application — Withered Registry Go relay (registry-backend)"
category: secure-coding
difficulty: medium
points: 975
type: writeup
status: complete
mitre:
  - T1190
  - T1078
  - T1068
  - T1552.001
tags:
  - writeup
  - HTB
  - Security
  - Secure_Coding
  - golang
  - access-control
  - authorization
  - code-review
  - detection
related:
  - "[[HTB-CA2026-Saltlock-Drift-RollJam-Rolling-Code-Replay]]"
aliases:
  - Withered Registry
  - CA2026 Withered Registry
created: 2026-07-25T18:38:16.183Z
updated: 2026-07-25T18:38:16.183Z
---

# Withered Registry — Broken Access Control on a Privileged Write

> [!success] Solved
> Flag: `HTB{h0us3_0f_3mb3rs_4nd_4sh_e3907ccb9837282912586a21c5fdd438}`
> **Hard 60/60 · Soft 37/40** (code quality 14, security reasoning 14, patch correctness 9). Accepted on PR #2.
> First **secure-coding** category solve. The deliverable is a patch plus its written justification, not an exploit.

## 0. How the flag was obtained

1. Cloned the repo with the supplied developer account. **One commit only** — the "seven records" in the brief was not git history.
2. Mapped 1,553 lines of Go. `internal/server/authz.go` is 13 lines and exports `houseOf` / `ownsHouse`.
3. Read every handler in `routes.go`. All three read paths scope to the caller's house; **`handleRecognise`, the one privileged write, did not.**
4. Three independent sources stated the intended invariant (§2), none of them enforced it.
5. Installed a Go toolchain and stood up a local harness (§6) to get a **green baseline** before changing anything.
6. Wrote two exploit probes and **confirmed the vulnerability against a live build** — both returned `200` and wrote a crown writ.
7. **v1 patch:** added `ownsHouse(p, house)` before the grant. Both probes → `403`, 17/17 tests pass.
8. **PR #1 rejected. Hard 0/60**, patch correctness 5/10 — below its own floor.
9. Bot feedback: *"the privileged action is still ultimately scoped from request-controlled input… aim for a design where the request cannot select the object being acted on."*
10. **v2 patch:** derived the house from the session (`houseOf(p)`) and **deleted** `targetHouse` and `recogniseRequest` entirely. 18/18 tests pass. **PR #2 accepted, 60/60.**

## 1. Shape of the challenge

A Flask grading platform fronts a Git server holding a Go backend. Push to `developer`, a PR opens automatically, a bot scores it. Hard score (build · required functionality · security checks) must be **60/60**; soft score (code quality 15/12, security reasoning 15/12, patch correctness 10/6) must total ≥28/40.

That rubric is the challenge. The cheapest way to kill a vulnerability is to break the feature, which fails functionality. And **security reasoning is graded on the commit message** — a correct patch with a thin justification still fails.

## 2. The vulnerability

`POST /rite/recognise` raises a house to crown standing. It had two gates, and **neither is an authorization gate**:

| Gate | What it establishes |
|---|---|
| `requireSession` | Authentication — *who* the caller is |
| `requireSlate` | Channel integrity — the request came from a field slate holding `SLATE_KEY`, body unaltered |

Neither answers *"may this principal act on this house?"*. The slate seal is especially misleading as a substitute: **`SLATE_KEY` ships inside the distributed Android client**, so possessing it proves only that the caller downloaded the app. It is a channel credential, not a grant of authority.

The vulnerable handler read its target straight from the request:

```go
func targetHouse(r *http.Request, body *recogniseRequest) string {
	if h := strings.TrimSpace(r.URL.Query().Get("house_id")); h != "" {
		return h                       // query wins
	}
	return strings.TrimSpace(body.HouseID)
}

house := targetHouse(r, &body)
p, _ := principalFrom(r)
writ, err := s.store.GrantCrownWrit(house, p.Username)   // no check
```

**Three sources documented the invariant; none enforced it:**

- `seed.sql` — *"that grant is meant to be made solely by the house's own sworn scribe"*
- `store.GrantCrownWrit` — *"the caller is responsible for deciding whether the grant is authorized"*
- `authz.go` exports `ownsHouse`, used by `handleDecrees` / `handleDecree` / `handleWrits` — and by no write path

## 3. Two exploit vectors, both confirmed live

Logged in as `rook` (house `rookhold`), both returned `200` and wrote a crown writ against `ashvault`:

**Body vector** — `{"house_id":"ashvault"}` in a correctly sealed POST.

**Unsigned query vector** — the more interesting one. `canonicalSeal` covers only:

```
ts \n METHOD \n r.URL.Path \n hex(sha256(body))
```

`r.URL.Path` **excludes the query string**. So a request honestly sealed for the caller's *own* house stays cryptographically valid when `?house_id=ashvault` is appended — and `targetHouse` gives that unsigned parameter precedence over the signed body. **The seal verifies while the effect differs from what was signed.**

## 4. v1 — the wrong fix, and why it scored 0

```go
p, _ := principalFrom(r)
if !ownsHouse(p, house) {
	writeJSON(w, http.StatusForbidden, ...)
	return
}
```

This closed **both** vectors. Both probes returned `403` with no ledger write, verified against a live build, 17/17 tests green.

**It still scored `HARD_SCORE: 0` and `patch_correctness: 5/10`.**

> [!warning] The lesson that cost an attempt
> v1 blocked every attack I could construct, and was still wrong. The grader was not asking *"can rook recognise ashvault"* — it was asking whether request input reaches the privileged decision **at all**. My threat model was complete against my own hypotheses and incomplete against the defender's specification.
>
> **Testing what you thought of is not the same as testing what was asked for.** When a rubric names a property ("required functionality", "security checks"), the property is the spec — not your reconstruction of the attack surface.

## 5. v2 — remove the choice instead of policing it

```go
// The house acted upon is derived from the authenticated session, never from
// the request. A scribe is sworn to exactly one house and that bond is the
// realm's record of who they may act for, so the rite has no target to name.
func (s *Server) handleRecognise(w http.ResponseWriter, r *http.Request) {
	if !s.requireSlate(w, r) {
		return
	}

	p, _ := principalFrom(r)
	house := houseOf(p)
	if house == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "this session is not sworn to a house",
		})
		return
	}

	writ, err := s.store.GrantCrownWrit(house, p.Username)
	...
}
```

`recogniseRequest` and `targetHouse` were **deleted**. The handler reads no house identifier from the body, the query, or any other client-controlled position.

**Why this is strictly stronger than validating.** Validation leaves the object selectable and keeps the security decision dependent on parsing, precedence and canonicalisation of attacker-controlled input — precisely the surface that produced the query-string bypass. An identifier that cannot be supplied cannot be forged, smuggled past the seal, or confused with authority. It also **removes the unsigned-query weakness as a side effect rather than by argument**: no code path reads it any more.

Deliberately not done: extending `canonicalSeal` to cover the query. That is the direct fix for vector 2, but the field client signs path and body only and is **not in the patchable repository** — changing the canonical form would invalidate every legitimate signature and break the workflow.

## 6. Local verification under egress constraints

`proxy.golang.org`, `golang.org` and `gitlab.com/cznic` are all outside the sandbox allowlist, so `go mod download` could not resolve `golang.org/x/crypto` or `modernc.org/sqlite`.

| Blocker | Workaround |
|---|---|
| Go 1.23 toolchain auto-download | `GOTOOLCHAIN=local`, `go.mod` pinned to 1.22 **locally only** |
| `golang.org/x/*` unreachable | `replace` → `github.com/golang/crypto`, `github.com/golang/sys` |
| `modernc.org/sqlite` unreachable | Local shim module registering driver name `"sqlite"` against `mattn/go-sqlite3` |
| `libsqlite3-dev` 404 from the archive | Not needed — `mattn/go-sqlite3` bundles the SQLite amalgamation, so `gcc` alone sufficed |

**None of it reached the diff** — verified `go.mod` appeared zero times in the generated patch. The shimmed suite and the real Docker `--target test` build agreed exactly: 18/18 both sides.

## 7. Final payload

```go
p, _ := principalFrom(r)
house := houseOf(p)
```

That is the whole security fix. Everything else in the diff is deletion of the request-parsing path plus three regression tests.

Submission:

```bash
git checkout -b developer
# apply patch
docker build --target test -t withered-registry-test registry-backend
docker run --rm withered-registry-test go test ./... -v
git add registry-backend/internal/server/routes.go registry-backend/internal/server/server_test.go
git commit -F commit-message-v2.txt        # graded artifact — use -F, never -m
git push -u origin developer               # push opens the PR
curl -s http://[IP]:[PORT]/flag
```

## 8. Tools & techniques

`git` · Go 1.22 (apt) · Docker · `gofmt` · `go vet` · `mattn/go-sqlite3` as a driver shim.

Concepts: broken access control / missing function-level authorization · authentication vs channel integrity vs authorization as three distinct properties · signature coverage gaps (signed path, unsigned query) · client-side secrets as non-credentials · **capability-derived scope over validated input** · regression tests asserting the *effect* rather than the handler's own response.

## 9. MITRE ATT&CK

- **T1190** Exploit Public-Facing Application — the vulnerable endpoint is the entry point
- **T1078** Valid Accounts — the attack requires a legitimate scribe session; it is abuse of granted access, not a break of authentication
- **T1068** Exploitation for Privilege Escalation — crown standing is a privilege the caller's house is not entitled to
- **T1552.001** Unsecured Credentials: Credentials In Files — `SLATE_KEY` embedded in a distributed client, recoverable by any user

> [!warning] Honest scope of this mapping — verify the IDs before trusting them
> This is a defensive code-review exercise; the techniques describe the **adversary behaviour the flaw would enable**, not actions taken.
> **All four IDs were assigned without access to the live ATT&CK matrix and are unverified.** `T1552.001` is the most analogical — it is defined around credentials in files on a compromised host, and a key baked into a distributed mobile client is an extension of that idea. Confirm against attack.mitre.org before treating this frontmatter as authoritative.

## 10. Detection / blue-team & fix notes

- **The bug class is invisible to authentication and integrity controls.** Both gates on this route worked perfectly. Session validation and HMAC verification will never flag a caller acting on an object they should not touch, because neither has any notion of object ownership. Reviews that check "is this endpoint authenticated?" pass this code.
- **Grep for the asymmetry.** The strongest review signal here was internal inconsistency: three read paths called `ownsHouse`, one write path did not. **An authorization helper that every read uses and no write uses is a finding on its own** — and it is mechanically greppable across a codebase.
- **A secret shipped in a client is not a credential.** Anything embedded in a mobile app, desktop binary or JS bundle is public. It can prove *which software* is talking, never *who* is talking or *what they may do*. Treat client-held keys as channel identifiers only.
- **Sign everything that changes the effect, or read only what you signed.** The canonical string covered path and body but not query, while the handler preferred the query. Any gap between "what the signature covers" and "what the handler reads" is exploitable. If the canonical form cannot be changed, stop reading the uncovered positions.
- **Prefer session-derived scope to validated input on privileged writes.** Where the object a request acts on is determined by the caller's identity, derive it. Validation is a control that can be bypassed by parser confusion, precedence quirks, encoding, or a second input position; derivation has no bypass because there is no input.
- **Log the grantor and the grantee separately.** `writs.granted_by` recorded the attacker's own username, so the forged grants were fully attributable after the fact. Cheap, and it turned an invisible compromise into an auditable one.

## 11. Method notes

- **Establish a green baseline before touching anything.** Standing up a working test harness first meant "did I break functionality?" was answerable at every step. Without it, a failing test after a patch is ambiguous.
- **Prove the vulnerability before fixing it.** Two probes returning `200` with a written writ converted "I think this is the bug" into "this is the bug." Both then became regression tests.
- **Read the feedback as a specification, not as a complaint.** The bot's rejection named the required *property* — "the request cannot select the object being acted on" — which is a design constraint, not a bug report. Implementing it literally scored 60/60.
- **`gofmt -l` exits 0 whether or not it lists files.** My `gofmt -l ... && echo clean` printed "clean" while simultaneously listing an unformatted file. Same class of error as syntax-checking a script and calling it tested: **verify the property you care about, not one that cannot fail.**
- **Shell variables do not survive pasted blocks.** `$REPO`/`$PD` silently expanded to empty across separate command blocks four times, producing `/commit-message-v2.txt` and a `-F` failure that would have cost most of the reasoning score. Literal paths in anything handed over for copy-paste.
- **`Everything up-to-date` is a failure message.** It appeared twice when a commit step had been skipped, and reads like success.
- **The commit message is a graded artifact.** 15 of 40 soft points. `-F <file>`, never `-m`, and confirm with `git log -1 --stat` before pushing.

## 12. Open items

- The APK was never opened. `SLATE_KEY` is recoverable from it, but the fix makes the key irrelevant to authorization — worth confirming the field client has no call shape the patch does not cover
- All four ATT&CK IDs unverified — see §9 callout; `T1552.001` is the weakest
- Unknown what the grader's hard security check actually probes. v1 blocked both known vectors and still scored 0, so the check is either structural or uses a vector not reconstructed here
- `code_quality` peaked at 14/15 across both attempts; the missing point was never explained

## Cross-references
- [[HTB-CA2026-Saltlock-Drift-RollJam-Rolling-Code-Replay]]
- [[HTB-CA2026-Cadence-in-the-Cord-UART-Inter-Frame-Timing-Covert-Channel]]
- [[HTB-CA2026-What-the-Shard-Displayed-I2C-SSD1306-Framebuffer-Reconstruction]]

## Change Log
- 2026-07-25 — Note created. Solved on the second submission: PR #1 (validate the request-supplied target) rejected with hard 0/60 and patch correctness 5/10 despite blocking both known exploit vectors; PR #2 (derive the target from the session, delete the request-parsing path) accepted with hard 60/60 and soft 37/40. Records the vulnerability, both exploit vectors including the signed-path/unsigned-query gap, the rejected-then-accepted patch progression, local verification under egress constraints via a SQLite driver shim, and the operational lessons around graded commit messages and shell-variable scope.
