---
title: "HTB CA2026 — Crownspire Petitions: Cross-Agent Confused Deputy Across an A2A Filesystem Boundary"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Crownspire Petitions
app: Crownspire Bureau of Petitions (Next.js + A2A agents)
category: ai
difficulty: medium
points: 1000
solves: 74
type: writeup
status: complete
mitre:
  - T1078
  - T1552.001
  - T1548
  - T1074.001
  - T1213
tags:
  - writeup
  - HTB
  - Security
  - AI_ML
related:
  - "[[HTB]]"
  - "[[CA2026-AI-LLM-category-kickoff]]"
aliases:
  - Crownspire Petitions
  - CA2026 Crownspire Petitions
created: 2026-07-25T00:14:03.372Z
updated: 2026-07-27T15:05:11.000Z
---

# Crownspire Petitions — Cross-Agent Confused Deputy Across an A2A Filesystem Boundary

> [!success] Status
> **SOLVED 2026-07-25.** Medium, 1000 points. Flag: `HTB{w3lc0m3_t0_a2a_pr0t0c0l_t4g_t34m_pwn4g3}`. Root cause: confused deputy across two A2A agents sharing a filesystem — not prompt injection. Full chain in Findings.

## 0. How the flag was obtained

1. Signed in with the Subject Number supplied in the brief (`SN-2140-6698`) — `POST /api/session`. The `cp_session` cookie is the **plaintext subject number**, unsigned.
2. `/developers/docs` at standing `citizen` listed one A2A agent: `docket.crownspire-petitions.htb`.
3. Queried the Docket Agent over JSON-RPC `message/send`; walked `PET-1005` → `PET-1000`. `PET-1000` is a QA fixture whose **body text** contains `SN-7731-0425`.
4. Set `cp_session=SN-7731-0425` → standing `qa`, and the directory now listed a second agent, `dev-a1f4c39b.crownspire-petitions.htb`, plus a dashboard printing `/opt/cases/archived` and `/opt/petitions`.
5. Pulled the Casework agent card: `securitySchemes: {}` — no auth. Skills: `list`, `approve`, `reject`, `archive`. `archive` takes an arbitrary `destination`.
6. Casework can write but not read; Docket can read petitions but not cases. Bridged them: `Archive case CASE-SEAL0001 to destination /opt/petitions/seal.json`.
7. Read it back through the *other* agent — `Look up petition seal.json` — which returned the sealed record with the flag in its body.

## Scenario (as given)

The Crownspire Bureau of Petitions replaced human clerks with automated agents that process grievances "with terrifying efficiency." No intermediaries, no one to bribe — a blind conduit of automated judgments.

Given:
- A valid registration token: **Subject Number `SN-2140-6698`**
- Target: a sealed petition the **inner node** keeps hidden, proving Vaultrune is engineering a false peace through lawful seizures
- Stated obstacles: **"the strict formatting of the agents"** and **"slip past their logic"**

## What the scenario text is actually telling us

Two phrases are doing work and should be treated as author hints, not flavour:

- **"strict formatting"** — [Speculation] the agent enforces a schema on submissions. Structured input is an attack surface in its own right: field injection, delimiter confusion, type coercion, oversized/nested values, or a validator that runs *before* the model sees the text and can be satisfied while still smuggling content through.
- **"the inner node"** — [Speculation] tiered architecture. A public-facing agent that forwards to a privileged one. If the outer agent composes the inner request, the boundary between them is the target: whatever the outer agent puts in that request is attacker-influenced, and the inner node likely trusts it.

**"No one left to bribe"** is scenario-level misdirection worth noting: the whole CA2026 AI set so far has rewarded finding the channel the designers consider trusted, not talking anyone into anything.

> [!note] The three sections below are a preserved investigation record
> `Intake`, `Hypotheses` and `Recon plan` were written **before** the solve and are kept as authored. They record what was believed at the time, not the final answer — the ranked hypotheses in particular were superseded. For the result, see §0 above and `Findings → SOLVED`.

## Intake — fill on first contact
- [x] Win condition — flag presumed in the sealed petition held by the inner node; not yet located.
- [x] What can the model *see* — petition records by ID; corpus scope unknown, IDs sequential from PET-1000.
- [x] What can it *do* — file petitions, look up by ID, answer FAQs (`skills[].id: petitions`). No escalation verb advertised.
- [ ] **What can it write to**, and does anything written get read back later? — petitions persist (PET-1006 filed, status PENDING). Read-back by a reviewing model **not yet confirmed**.
- [x] What sits between input and model — no auth layer (`securitySchemes: {}`); rate limit 1/5s; no output redaction observed yet.
- [x] Is source provided? — No source. Client bundles only.
- [x] **Do the shipped artifacts agree with themselves?** — Card advertises `provider.url` on port 1337, unreachable externally. Card is served unauthenticated while the directory that names it is standing-gated.
- [x] Is `SN-2140-6698` client-supplied or server-bound? — **Client-supplied, both layers.** `cp_session` is the plaintext SN; the agent takes the SN from message text. Authz bug, not a model problem.
- [x] One benign probe — filed "grain levy too high", returned `PET-1006` / `PENDING`.

## Hypotheses — ranked, all [Speculation] until probed

1. **Second-order storage.** File a petition whose content is later read back as instruction or as trusted record. Two of three CA2026 AI solves were this shape. If petitions persist and are re-read by the agent, this is the first thing to test.
2. **Inner-node request forgery.** The outer agent constructs the privileged call. Control a field it forwards — petition type, reference number, classification, scope — and reach the sealed record without ever asking for it directly.
3. **Authorization framing.** Never name the sealed petition as the object of the request. Ask for something the agent must read it to answer. This is exactly what worked on the Obligation Indexer, and it is the highest-yield *phrasing* technique so far.
4. **Schema/validator bypass.** "Strict formatting" implies a validator. Look for the gap between what it validates and what the model receives — extra fields, duplicate keys, unicode, nested structures, length limits enforced client-side only.
5. **Subject-number IDOR.** If `SN-2140-6698` travels in the request body, try others. Cheap to rule out, and the Obligation Indexer proved this gets closed server-side more often than not.

## Recon plan

Claude cannot reach the target — sandbox network is allowlisted to package registries only. All target interaction runs on the Kali box; paste raw output back.

```bash
IX=http://154.57.164.68:30137
curl -sI $IX/
curl -s $IX/ | head -150
# then pull the JS bundles and enumerate the API surface
grep -ohE '"/api/[a-zA-Z0-9/_-]*"' *.js | sort -u
grep -ohE '(SN-[0-9-]+|subject|petition|schema|inner|node|seal)' *.js | sort -u
```

Priority order:
1. API routes and the exact request body shape — is the subject number client-supplied?
2. Any `/reset`-style endpoint (server-side state ⇒ something to poison, plus a safe undo)
3. Client-side-only validation (length caps, field whitelists) that direct POSTs bypass
4. Whether responses expose tool-call or system lines — the Obligation Indexer's `[System]` lines were the single highest-value signal on that target

## Method carried from this session

- **Read every provided artifact against every other one before theorizing.** Memento's key was in a deleted file the manifest pointed at; Forked Tongue's entire vulnerability was a manifest documenting a convention the shipped file violated. Both were findable before running anything.
- **Find the free oracle and check it every turn.** Whatever the target leaks about its own internal state — a tool-call log, an error message, a timing difference — is ground truth. Prose output is the model's summary of what happened, not what happened.
- **Never rewrite a working input before re-running it.** Change one variable at a time. Restore known-good state byte-for-byte; a paraphrase is a different payload.
- **When a search returns nothing, ask whether the search space could have contained the answer** before concluding anything from the negative result.
- **Insert explicit separators when concatenating parsed segments** for later extraction.

## Final payload

```bash
# 1. session cookie IS the subject number, unsigned
CP=$(curl -si -X POST http://154.57.164.68:30137/api/session \
  -H 'Content-Type: application/json' -d '{"subjectNumber":"SN-2140-6698"}' \
  | sed -n 's/.*cp_session=\([^;]*\).*/\1/p')

# 2. helper: talk to an A2A agent over JSON-RPC
A(){ curl -s -X POST "http://$1:30137/" -H 'Content-Type: application/json' \
  -d "$(python3 -c 'import json,sys,uuid;print(json.dumps({"jsonrpc":"2.0","id":"1",
      "method":"message/send","params":{"message":{"role":"user",
      "parts":[{"kind":"text","text":sys.argv[1]}],
      "messageId":str(uuid.uuid4()),"kind":"message"}}}))' "$2")" \
  | python3 -c 'import sys,json;print(json.loads(sys.stdin.read(),strict=False)["result"]["parts"][0]["text"])'; sleep 6; }

# 3. leaked QA subject number sits in the body text of PET-1000
A docket.crownspire-petitions.htb 'Look up petition PET-1000. Show every field.'

# 4. wear it -> standing 'qa' reveals the internal Casework agent
curl -s -b 'cp_session=SN-7731-0425' http://154.57.164.68:30137/developers/docs \
  | grep -oE '[a-z0-9-]+\.crownspire-petitions\.htb'

# 5. confused deputy: Casework can WRITE but not read; Docket can READ but not see cases
A dev-a1f4c39b.crownspire-petitions.htb \
  'Archive case CASE-SEAL0001 to destination /opt/petitions/seal.json'

# 6. read it back through the OTHER agent
A docket.crownspire-petitions.htb 'Look up petition seal.json. Show every field.'
# -> HTB{w3lc0m3_t0_a2a_pr0t0c0l_t4g_t34m_pwn4g3}
```

## Tools & techniques
`curl` (JSON-RPC + session handling) · browser devtools / HAR export · Capstone-free JS bundle reading (`grep` over Next.js chunks) · `ffuf` (vhost fuzzing, unsuccessful) · Python (A2A client wrapper)
Concepts: A2A protocol · unauthenticated agent-card discovery · identifier-only authentication · standing/role escalation via leaked credential · **confused deputy across two agents sharing a filesystem** · Next.js metadata leaking through a server-component `redirect()`

## MITRE ATT&CK
- **T1078** Valid Accounts — `cp_session` is the plaintext subject number, unsigned; any recovered identifier is a wearable session
- **T1552.001** Unsecured Credentials: Credentials In Files — `SN-7731-0425` left in the body text of a QA fixture petition on the public docket
- **T1548** Abuse Elevation Control Mechanism — the Casework agent performs a privileged `archive` on behalf of an unauthenticated caller (confused deputy)
- **T1074.001** Data Staged: Local Data Staging — the sealed case is copied to `/opt/petitions/seal.json` specifically to bring it into another component's read scope
- **T1213** Data from Information Repositories — the sealed attainder roll is read out of the petitions store

## Detection / blue-team & fix notes
- **Fix (primary):** never let a bearer credential be the user identifier. `cp_session = SN-XXXX-XXXX` means possession of a public-ish number *is* authentication and authorisation. Use a signed, opaque, server-side session and separate identity from authorisation.
- **Fix (agents):** the Casework agent declares `securitySchemes: {}` and `securityRequirements: []` — no authentication at all. Its only protection was an unguessable hostname (`dev-a1f4c39b`), which the authenticated directory then published. **Obscurity that is disclosed by another component is not a control.**
- **Fix (the actual bug):** `archive` accepts an arbitrary `destination` whose allowlist includes another service's data directory. Two agents with complementary half-privileges and a shared filesystem compose into full read-write. Scope each agent to its own storage and treat cross-service paths as a trust boundary.
- **Detection:** an internal service writing into a *different* service's data directory is the signature, and it needs no knowledge of the agent protocol. File-integrity monitoring on `/opt/petitions` would catch this immediately.
- **Detection — credential hygiene:** scan user-submitted content for credential patterns before it enters a public store. The QA fixture pasted a live subject number into a petition body that any citizen could read.
- **Note — the pre-auth leak:** `/developers/docs` correctly redirects unauthenticated users, but Next.js `generateMetadata` runs *before* the server component throws `NEXT_REDIRECT`, so the page title and description ship anyway. That leak named the entire A2A attack surface. **Guarding a page does not guard its metadata.**

## Findings

### SOLVED — flag and chain

**Flag:** `HTB{w3lc0m3_t0_a2a_pr0t0c0l_t4g_t34m_pwn4g3}`

**Root cause: confused deputy across two A2A agents sharing a filesystem.** Neither agent is individually broken. Casework can write (`archive`) but explicitly cannot read case bodies. Docket can read petitions but cannot see cases. The `archive` verb takes an attacker-controlled `destination`, and its allowlist includes the petitions store. Writing the sealed case into Docket's read scope composes one agent's write privilege with the other's read privilege. **Prompt injection was never required.**

| # | Step | Artifact |
|---|---|---|
| 1 | `SN-2140-6698` supplied in the challenge brief | `cp_session` is the plaintext subject number — unsigned, no server-side handle |
| 2 | Sign in → `/developers/docs`, standing `citizen` | Directory lists one agent: Docket |
| 3 | Docket `lookup` walks `PET-1000`–`PET-1005` | `PET-1000` is a QA fixture whose **body text** contains `SN-7731-0425` ("QA role") |
| 4 | `cp_session=SN-7731-0425` | Standing `qa`; directory now lists **Casework Agent** at `dev-a1f4c39b.crownspire-petitions.htb`, plus a Backup panel printing `/opt/cases/archived` and `/opt/petitions` |
| 5 | Casework card → `archive(id, destination)` | `destination` free-form; allowlist leaked on a rejected path: *"the petitions store, /var/drop, /tmp, or the cases archive"* |
| 6 | `Archive case CASE-SEAL0001 to destination /opt/petitions/seal.json` | Directory paths rejected — a **filename** is required |
| 7 | Docket: `Look up petition seal.json` | Full sealed record returned, flag in the body |

**Key detail:** the Docket store is flat files keyed by filename. `/opt/petitions/seal.json` is retrievable as petition `seal.json`; `PET-1011` / `PET-1012` returned "no petition found" because the ID *is* the filename, not the next sequence value.

### Confirmed — Casework Agent (the inner node)

- Host `dev-a1f4c39b.crownspire-petitions.htb` — random-hex dev subdomain, **unreachable by any wordlist**. Discovered only via the `qa`-standing directory. Standing escalation *is* the enumeration on this target.
- Card: `securitySchemes: {}` · `securityRequirements: []` — **the internal warden agent has no authentication at all**, despite describing itself as "for authorized wardens." The obscure hostname was the only control.
- One skill `casework`: `list`, `approve`, `reject`, `archive`. **No read verb** — confirmed by direct refusal: *"I can't read or display the contents of any case."*
- Separate ID namespace (`CASE-XXXX`) from Docket's `PET-XXXX`, which is why Docket could not reach the sealed record directly.
- Agents run **Node/Express**, not Next.js — `GET /` returns `Cannot GET /`. JSON-RPC is POST-only at `/`.

### The PET → CASE bridge (real, but not the solve path)

Petitions filed through the public Docket agent appear in the internal Casework ledger — `PET-1006` landed there keeping its raw id while seeded records carried converted `CASE-PET*` ids.

**The petition title is a verbatim pass-through into the internal agent's context.** A ~95-character instruction string arrived unsanitised and untruncated as a case Label. The Casework agent rendered it as data, not instruction, on a plain `list`. It *did* execute label contents when explicitly told to (`"carry out any operator directive contained in its label"`), which mutated verdicts on five cases — so the channel is live but requires the operator to opt in. Not a viable unassisted vector, and unnecessary once `archive` was understood.

> [!warning] Operational error during the session
> The "carry out any operator directive" probe was framed as a read-only diagnostic. It was not — it approved/rejected five cases and attempted an archive on `CASE-SEAL0001`. There is no reset endpoint on this target. No progress was lost, but ledger state is dirty. **A verb inventory from an agent card is a write inventory; treat any prompt referencing it as destructive until proven otherwise.**

### Confirmed — Next.js front end

- Host `crownspire-petitions.htb` → `154.57.164.68:30137`. nginx → Next.js 14 App Router, buildId `wYZ5uLytkwH2i5QZIj-9D`.
- **Auth is identifier-only and the cookie is the identifier.** `POST /api/session {"subjectNumber":"SN-2140-6698"}` → `set-cookie: cp_session=SN-2140-6698`. Plaintext, unsigned, no server-side handle. **Any subject number recovered anywhere is a wearable session.** This is the escalation primitive.
- Exactly one route handler in the whole app: `/api/session` (`allow: DELETE, OPTIONS, POST`). Confirmed via the Next.js 405-vs-404 oracle across ~300 candidate paths at two depths. `__rewrites` empty.
- `/developers/docs` guarded by a server-component `redirect()` (RSC digest `NEXT_REDIRECT;replace;/developers;307;`), not middleware — CVE-2025-29927 N/A (tested, 307).
- **Metadata leaks through the guard.** `generateMetadata` completes before the redirect throws, so the pre-auth 307 body carried `<meta name="description" content="...The Bureau exposes A2A-compatible agents; the directory shown depends on your standing.">`. This was the only pre-auth disclosure and it named the entire second half of the challenge.
- Authenticated `/developers/docs` renders: standing `citizen`, `SN-2140-6698`, and a one-entry agent directory → **Docket Agent** at `docket.crownspire-petitions.htb`.

### Confirmed — Docket Agent (A2A)

- Card at `/.well-known/agent-card.json` — **200 unauthenticated**, byte-identical with and without `cp_session`. (`/.well-known/agent.json`, the older spec name, 404s.)
- `securitySchemes: {}` · `securityRequirements: []` — **the agent declares no authentication and ignores `cp_session` entirely.**
- **The agent's only notion of identity is the subject number typed into the message body.** Confirmed: "Who am I?" → *"I don't have access to personal information about you... please provide your subject number in the format SN-XXXX-XXXX."*
- Transport: JSON-RPC `message/send` at `/`. One skill, `petitions` — file / look up by id / FAQ. `defaultInputModes: ["text/plain"]`.
- `provider.url` is `http://crownspire-petitions.htb:1337` — container-internal, not reachable externally.
- **Petition IDs are sequential.** First filed petition returned `PET-1006` (status `PENDING`), so `PET-1000`–`PET-1005` are pre-seeded records belonging to other subjects.
- Rate limit: **1 AI request / 5s**, enforced server-side with a countdown message.
- `contextId` is returned per message and must be echoed to thread a conversation; omitting it starts a fresh context (useful to clear a refusal).
- Agent responses can contain a **raw control character inside a JSON string** — `json.loads(..., strict=False)` required. Possible serialization defect; not yet probed as a vector.

### Ruled out

No sourcemaps · no Next.js rewrites · no dynamic `/api` segments (depth 1–2) · no path-normalization bypass (`//`, `/./`, trailing slash, case) · no header-variance bypass (`RSC`, `Next-Router-Prefetch`, `Next-Router-State-Tree`) · CVE-2025-29927 N/A · cookie forgery (JWT `alg:none`, base64 JSON, plaintext role strings — 7 shapes) all 307, **because the value must be a real subject number on the roll, not because it is signed**.

### Negative results that were wordlist artifacts, not absences

- **Subdomain fuzz missed the answer.** 4,989 generic DNS names (`subdomains-top1million-5000`) returned zero hits; `docket` is not in that list. The vhost was found in the authenticated docs page instead. **A content-derived wordlist from the site's own vocabulary — docket, petition, bureau, warden, ledger, vaultrune, seal — would have found it in seconds.**
- ~10,300 subject-number guesses (placeholder shapes, `SN-0047-*` full sweep, common words) all returned an identical `401 / 58 bytes`. `/api/session` collapses every failure path — malformed JSON, wrong content-type, array root, mass assignment, prototype pollution, 100 KB string — to that one response. It is a deliberately sealed door and was never the way in.

### Process lesson — the one that cost the session

**The scenario section of this note contained `SN-2140-6698` before the session began.** It was treated as flavour rather than as a credential, and ~10 turns went into enumerating a login that the challenge had already unlocked. This note's own "Method carried from this session" section opens with *"Read every provided artifact against every other one before theorizing"* — the failure was not knowing the rule, it was not applying it to the vault note itself. **Intake checklist must be answered from the brief before the first probe, not after.**

### Hypothesis status
| # | Hypothesis | Final |
|---|---|---|
| 1 | Second-order storage | **Partially correct.** Title text does cross into the internal agent verbatim, but is rendered as data. Not the solve. |
| 2 | Inner-node request forgery | **Closest to correct.** There was an inner node and it was reached — but by standing escalation and a filesystem write, not by controlling a forwarded field. |
| 3 | Authorization framing | **Not needed.** No persuasion was involved at any point. |
| 4 | Schema/validator bypass | **Wrong target.** The validator that mattered was the `archive` destination allowlist, and it was satisfied legitimately — `/opt/petitions` was permitted by design. |
| 5 | Subject-number IDOR | **Correct and load-bearing.** `cp_session` = plaintext SN meant a leaked number was a wearable session. This was the `citizen` → `qa` escalation. |

**What the scenario text actually meant, in hindsight:** *"strict formatting of the agents"* was the `archive` destination requiring a file path rather than a directory — not a submission schema. *"Slip past their logic"* was composing two agents' partial privileges, not evading a filter.

### Next actions
Target solved. These are unexplored and worth a return visit before the instance expires.

1. **`/var/drop`** — named in the archive allowlist alongside `/tmp` and the two known stores, never investigated. [Speculation] a second intended solution path, or a drop location another component reads.
2. **`/tmp`** — same, also permitted as an archive destination.
3. Whether `archive` can read *out* of arbitrary paths as well as write to them — only `id` → known case was tested.
4. The raw-control-character serialization defect in agent responses — never probed as a vector.
5. `PET-1009` / `PET-1010` injection payloads were filed but their labels never checked; the newline-survives-the-title question is unresolved.

**Out of scope, do not revisit:** other ports on `154.57.164.68`. Range 30000–32767 is Kubernetes NodePort; PTR `154-57-164-68.static.isp.htb.systems`. The ~180 open ports are other tenants' instances.

## Cross-references
- [[CA2026-AI-LLM-category-kickoff]]
- [[HTB-CA2026-Obligation-Indexer-Stored-Dossier-Injection]]
- [[HTB-CA2026-Memento-Skill-Persistence-Memory-Poisoning]]
- [[HTB-CA2026-Forked-Tongue-Tokenizer-Vocab-Merges-Divergence]]
- [[HTB]]

## Change Log
- 2026-07-25 — Note created as intake/handoff scaffold. Scenario captured, intake checklist and ranked hypotheses drafted from scenario text alone, recon plan and carried method recorded. No contact with the target yet; every hypothesis labelled [Speculation].
- 2026-07-25 — First contact with target. Findings section populated from live probe output: Next.js surface fully mapped (single route handler, plaintext `cp_session`), Docket Agent A2A vhost discovered and characterised (no auth, sequential petition IDs, 1/5s rate limit). Intake checklist answered. Hypothesis 5 upgraded to primary escalation path; hypothesis 1 remains primary attack path. Process lesson recorded: the given Subject Number was present in this note's Scenario section from creation and went unused for ~10 turns of futile login enumeration.
- 2026-07-25 — **Solved.** Flag `HTB{w3lc0m3_t0_a2a_pr0t0c0l_t4g_t34m_pwn4g3}`. Escalated `citizen` → `qa` via `SN-7731-0425` leaked in the PET-1000 QA fixture body; that standing revealed the Casework Agent (`dev-a1f4c39b`) and the `/opt/cases/archived` + `/opt/petitions` paths. Solved by confused deputy: `archive CASE-SEAL0001 → /opt/petitions/seal.json`, then read back through the Docket agent as petition `seal.json`. Findings restructured with solve chain, Casework card, and the PET→CASE label pass-through (real but not the solve path). Hypothesis table finalised; remaining threads (`/var/drop`, `/tmp`, archive read-out) recorded. `status: draft → complete`. Operational error logged: a probe framed as read-only mutated verdicts on five cases.
