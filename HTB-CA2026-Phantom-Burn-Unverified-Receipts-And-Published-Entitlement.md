---
title: "HTB CA2026 — Phantom Burn: A Verifier That Verified Nothing, Over a Chain That Published the Credential"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Phantom burn
app: "core_application — Solidity ShardRegistry with two Node/TypeScript services (public app console, archive service)"
category: secure-coding
difficulty: hard
points: 975
type: writeup
status: complete
mitre:
  - T1190
  - T1552.001
tags:
  - writeup
  - HTB
  - Security
  - Secure_Coding
  - Blockchain
  - authorization
  - code-review
related:
  - "[[HTB-CA2026-Hollow-Courier-XFF-Hop-Count-Trust-Boundary]]"
aliases:
  - Phantom Burn
  - CA2026 Phantom Burn
created: 2026-07-27T14:40:24.347Z
updated: 2026-07-27T14:40:24.347Z
---

# Phantom Burn — A Verifier That Verified Nothing, Over a Chain That Published the Credential

> [!success] Solved — 2026-07-27 10:38
> Flag: `HTB{gh0st_t0uching_sh4rds_8f87779588c1b2aa11290570e7814251}`
> PR #17 accepted — **hard 60/60 · code quality 14 · security reasoning 14 · patch correctness 8** (soft 36/40).
> Fourth **secure-coding** solve, and the first `hard` one. `hard` · 975 points.
> **Seventeen pull requests across seven distinct patches.** No single submission was close; each rejection named exactly one more layer.

> [!note] Credential values (passwords, access keys, credential hashes) are truncated for publication.

> [!info] Scenario, verbatim
> Caldrin Vowmark receives an Ash-Vault receipt that passes every local check, although no rightful keeper issued it. A sealed source transfer begins when the next burn is finalised. If the receipt is accepted first, the hidden hand gains the Ash-Vault's source bundle and can manufacture more receipts that appear lawful to every Eastreach verifier. Caldrin must discover how the counterfeit survives the weighing, stop the transfer, restore the witness chain, and preserve one legitimate owner unlock.

## 0. How the flag was obtained

1. Cloned into a **named** directory — the third room this event to clone as `core_application`, after Withered Registry and Hollow Courier.
2. Polled `curl /flag` and `/pulls` before reading source: `0/60`, no existing PRs. Clean instance, so the first push would be the increment the grader sees.
3. Read `verifyReceipt` in `archive-service/src/chainReceipt.ts`. It takes `_config` and `_principal`, discards both, checks three fields `startsWith("0x")`, and returns `ok: true`. **No chain access at all.**
4. Grepped for consumers of `ArchiveConfig`: `rpcUrl`, `registryAddress` and `confirmations` appear only in `config.ts`. A verifier handed an RPC URL that never opens a socket.
5. Stood up anvil + both services locally and posted `{"txHash":"0xdeadbeef","registry":"0xcafebabe","shardId":"0xfeedface"}`. Returned `opened: true` with `source:read` — **while no registry was deployed at all**.
6. Deployed an attacker contract emitting a byte-identical `ShardFiled` event; `app/src/sourceVault.ts` accepted it, because nothing compared `log.address` to the configured registry.
7. Submitted seven patches over seventeen PRs, each answering the previous rejection verbatim (§5).
8. PR #17 cleared the soft gate and all three hard stages; `curl /flag` returned the flag.

## 1. Shape of the challenge

Patch-and-submit against an automated reviewer, like both prior secure-coding rooms — but hybrid where they were single-language.

```
phantom_burn/
|-- contracts/          Foundry: ShardRegistry, ReceiptVerifier, tests
|-- app/                public Node/TS console + /api surfaces (Postgres)
|-- archive-service/    Node/TS archive gate
|-- tools/              deploy and offline unlock helpers
`-- db/schema.sql       operator directory
```

Two gates, as before: hard **60/60** (build · functionality · security), soft **≥28/40** with per-objective floors of 12/12/6. The hard stage is itself three sub-stages, and its output names the failing one — the single most useful diagnostic in the room:

```
[+] STAGE 1: STATIC ANALYSIS PASSED!
[+] STAGE 2: ENDPOINTS HAVE BEEN TESTED AND CONFIRMED WORKING!
[-] STAGE 3: public chain log data can still unlock the archive source bundle.
```

**What made it `hard` was not the bug — it was that there were five of them, layered, and the reviewer revealed one at a time.** Withered Registry and Hollow Courier each had one defect and one correct shape of fix. Here, every patch that closed a real defect was rejected for the next one down.

## 2. The five defects

Each was genuine, and closing any one alone left the bundle reachable.

| # | Defect | Where |
|---|---|---|
| 1 | `verifyReceipt` performs no verification — no chain access, config discarded | `archive-service/src/chainReceipt.ts` |
| 2 | `resolveFiling` decodes any log matching the event signature; `?? logs[0]` fallback; `log.address` never checked | `app/src/sourceVault.ts` |
| 3 | Grants and responses assembled from request-body fields that were compared against the log rather than read from it | both `routes.ts` |
| 4 | The bundle token is an unkeyed digest of values the chain publishes; `SOURCE_BUNDLE_SIGNING_KEY` appears only in the README | `app/src/sourceVault.ts` |
| 5 | **`ShardRegistry` publishes the entitlement.** `unlockSeal = keccak256(abi.encodePacked("PHANTOM_BURN_ARCHIVE:", archiveKey))`, emitted in `ShardFiled` and returned by `shardOf()` | `contracts/src/ShardRegistry.sol` |

Defect 5 is the room's actual subject and the last one found. Everything above it can be fixed perfectly and the counterfeit still survives, because *the credential was broadcast before any request arrived*. That is the scenario's *"manufacture more receipts that appear lawful to every Eastreach verifier"*, stated in code.

**The unused-configuration tell.** The fastest route to defect 1 was not reading the verifier but grepping its config: three values loaded, none consumed. Same shape as Withered Registry's comments-that-document-an-unenforced-invariant, one level up — configuration describing a control the code does not implement.

**The regression-noise tell.** `contracts/test/ShardRegistry.t.sol` shipped `testUnlockSealIsPublicRegressionNoise`, asserting the seal equalled `keccak256(abi.encodePacked("PHANTOM_BURN_ARCHIVE:", key))`. It pinned defect 5 in place, and *"RegressionNoise"* in the name is the author saying so. **A test that asserts the vulnerable property is part of the vulnerability.**

## 3. The accepted patch

Ten files, +405/−51.

**Chain.** The seal commits to the filing and to nothing else:

```solidity
bytes32 unlockSeal =
    keccak256(abi.encode("PHANTOM_BURN_ARCHIVE", address(this), msg.sender, shardId, nonce));
```

`archiveKey` never reaches the chain in any form. The event shape is preserved — `ShardFiled` still carries five fields and `shardOf()` returns the same struct — so only the *meaning* of the seal changes, from secret to metadata.

**Verification.** A receipt names a transaction and a log position, nothing else. There is no caller-declared registry: the trusted origin is `config.registryAddress`, and `log.address` is the only evidence of who emitted a filing. The exact `logIndex` is used with no fallback; `ShardFiled` is decoded strictly; every response and grant is built from decoded values; confirmation depth comes from `ARCHIVE_CONFIRMATIONS`.

**Identity and consumption.** `receiptId` is computed from chain-verified properties only — emitting address, transaction hash, block hash, log position — so two requests naming the same event collapse to one identity however they were phrased. The app claims it durably:

```sql
INSERT INTO consumed_receipts (receipt_id) VALUES ($1) ON CONFLICT DO NOTHING
```

The insert *is* the lock, so check and claim cannot race, and a conflicting row is exactly a replay — across restarts and instances.

**Token.** HMAC under `SOURCE_BUNDLE_SIGNING_KEY` over filing metadata, each field length-prefixed. Where no key is configured an ephemeral one is generated at startup; issued tokens are process-scoped already, so this costs nothing and never leaves the service deriving credentials from public data.

## 4. Falsified leads

Four hypotheses cost real attempts. Three were rejected by the grader in terms worth keeping.

**Confirmations depth.** `ARCHIVE_CONFIRMATIONS` defaults to 12 and PR #5 enforced it. Predicted as the likeliest functionality break at 50/60. **Wrong** — Stage 2 passed on every submission that reached it, and the hard-stage output said so explicitly. Cost: nothing, because the diagnostic was read before acting.

**The archive-key preimage.** PR #7 required the caller to submit `archiveKey` so the service could open the commitment. Reasoning: a commitment exists to be opened, and the key is the only unpublished value. Rejected at 12/10/4 — *"reintroduces trust in caller-supplied secret material and changes the intended receipt flow semantics."* **A secret travelling in the request is not proof of anything; it is one more thing to steal.**

**Session-gating the API.** PR #10 put `requireOperator` on `/api/source/unlock` and `/api/source/bundle`, the only two routes lacking it. Not rejected on that basis — the bot called it *"a strong move back toward provenance-based verification"* — but it wasn't the answer, and it was dropped from later patches to keep the diff narrow.

**"The contracts are unchanged and unambiguous."** Written into PR #3's commit message as a deliberate scope decision. Wrong twice: the contract held the deciding defect, and even after binding the seal to the filing, anything published that is derived from a secret is still entitlement material.

## 5. Seventeen pull requests

The grader is a bisection instrument, not a pass/fail oracle. Each rejection named exactly one layer.

| PR | Patch | Soft | Verdict, in its own words |
|---|---|---|---|
| #1 | Chain verification on both paths | 13/12/**5** | *"one authorization path still returns decisions using request-body fields instead of values derived from the verified log"* |
| #3 | Receipt → pointer; decoded grants; HMAC token | 14/**11**/**5** | *"the on-chain side still emits/stores entitlement-like material publicly … move to commitment/metadata-only chain outputs"* |
| #5 | Seal → filing-bound commitment | 14/14/9 **accepted** | hard **50/60** — *"STAGE 3: public chain log data can still unlock the archive source bundle"* |
| #7 | Require `archiveKey` preimage | 12/10/**4** | *"reintroduces trust in caller-supplied secret material"* |
| #10 | Session guard on `/api/source/*` | — | *"still depends on a caller-declared context value … no clear one-time receipt identity derived solely from verified on-chain values"* |
| #15 | Registry dropped; identity from log; app-side consumption | 14/11/5 | *"still publishes a value that acts like portable entitlement material … app-side consumption is in-memory only"* |
| **#17** | Seal drops `archiveKey`; Postgres claim | **14/14/8** | **accepted · hard 60/60** |

Even-numbered PRs are deliberate baseline resets. **Increment-scoped review, established in Hollow Courier, applies here unchanged** — PR #2's reset scored 6/3/1 in isolation, confirming the model outright. Every real submission therefore cost two pushes: one to restore `main`'s tree, one to land the complete patch.

**Patch correctness was the weakest objective on every single submission** — 5, 5, 9, 4, 5, 8 — against 12–14 on the other two throughout. Three rooms now, same pattern, and the same rule held every time: when it lags while the others sit comfortably, the design is wrong and rewriting the justification will not move it.

## 6. Local verification

The instance is not reachable from the analysis sandbox and exposes no RPC — anvil lives on `127.0.0.1:8545` inside the container, so the Stage 3 attack could not be replayed by hand. Everything was proven against a faithful local stack instead.

Foundry and `solc 0.8.26` came from **GitHub releases**; the usual installer hosts are outside the allowlist but `github.com` is not, so `solc` was pinned with `--use` rather than fetched by Forge. npm registry is reachable, so both services installed from their committed lockfiles and ran against a local anvil with the contracts deployed from patched source, one legitimate filing, and an attacker contract emitting a byte-identical `ShardFiled`.

The decisive local result, and the one that generalises: **a receipt claiming a different owner, shard and nonce over the same pointer returns `409 already consumed`** rather than minting a second grant — proof that identity is anchored to the event and the descriptive fields are genuinely ignored.

## 7. Final payload

There is no exploit script; the deliverable is the patch. Full source: `phantom-burn-fix-v7.patch`.

```bash
curl -s http://[IP]:[PORT]/flag | jq          # scorecard, before passing
curl -s http://[IP]:[PORT]/pulls              # existing attempts

cd HTB_CA2026 && git clone http://htb_developer:HT…rd@[IP]:[PORT]/git/core_application.git phantom-burn
cd phantom-burn

# every submission: reset, then the complete patch
git restore --source=origin/main --staged --worktree -- phantom_burn/
git commit -m "Reset to the reviewed baseline before resubmitting a single complete patch"
git push origin developer

git apply ../phantom-burn-fix-v7.patch
git add phantom_burn/
git diff --cached --stat                      # 10 files, 405 insertions(+), 51 deletions(-)
cd phantom_burn && npm run build && npm test; cd ..
git commit -F ../phantom-burn-commit-message-v7.txt
git log -1 --stat                             # -F fails silently on a bad path
git push origin developer

sleep 120
curl -s http://[IP]:[PORT]/pulls/17 | sed 's/<[^>]*>//g' | grep -A8 'TESTING RESULTS'
curl -s http://[IP]:[PORT]/flag | jq
```

Reading the hard-stage output needs tag stripping and entity unescaping; a naive `grep` returns the rendered diff instead:

```bash
curl -s http://[IP]:[PORT]/pulls/N | python3 -c "
import sys,html,re
t=html.unescape(re.sub(r'<[^>]+>','\n',sys.stdin.read()))
i=t.find('Review Activity'); print(t[i:i+1200] if i>=0 else 'none')
"
```

## 8. Tools & techniques

`git` (rev-range analysis, `git restore --source`, reset-then-patch submissions) · `forge` / `cast` / `anvil` · `solc` 0.8.26 pinned from GitHub releases · `npm ci` from committed lockfiles · Node 22 · `curl` · `python3` for HTML entity handling

Concepts: verification functions that discard their configuration · event-signature decoding without emitter binding · request-body values standing in for verified state · replay keys derived from caller input · unkeyed digests of public data used as bearer credentials · commitments that must contain no key material · durable one-time claims via `INSERT … ON CONFLICT` · increment-scoped automated review

## 9. MITRE ATT&CK

- **T1190** Exploit Public-Facing Application — the archive and unlock endpoints are the whole attack surface; no credential or access-control bypass was required
- **T1552.001** Unsecured Credentials: Credentials In Files — the closest technique to *"the registry broadcasts the entitlement in an event"*, which is a public ledger rather than a file

> [!warning] Honest scope of this mapping — verify the IDs before trusting them
> **Both were assigned without access to the live ATT&CK matrix and are unverified.** T1552.001 is a stretch: the credential is not in a file, it is in a blockchain event log, and ATT&CK has no technique for that.
>
> ATT&CK describes adversary behaviour against deployed systems and maps poorly onto *"the verifier never called the chain"* or *"the contract published the secret."* **Cite the source-level taxonomies first for this class of room:**
> - **OWASP A01:2021** Broken Access Control — the unlock decision established that a filing existed, never that the caller was entitled to it
> - **CWE-345** Insufficient Verification of Data Authenticity — the receipt was accepted on shape alone
> - **CWE-346** Origin Validation Error — any contract's `ShardFiled` was decoded as genuine
> - **CWE-522** Insufficiently Protected Credentials — the seal and the unkeyed token
> - **CWE-294** Authentication Bypass by Capture-replay — identity keyed on request fields, consumption in process memory

## 10. Detection / blue-team & fix notes

- **Grep for loaded-and-unused configuration.** A service that reads an RPC URL, a contract address and a confirmation depth and consumes none of them has a verifier that does not verify. This was the fastest path to the primary defect and it is mechanical: enumerate every config field and find its readers.
- **Decoding an event proves nothing about who emitted it.** Any contract can emit any signature. `log.address` against a configured, trusted address is the check; ABI decoding is not.
- **Never let a request field stand in for verified state.** Comparing a caller-supplied value to a verified one is weaker than not accepting it at all — the difference between validating input and removing the input, which is the same lesson Withered Registry's accepted patch turned on.
- **A published value derived from a secret is entitlement material, however it is bound.** Binding stops portability; it does not stop disclosure. On-chain outputs should be commitments to metadata, with key material never reaching the chain in any form.
- **Keying a digest does not fix public inputs.** An HMAC over values the chain publishes stops third parties computing the output; it does not stop those values being the wrong basis for a decision.
- **Replay keys must be derived from verified state.** Identity built from request fields means two phrasings of one event are two receipts. Anchor to emitter, transaction, block and log position.
- **One-time semantics need durable storage.** A process-local `Set` fails on restart and shares nothing across instances. `INSERT … ON CONFLICT DO NOTHING` makes the claim atomic and the storage the lock.
- **A test that asserts the vulnerable property is part of the vulnerability.** Regression suites can pin defects in place; changing one is legitimate, and the change must be argued in the commit message.
- **Detection.** Alert on archive-grant responses whose fields do not match the referenced log, on repeated grants against one filing, and on any unlock served for a filing whose transaction is shallower than the configured confirmation depth.

## 11. Method notes

- **Read the hard-stage output before theorising.** At 50/60 the confirmations depth was the obvious suspect; the output said `STAGE 2 CONFIRMED WORKING`, which eliminated it for free. Two pushes saved by reading rather than guessing.
- **Poll `/flag` after every attempt — and wait.** Hard scoring wrote `0 → 50` across two polls, and several early readings were of the reset push rather than the real one. `sleep 90` and pair the number with a PR verdict before drawing conclusions.
- **Each rejection is a bisection step.** Seven patches, each closing something real, each revealing the next layer. In a room with layered defects the grader is the only instrument that can see them all — treat a rejection as information rather than failure.
- **Increment-scoped review costs two pushes per submission.** Established in Hollow Courier, reconfirmed here by PR #2's reset scoring 6/3/1 in isolation. Budget for it.
- **Assertions in a commit message are graded.** PR #3's *"the contracts are deliberately unchanged and unambiguous"* was a wrong claim in the artifact the reviewer reads most closely. A later message also carried a stale paragraph contradicting its own diff — the Hollow Courier failure repeated.
- **Verifying an artifact is not shipping it.** Three separate times a patch was built and verified in the sandbox and never handed over, costing the operator time on errors from a stale file. **Confirm the artifact in the operator's hands is the one that was tested.**
- **Clone into named directories.** Three rooms this event clone as `core_application`; a stale one caused a `git fetch` against a dead remote and a near-miss analysis of the wrong application.

## 12. Open items

- **`points: 975`** is from the scenario page at solve time and drifts under dynamic scoring. Re-read before treating as authoritative.
- **`solves` not captured.** Omitted rather than guessed.
- **Both ATT&CK IDs unverified** — see §9. The CWE and OWASP entries are the defensible classification.
- **PRs #11–#14 were submitted but their verdicts were never read.** The table in §5 covers the seven that were. Whether those four contained feedback not represented here is unknown.
- **The archive service keeps in-memory consumption.** It has no datastore; only the app path was made durable. The accepted patch says so explicitly, and the grader did not object — but it is a real remaining weakness in a multi-instance deployment.
- **`/api/shards/recent` returns 500** on any chain with filings: it serialises a `bigint` `nonce` through `res.json`. Pre-existing, present on unpatched `main`, never exercised by the harness, and deliberately left alone to keep the diff narrow.
- **Session-gating the `/api/source/*` routes was dropped** after PR #10. It was never rejected on its merits and may be correct hardening; it was removed to keep the submitted diff minimal.

## Cross-references
- [[HTB-CA2026-Hollow-Courier-XFF-Hop-Count-Trust-Boundary]]
- [[HTB-CA2026-Withered-Registry-Broken-Access-Control-Privileged-Write]]
- [[HTB-CA2026-Wrong-Stamp-CloudTrail-Credential-Reuse-Log-Disablement]]
- [[HTB-CA2026-Caldrins-Day-Away-Stamped-Oracle-Spot-Reserve-Manipulation]]

## Change Log
- 2026-07-27 — Note created. First `hard` secure-coding solve, accepted at PR #17 with hard 60/60 and soft 36/40 after seven distinct patches across seventeen pull requests. Records five layered defects — a verifier that discarded its own configuration and never contacted the chain, event decoding without emitter binding, grants assembled from request fields, an unkeyed token over public values, and a registry that published the entitlement itself — together with the verbatim grader verdict that revealed each. Documents the three falsified leads (confirmations depth, the caller-supplied archive-key preimage, session-gating) with the reasoning that produced them, since two were acted on before being disproved. Confirms increment-scoped review a second time: PR #2's baseline reset scored 6/3/1 in isolation.
