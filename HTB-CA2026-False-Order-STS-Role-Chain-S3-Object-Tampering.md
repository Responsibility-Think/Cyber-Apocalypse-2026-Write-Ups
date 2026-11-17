---
title: "HTB CA2026 — False Order: A Role Chain That Signed Itself With the Victim's Name"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: False Order
app: LocalStack AWS emulation (CloudTrail, S3 versioning, STS, IAM)
category: cloud
difficulty: medium
points: 1000
type: writeup
status: complete
mitre:
  - T1078.004
  - T1548.005
  - T1565.001
  - T1485
  - T1036
tags:
  - writeup
  - HTB
  - Cloud
  - Security
  - DFIR
  - Incident_Response
  - Log_Analysis
  - aws
  - cloudtrail
  - anti-forensics
related:
  - "[[HTB-CA2026-Wrong-Stamp-CloudTrail-Credential-Reuse-Log-Disablement]]"
aliases:
  - False Order
  - CA2026 False Order
created: 2026-07-26T16:45:16.902Z
updated: 2026-07-26T16:45:16.902Z
---

# False Order — A Role Chain That Signed Itself With the Victim's Name

> [!success] Solved
> Twelve graded short-answer questions, no `HTB{}` string. Ephemeral LocalStack instance `154.57.164.72` — briefing `:31839`, AWS API `:31274`.
> Third CA2026 cloud room and the second on this harness. The [[HTB-CA2026-Wrong-Stamp-CloudTrail-Credential-Reuse-Log-Disablement]] collection pattern transferred directly; total working time was a fraction of that room's.

> [!note] Credential values (passwords, access keys, credential hashes) are truncated for publication.

## 0. How the answers were obtained

1. Fingerprinted the two unlabelled ports (AWS API answers a bare `GET` with `AccessDeniedException` JSON; briefing answers with HTML).
2. Probed the access envelope — **and the probe lied** (§3). Both CloudTrail *and* S3 were readable; `describe-trails` / `get-trail-status` were the only denials.
3. Drained `LookupEvents` through `NextToken` — 651 events — and passed each `.CloudTrailEvent` through `jq`'s `fromjson`.
4. Listed **object versions**, not just objects. The tampered key has three entries: an original, a delete marker, and a replacement, seven seconds apart.
5. Segregated four populations by source IP: legitimate gatehouse, attacker, container provisioning, and other players' harness noise (§4).
6. Isolated the attack burst — 10 events in ~700 ms — and read `requestParameters` on each rather than trusting the flattened timeline.
7. Found **three** `AssumeRole` events naming **two different roles**. That distinction is the one that decides Q5 vs Q9, and getting it backwards is the room's main trap (§6).
8. Answered all twelve off the frozen local `events.json` plus the S3 version listing.

## 1. Shape of the challenge

Pure forensics — nothing to exploit. The briefing is unusually generous compared with Wrong Stamp: it names the trail (`coalition-gate-audit-trail`), the bucket (`ashguard-order-custody`), the starting key (`custody/east-gate-order.json`), and states the method outright:

> *"Begin with `custody/east-gate-order.json`, then correlate its version history with the audit events."*

That sentence is the whole room. Two evidence stores, and the answer lives in the join between them.

**Narrative mapping.** The "sealed order" is an S3 object. "Garran's orders carry small marks that copyists miss" is the version history — the original object still exists behind the delete marker. The "copyist" is `seal-copyist-contractor`, and the forged seal is the `roleSessionName` (§7).

## 2. Access envelope

| Call | Result |
|---|---|
| `cloudtrail lookup-events` | **OK** |
| `cloudtrail describe-trails` | DENIED |
| `cloudtrail get-trail-status` | DENIED |
| `s3api list-objects-v2` | **OK** |
| `s3api list-object-versions` | **OK** |
| `s3api get-object` (incl. `--version-id`) | **OK** |
| `iam list-users` | **OK** |

Materially wider than Wrong Stamp, where `LookupEvents` was the *only* grant. Here the S3 side is fully readable, which is what makes the version-history correlation possible.

## 3. The probe that lied — a zsh trap worth internalising

The envelope probe was written as:

```bash
for c in "cloudtrail lookup-events --max-results 1" "s3api list-objects-v2 --bucket X"; do
  aws $c >/dev/null 2>&1 && echo OK || echo DENIED     # WRONG in zsh
done
```

**In bash, `$c` word-splits; in zsh it does not.** Every command ran as `aws "cloudtrail lookup-events --max-results 1"` — a single invalid argument — exited non-zero, and printed `DENIED`. All seven probes reported DENIED. The very next command in the same session then pulled 651 CloudTrail events and the full S3 version listing.

Correct form:

```bash
while IFS= read -r c; do
  printf '%-72s ' "$c"; eval "aws $c" >/dev/null 2>&1 && echo OK || echo DENIED
done <<'EOF'
cloudtrail lookup-events --max-results 1
s3api list-object-versions --bucket ashguard-order-custody --max-keys 3
EOF
```

> [!warning] This is not a cosmetic bug
> A permission probe that reports false negatives will send you down an entirely wrong path — and unlike a crash, it fails silently and plausibly. Any probe loop must be validated against a call you *know* succeeds before its output is trusted.

## 4. Four populations

651 events, and only 16 of them matter.

| Population | Source IP | Identity | Nature |
|---|---|---|---|
| Gatehouse baseline | `10.41.53.22` | `user/coalition-gate-clerk` | ~600 events, 07-22 → 07-26T10:38, minutes apart. Read-only S3: `ListObjectsV2`, `HeadObject`, `GetObject`, `GetBucketVersioning` |
| **Attacker** | `198.18.44.91` | `user/seal-copyist-contractor` → assumed role | Recon 10:39–13:19, then a 700 ms burst at 13:38:04 |
| Provisioning | `127.0.0.1` | `root` | `StopLogging`(fail) → `CreateTrail` → `CreateUser` → `CreateAccessKey`. Container standing itself up |
| Harness noise | `10.244.x.x` and assorted public IPs | `root` | `Unknown` / `POSTRequest` with `AccessDeniedException`, from 14:06 onward — **other players' instances**, after our seed data was written |

**`198.18.44.91` is RFC 2544 benchmark space** — reserved for network device testing, never routable on the public internet. Same convention as Wrong Stamp's `192.0.2.55` (TEST-NET-1). The generator marks its attacker with a deliberately non-routable address.

> [!note] Anything after 13:38:24 is not evidence
> The `10.244.x.x` events are Flannel pod addresses from the shared Kubernetes cluster. They post-date the scenario entirely and are noise from other players working the same challenge. Cutting the timeline at the provisioning block's end removes ~40 distracting events.

## 5. The tampered object — version history

```
13:37:58   429 bytes   0038e8b0-e3db-456d-8183-80877f14682a   ← ORIGINAL
13:38:05   DELMARK     66de840a-1f62-4171-9309-6e7d803d94d6   ← DeleteObject
13:38:05   436 bytes   adc3d385-1335-47e1-b2ef-bd6f3fb6843e   ← FORGED (PutObject)
```

`13:37:58` is shared by **every other object in the bucket** — that is the seed batch. The delete marker and the 436-byte replacement land seven seconds later, alone. Larger file, later write, immediately following a deletion: that is the replacement, and the 429-byte version is Garran's real order.

```bash
aws s3api get-object --bucket ashguard-order-custody --key custody/east-gate-order.json \
  --version-id 0038e8b0-e3db-456d-8183-80877f14682a original.json
aws s3api get-object --bucket ashguard-order-custody --key custody/east-gate-order.json \
  --version-id adc3d385-1335-47e1-b2ef-bd6f3fb6843e forged.json
diff <(jq -S . original.json) <(jq -S . forged.json)
```

**The delete marker is what makes this recoverable.** `DeleteObject` on a versioned bucket does not destroy anything — it writes a tombstone and hides the current version. The original is one `--version-id` away, which is the same mechanic that broke [[HTB-CA2026-Bought-Riot-AssumeRole-ExternalId-Chain-PARTIAL]] open at its first hop.

## 6. Three AssumeRole calls, two roles — the trap

The flattened timeline shows `AssumeRole AccessDenied` then `AssumeRole OK` and invites the assumption that they target the same role. They do not.

| Time | Result | `roleArn` | `roleSessionName` |
|---|---|---|---|
| `12:14:35.583` | ❌ AccessDenied | `role/ashguard-order-`**`auditor`** | `seal-copyist-session` |
| `13:38:04.896` | ❌ AccessDenied | `role/ashguard-order-`**`auditor`** | `coalition-gate-clerk` |
| `13:38:04.911` | ✅ OK | `role/ashguard-order-`**`scanner`** | `coalition-gate-clerk` |

The attacker probed the **auditor** role twice — once during recon 84 minutes earlier, once inside the burst — was denied both times, then pivoted to the **scanner** role and succeeded on the next call, 15 ms later.

**Reading the successful session ARN backwards gives the right answer to the wrong question.** `assumed-role/ashguard-order-scanner/coalition-gate-clerk` decomposes to scanner + clerk, which answers Q5 and Q10 — but Q9 asks for the role that *failed*, and that name appears nowhere in the session ARN. It is only in `requestParameters.roleArn` on the denied events.

Corroboration across the dataset:

```bash
grep -oE 'role/[A-Za-z0-9_+=,.@-]+' events.json | sort | uniq -c | sort -rn
#   11 role/ashguard-order-scanner
#    4 role/ashguard-order-auditor
```

> [!important] LocalStack populates `requestParameters` inconsistently
> The `12:14:35` event is `eventVersion 1.11` with a terse `errorMessage` ("An error occurred (AccessDenied) when calling the operation") and `resources: null`. The `13:38:04` events are `eventVersion 1.08` with a full AWS-style message naming the target ARN, and populated `resources[]`. Same emulator, same run, different fidelity. Dump whole events (`jq '.[] | select(...)'`) rather than projecting fields, or a `null` will read as a wrong answer rather than a missing one.

## 7. The forged seal is the `roleSessionName`

The attacker set `roleSessionName: coalition-gate-clerk` — **the legitimate gatehouse clerk's own IAM username**.

Every downstream event therefore carries:

```
arn:aws:sts::638291047582:assumed-role/ashguard-order-scanner/coalition-gate-clerk
```

Any dashboard, alert, or log view that renders the assumed-role ARN and stops there attributes the `DeleteObject` and `PutObject` to the clerk. The actual caller — `seal-copyist-contractor` — appears only on the `AssumeRole` event itself, one hop earlier.

**That is Caldrin's false seal, expressed in IAM.** The narrative's "small marks that copyists miss" is the fact that `roleSessionName` is a caller-supplied free-text string with no validation whatsoever. AWS will happily let you label your session with someone else's username.

## 8. Final payload

```bash
# The attack burst, in full
jq '.[] | select(.sourceIPAddress=="198.18.44.91")
  | {t:.eventTime, ev:.eventName, err:(.errorCode//"OK"),
     arn:.userIdentity.arn, req:.requestParameters}' events.json

# All AssumeRole events — whole objects, not projections
jq '.[] | select(.eventName=="AssumeRole")' events.json

# The destructive pair
jq '.[] | select(.eventName=="DeleteObject" or .eventName=="PutObject")
  | {t:.eventTime, ev:.eventName, arn:.userIdentity.arn, req:.requestParameters}' events.json

# Population split
jq -r '.[] | [.sourceIPAddress, (.userIdentity.arn // .userIdentity.type)] | @tsv' events.json \
  | sort | uniq -c | sort -rn
```

**The twelve submitted answers:**

| # | Question | Answer |
|---|---|---|
| 1 | Last action from internal gatehouse IP before attacker session | `ListObjectsV2` |
| 2 | First action from attacker IP | `GetCallerIdentity` |
| 3 | S3 action explicitly denied before role assumption | `GetObject` |
| 4 | Full S3 path of the tampered object | `s3://ashguard-order-custody/custody/east-gate-order.json` |
| 5 | Role assumed for the destructive session | `arn:aws:iam::638291047582:role/ashguard-order-scanner` |
| 6 | Full STS principal ARN on `DeleteObject` | `arn:aws:sts::638291047582:assumed-role/ashguard-order-scanner/coalition-gate-clerk` |
| 7 | IP of the AssumeRole and destructive calls | `198.18.44.91` |
| 8 | IAM username owning the long-lived credentials | `seal-copyist-contractor` |
| 9 | Role name that failed to assume | `ashguard-order-auditor` |
| 10 | `roleSessionName` on the successful AssumeRole | `coalition-gate-clerk` |
| 11 | `errorCode` on the denied `GetObject` probe | `AccessDenied` |
| 12 | Action marking the forged ledger upload | `PutObject` |

Supporting identifiers:

- Attacker access key `AKIA…T88P` — identical across all three `AssumeRole` calls
- Temporary key issued by the successful assume: `ASIA…IT7L`, `assumedRoleId` `AROAKQ08OJ1KG8CR7ZCK:coalition-gate-clerk`
- Account `638291047582`; attack window `13:38:04.595Z` → `13:38:05.309Z`
- `eventID` of the successful assume: `830fa02f-8dd2-4524-bd54-ea513d511b70`

## 9. Tools & techniques
AWS CLI v2 against a LocalStack endpoint · `cloudtrail lookup-events` with `NextToken` pagination · `s3api list-object-versions` and `get-object --version-id` · `jq` (`fromjson`, `unique_by`, `@tsv`) · `grep -oE` for ARN frequency counts across the raw event corpus
Concepts: STS role-chain reconstruction · `roleSessionName` impersonation · S3 delete-marker recovery · two-store correlation (audit log × object version history) · separating four traffic populations by source IP · emulator `eventVersion` inconsistency as an analysis hazard

## 10. MITRE ATT&CK
- **T1078.004** Valid Accounts: Cloud Accounts — `seal-copyist-contractor` long-lived key as the entry credential
- **T1548.005** Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access — `AssumeRole` into `ashguard-order-scanner` after being denied `ashguard-order-auditor`
- **T1565.001** Data Manipulation: Stored Data Manipulation — the order object replaced with a forged version
- **T1485** Data Destruction — `DeleteObject` against the custody record
- **T1036** Masquerading — `roleSessionName` set to the victim clerk's username so the session ARN misattributes the action

> [!note] Honest scope of this mapping
> T-codes are inferred from the observed API calls and were not re-verified against the live ATT&CK matrix. `T1036` is used at the parent level because no sub-technique cleanly covers "session-name impersonation"; `T1036.005` (Match Legitimate Name or Location) is the closest and is arguable.

## 11. Detection / blue-team & fix notes
- **Alert on `roleSessionName` that matches an existing IAM principal name.** It is caller-supplied and unvalidated, and a session named after a real user is either sloppy automation or deliberate misattribution. This is cheap to implement and there is no legitimate reason for it.

  ```sql
  SELECT e.eventtime, e.useridentity.username AS real_caller,
         e.requestparameters
  FROM cloudtrail_logs e
  WHERE e.eventname = 'AssumeRole'
    AND regexp_extract(e.requestparameters, '"roleSessionName":"([^"]+)"', 1)
        IN (SELECT username FROM iam_users)
    AND regexp_extract(e.requestparameters, '"roleSessionName":"([^"]+)"', 1)
        <> e.useridentity.username;
  ```

- **Never attribute from the assumed-role ARN alone.** `assumed-role/<role>/<session>` contains no authoritative caller identity. Always join back to the `AssumeRole` event on `responseElements.credentials.accessKeyId` to recover who actually called it. Any SIEM dashboard that shows only the session ARN is trivially spoofable by the attacker choosing the session name.
- **A denied `AssumeRole` followed within seconds by a successful one against a different role is a role-enumeration signature.** Individually both are unremarkable; the pair, ordered and close in time from one principal, is high-fidelity. Alert on it.
- **`DeleteObject` + `PutObject` on the same key inside one second** is object replacement, not two independent operations. On a custody or evidence bucket that pattern should page.
- **Fixes, in order of value:** MFA-delete and Object Lock (governance or compliance mode) on custody buckets — either would have blocked the delete outright. Then S3 Versioning retention so tombstoned versions cannot be lifecycle-expired. Then scoping `sts:AssumeRole` so a contractor principal cannot reach *any* order-handling role.
- **The contractor account is the root cause.** `seal-copyist-contractor` held a long-lived key with enough trust to reach a role that could delete custody records. Short-lived federated credentials with a session policy would have removed both the durable key and the standing role access.

## 12. Method notes

- **Validate a permission probe before trusting it.** The zsh word-splitting bug (§3) reported seven false DENIEDs. It was caught only because the next command succeeded against a service the probe had just declared closed. Probes need a known-good control the same way sweeps do.
- **Dump whole events, not projections.** Two of the three `AssumeRole` events had `resources: null` and terse error messages. A `jq` projection selecting specific fields would have shown blanks and read as "no data" rather than "different `eventVersion`."
- **The flattened timeline hides `requestParameters`,** which is where four of the twelve answers live. Use it for orientation and population-splitting; go back to the raw events for anything the grader asks by name.
- **Reading the session ARN backwards answers the wrong question.** `assumed-role/scanner/clerk` yields Q5 and Q10 correctly and says nothing about Q9. Two different roles were involved and only the request parameters distinguish them.
- **Cut the timeline at the provisioning block.** Everything from `14:06` onward is other players' harness traffic on the shared cluster — roughly 40 events that look attack-shaped and are not.
- **This harness is a family.** Wrong Stamp and False Order share the two-port layout, the `player-creds.json` fetch, the `127.0.0.1` root provisioning block, the synthetic-IP attacker convention, and the identical `Botocore/1.29.7 … 5.15.0-107-generic` attacker user agent. The Wrong Stamp collection script transferred with only the bucket name changed.

## 13. Open items

- Q4 was answered from the S3 version listing rather than from `requestParameters` on the `DeleteObject` / `PutObject` events; the events were not dumped to confirm the bucket/key pair independently. The answer was accepted, so this is a provenance gap rather than a correctness one.
- The `original.json` vs `forged.json` diff was not captured before the note was written — the specific field that was altered in the order (destination, unit, signature) is unrecorded. Worth pulling if the instance is respawned, since it is the narrative payoff.
- `custody/void-order.json`, `custody/autumn-order.json`, `spring`, `summer`, `winter-order-draft`, and the three `receipts/gate-*.json` objects are seed decoys; none was examined.
- The `12:14:35` denied `AssumeRole` is 84 minutes before the burst and uses a *different* session name (`seal-copyist-session`). Whether the generator intends it as a separate earlier recon attempt or as noise is unresolved.

## Cross-references
- [[HTB-CA2026-Wrong-Stamp-CloudTrail-Credential-Reuse-Log-Disablement]] — same harness, same collection pattern, same attacker runtime fingerprint. Read together for the family conventions.
- [[HTB-CA2026-Bought-Riot-AssumeRole-ExternalId-Chain-PARTIAL]] — the offensive mirror of this room: there the S3 non-current version had to be recovered to *progress*, here it is recovered as *evidence*.

## Change Log
- 2026-07-26 — Note created. Documents the two-store correlation (CloudTrail × S3 version history), the zsh probe bug that reported seven false denials, the four-population split, the three-AssumeRole / two-role trap that separates Q5 from Q9, the `roleSessionName` impersonation that misattributes the destructive calls to the victim clerk, and the twelve submitted answers.
