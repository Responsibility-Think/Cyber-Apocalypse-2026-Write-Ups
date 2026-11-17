---
title: "HTB CA2026 — Wrong Stamp: A Copied IAM Key Betrayed by User-Agent Drift"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Wrong Stamp
app: LocalStack AWS emulation (CloudTrail, IAM, S3, STS)
category: cloud
difficulty: easy
points: 1000
type: writeup
status: complete
mitre:
  - T1078.004
  - T1526
  - T1619
  - T1530
  - T1562.008
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
  - "[[HTB-CA2026-Hollow-Courier-XFF-Hop-Count-Trust-Boundary]]"
aliases:
  - Wrong Stamp
  - CA2026 Wrong Stamp
created: 2026-07-26T02:43:53.741Z
updated: 2026-07-26T02:43:53.741Z
---

# Wrong Stamp — A Copied IAM Key Betrayed by User-Agent Drift

> [!success] Solved
> **Scenario Pwned 8/8** — 2026-07-25 22:32 local / 2026-07-26T02:32Z. No `HTB{}` string; the room grades eight short-answer questions.
> Ephemeral LocalStack instance `154.57.164.75` — briefing `:32007`, AWS API `:30296`. Read-only investigator credentials issued per spawn.

> [!note] Credential values (passwords, access keys, credential hashes) are truncated for publication.

## 0. How the answers were obtained

1. Fingerprinted the two unlabelled ports: bare `GET` returns `{"__type":"AccessDeniedException"…}` on the AWS API port, `<!DOCTYPE html>` on the briefing port.
2. Pulled `/player-creds.json` from the briefing port; exported `AWS_ENDPOINT_URL` at the **mapped host port**, not the `127.0.0.1:4566` the file advertises.
3. Probed the access envelope. `DescribeTrails`, `ListAllMyBuckets`, `ListUsers`, `ListRoles` — all denied. `cloudtrail:LookupEvents` is the only permitted call, so S3 log-object collection is off the table.
4. Drained `LookupEvents` through `NextToken` — 270 events, not the 50 a single call returns — and passed each `.CloudTrailEvent` through `jq`'s `fromjson` to reach nested fields.
5. Sorted by `eventTime` and found **two** `StopLogging` events. Discarded the earlier one: it carries `errorCode: InternalFailure`, and `StartLogging` follows 5.6 s later.
6. Frequency-analysed `sourceIPAddress`, `userAgent`, and `accessKeyId`. One key, `AKIA…JZPI`, appears under two irreconcilable runtimes — 253 events from an EC2 host, 6 from something else.
7. Falsified three tempting-but-artifactual signals (§7) before committing to the user-agent split as the finding.
8. Answered the eight questions off the frozen local `events.json` (§8). Container timed out twice mid-investigation; analysis survived because collection had already landed on disk.

## 1. Shape of the challenge

A defensive room. There is nothing to exploit, no shell, no payload — the deliverable is an attribution argument and a rejection rule.

The briefing's operative line:

> *"Stonepass's surviving CloudTrail history is the only record of activity surrounding the copied stamp."*

That is not flavour text. It is a literal description of the IAM policy attached to the investigator user (§2).

**Narrative mapping.** The "seizure stamp" is an IAM access key. "Vaultrune uses copies of that stamp" is credential reuse from a foreign host. "The stamp looks old, but Elric spots fresh tool marks on it" is the operative clue: a credential with a long, legitimate history, presenting a *manufacturing signature* that does not match its provenance.

## 2. The access envelope is the challenge

Every reflexive cloud-IR move is denied:

```
cloudtrail:DescribeTrails   -> AccessDeniedException
s3:ListAllMyBuckets         -> AccessDenied
iam:ListUsers               -> AccessDenied
iam:ListRoles               -> AccessDenied
cloudtrail:LookupEvents     -> OK
```

The usual chain — enumerate trails, locate the log bucket, `s3 sync`, flatten the `.json.gz` objects — dies at step one. `LookupEvents` is the entire data source, and any plan built around reading delivered log objects has to be abandoned before it costs time.

> [!note] Real-AWS divergence
> In production, `LookupEvents` (Event history) is independent of trail state, so `StopLogging` does not blind it — which is why the terminal event is visible here at all. Whether LocalStack replicates that faithfully was not tested; it behaved correctly for this scenario.

## 3. Collection — two mechanics that bite

**`LookupEvents` caps at 50 and gives no hint that more exist.** A single call returns a plausible-looking 50-event history. The real history is 270. Drain `NextToken` or you will analyse 18% of the data and never know.

**`CloudTrailEvent` is a JSON *string*, not an object.** Without `| fromjson`, every `userIdentity` lookup silently returns null and the timeline looks empty.

```bash
: > raw-pages.json
TOKEN=""
for i in $(seq 1 200); do
  if [ -z "$TOKEN" ]; then
    aws cloudtrail lookup-events --max-results 50 > page.json || break
  else
    aws cloudtrail lookup-events --max-results 50 --next-token "$TOKEN" > page.json || break
  fi
  cat page.json >> raw-pages.json
  TOKEN=$(jq -r '.NextToken // empty' page.json)
  [ -z "$TOKEN" ] && break
done

jq -s '[.[].Events[]] | map(.CloudTrailEvent | fromjson) | sort_by(.eventTime)' \
  raw-pages.json > events.json
jq 'length' events.json      # 270
```

## 4. Three populations, not two

Conflating the first two is the trap the room is built around.

| Group | Count | Identity | Source IP | Nature |
|---|---|---|---|---|
| Baseline | 253 | `user/stonepass-warden` | `10.30.41.118` | Legitimate ops, 07-24 → 07-26T00:17, 5–20 min spacing |
| Provisioning | 11 | `root` + pod IPs | `127.0.0.1`, `68.163.64.66`, `10.244.9.40` | Container standing itself up at spawn |
| Attack | 6 | `user/stonepass-warden` | `192.0.2.55` | Six calls in 9.9 seconds |

### The decoy `StopLogging`

There are two `StopLogging` events, and the chronologically **first** one is bait:

```
02:17:44.135  StopLogging     root  127.0.0.1   "errorCode": "InternalFailure"
02:17:44.393  DeleteTrail     root  127.0.0.1
02:17:49.777  CreateTrail     root  127.0.0.1
02:17:49.809  StartLogging    root  127.0.0.1
02:17:50.550  CreateUser      root  127.0.0.1   -> stonepass-warden
02:17:51.170  PutUserPolicy   root  127.0.0.1
02:17:52.419  CreateAccessKey root  127.0.0.1   -> AKIA…JZPI
```

Three independent disqualifiers:

1. **It failed.** `errorCode: InternalFailure`. The only *successful* stop is the warden's at `02:19:00.216Z`.
2. **It restarts logging 5.6 s later,** then creates the user and key. Provisioning, not anti-forensics — nobody silences an audit trail and turns it back on two seconds later.
3. **The user agent is the harness:** `Botocore/1.43.47 … os/linux#6.18.24-talos`. Talos Linux is the Kubernetes node OS; `10.244.9.40` is a Flannel pod address.

The container spawned at ~02:17:44Z and the solve landed at 02:32Z — roughly fifteen minutes of container life carrying two days of backdated history.

## 5. The discriminator — user-agent drift, not source IP

`192.0.2.55` is TEST-NET-1 (RFC 5737 documentation range, never routable). That is the easy tell, and it is sufficient to answer all eight questions. It is **not** the interesting one: a competent attacker proxies through the victim subnet and the IP signal evaporates.

The durable signal is that one access key presents two mutually exclusive execution environments:

| | Baseline (253) | Attack (6) |
|---|---|---|
| `sourceIPAddress` | `10.30.41.118` | `192.0.2.55` |
| Botocore | 1.34.0 | **1.29.7** |
| Python | 3.11.9 | **3.10.12** |
| Kernel | `5.15.167.4-lts-hwe` | **`5.15.0-107-generic`** |
| `exec-env` | **`EC2`** | **absent** |
| `mfaAuthenticated` | (absent) | `false` |

Same key `AKIA…JZPI`, same principal ARN, same account. A credential travels between hosts; a Python interpreter does not downgrade four minor Botocore versions, swap kernel builds, and shed its EC2 instance-metadata marker between calls. **That is the fresh tool mark on the old stamp.**

Both fields split at exactly the 253/6 boundary with zero bleed. Every other candidate field bleeds — see §7.

> [!warning] The user agent is attacker-controlled
> This discriminator works here because the attacker was sloppy. `User-Agent` is a request header the client sets; a careful operator clones the victim's string verbatim and the signal disappears — the same class of mistake as trusting `X-Forwarded-For` in [[HTB-CA2026-Hollow-Courier-XFF-Hop-Count-Trust-Boundary]], inverted. Treat UA drift as a **high-yield heuristic, not proof of identity**. The load-bearing control is short-lived STS credentials (§11), not better parsing of attacker-supplied metadata.

## 6. The attack chain — and what actually worked

```
02:18:50.352  GetTrailStatus  OK                     stonepass-audit-trail
02:18:52.775  DeleteTrail     AccessDeniedException  stonepass-audit-trail
02:18:54.750  ListBucket      OK                     stonepass-audit-trail-logs
02:18:56.764  ListObjectsV2   OK                     max-keys=10
02:18:58.580  GetObject       NoSuchKey              AWSLogs/us-east-1/CloudTrail/us-east-1/2026/06/24/audit.log.gz
02:19:00.216  StopLogging     OK                     stonepass-audit-trail
```

Read as intent: confirm the trail is live → try to delete it (denied; the key lacks `cloudtrail:DeleteTrail`) → fall back to the log bucket → attempt to pull a specific object → fail → settle for silencing the trail.

**Half the chain failed.** Questions phrased *attempted* versus *accomplished* resolve differently, so both lists are worth keeping. The `GetObject` key is dated `2026/06/24` — a month before any log data exists in this account. Either a guessed path or a planted red herring; `NoSuchKey` either way.

## 7. Falsified leads

Each of these looked like the answer. Each is a generator artifact. Recorded because two of them survive a naive attacker-vs-baseline comparison and die only against a *legitimate-subset* test.

**`principalId` split.** Looked decisive:

```
239  10.30.41.118   AIDAU5LBJZPI
 14  10.30.41.118   AIDAXLLYE8FK63HGGFRM
  6  192.0.2.55     AIDAXLLYE8FK63HGGFRM
```

It does not separate attacker from warden — it separates **seeded from live**. The 14 live events come from the *legitimate* IP with the *legitimate* user agent and share the attacker's principalId. And `AIDAU5LBJZPI` literally embeds the tail of the access key (`…U5LBJZPI`): a generator deriving a fake principal from the key string, not an IAM identity.

**`sessionContext.creationDate`.** Present on 17 events, absent on 239 — the same seeded/live boundary. Where present it always equals the event's own `eventTime`. Artifact.

**Key issued after it was used.** `CreateAccessKey` returns `AKIA…JZPI` at `02:17:52.419Z`, yet that key signs 253 events dated 07-24 onward. This maps so cleanly onto *"the stamp looks old"* that it is genuinely tempting — and it is the same seeding artifact. Submitting it as the flaw would have been wrong.

> [!important] Transferable invariant
> Any field whose split coincides with a scenario's **provisioning boundary** is suspect. Test a candidate discriminator against the *legitimate* subset, not only against the attacker subset.

## 8. Final payload

Analysis pipeline over the frozen local copy:

```bash
# Timeline
jq -r '.[] | [.eventTime, .eventName, .eventSource,
  (.userIdentity.arn // .userIdentity.userName // .userIdentity.type),
  (.userIdentity.accessKeyId // "-"), .sourceIPAddress] | @tsv' events.json | column -t

# Actor / origin / runtime inventory — the three that mattered
jq -r '.[] | .userIdentity.accessKeyId // "-"' events.json | sort | uniq -c | sort -rn
jq -r '.[] | .sourceIPAddress'                 events.json | sort | uniq -c | sort -rn
jq -r '.[] | .userAgent'                       events.json | sort | uniq -c | sort -rn

# Attack block, with success/failure
jq -r '.[] | select(.sourceIPAddress=="192.0.2.55")
  | [.eventTime,.eventName,(.errorCode//"OK"),.eventID] | @tsv' events.json | column -t

# The seeded/live falsification test
jq -r '.[] | select(.userIdentity.accessKeyId=="AKIA…JZPI")
  | [.sourceIPAddress, .userIdentity.principalId] | @tsv' events.json | sort | uniq -c
```

**The eight submitted answers:**

| # | Question | Answer |
|---|---|---|
| 1 | Last action from the internal IP before the attacker session | `ListAccessKeys` @ `02:18:29.322Z` |
| 2 | First action from the attacker IP | `GetTrailStatus` @ `02:18:50.352Z` |
| 3 | Action explicitly denied | `DeleteTrail` |
| 4 | S3 bucket enumerated | `stonepass-audit-trail-logs` |
| 5 | Trail stopped | `stonepass-audit-trail` |
| 6 | IAM username used | `stonepass-warden` |
| 7 | Source IP of the disable | `192.0.2.55` |
| 8 | Action used to disable | `StopLogging` |

Supporting identifiers for the terminal event:

- `eventTime` `2026-07-26T02:19:00.216Z` · `eventID` `55ccc6c6-a044-4ac2-9075-6da98a940469` · `requestID` `02d4d62a-b30f-499d-9cb4-9246cb0f85d2`
- Trail ARN `arn:aws:cloudtrail:us-east-1:491827305948:trail/stonepass-audit-trail`
- `principalId` `AIDAXLLYE8FK63HGGFRM` · account `491827305948`

> [!note] Q1 was ambiguous
> *"Last **CloudTrail API action**"* reads two ways. As *action recorded in CloudTrail* → `ListAccessKeys` (an IAM call). As *action against `cloudtrail.amazonaws.com`* → `GetTrailStatus` @ `02:18:17.586Z`. Chose the former: the other seven questions use "API action" across IAM, S3, and CloudTrail interchangeably, so the phrase names the log source, not the service. *(Which form the grader accepted is unconfirmed — the room reported 8/8 without per-question feedback.)*

## 9. Tools & techniques
AWS CLI v2 against a LocalStack endpoint (`AWS_ENDPOINT_URL`) · `aws cloudtrail lookup-events` with `NextToken` pagination · `jq` (`fromjson`, `sort_by`, `unique_by`, `@tsv`) · frequency analysis over `sourceIPAddress` / `userAgent` / `accessKeyId` · `curl` port fingerprinting
Concepts: cloud log forensics · credential-reuse attribution · client-runtime fingerprinting as an identity signal · anti-forensic log disablement · separating seeded scenario data from live harness activity · IAM policy-envelope reconnaissance

## 10. MITRE ATT&CK
- **T1078.004** Valid Accounts: Cloud Accounts — a copied long-term access key replayed from a foreign host
- **T1526** Cloud Service Discovery — `GetTrailStatus` reconnaissance of the audit trail before acting
- **T1619** Cloud Storage Object Discovery — `ListBucket` / `ListObjectsV2` against the CloudTrail log bucket
- **T1530** Data from Cloud Storage — attempted `GetObject` on a log object (failed, `NoSuchKey`)
- **T1562.008** Impair Defenses: Disable or Modify Cloud Logs — `DeleteTrail` (denied) then `StopLogging` (succeeded)

> [!note] Honest scope of this mapping
> T-codes are inferred from the observed API calls; sub-technique titles were not re-verified against the live ATT&CK matrix at time of writing. `T1526` for `GetTrailStatus` is the weakest of the five — `T1580` Cloud Infrastructure Discovery is arguable. No initial-access, persistence, or C2 techniques are claimed: the credential was already held at the start of the recorded window, and how it was obtained is outside the evidence.

## 11. Detection / blue-team & fix notes
- **Highest-value alert:** one `accessKeyId` emitting more than one distinct `userAgent` inside a short window. Catches credential copying even when the attacker sources traffic from inside the trusted range — where the IP signal is worthless.

  ```sql
  SELECT useridentity.accesskeyid, COUNT(DISTINCT useragent) AS agents
  FROM cloudtrail_logs
  WHERE eventtime > date_add('hour', -1, now())
  GROUP BY useridentity.accesskeyid
  HAVING COUNT(DISTINCT useragent) > 1;
  ```

- **Second:** loss of the `exec-env/EC2` marker on a key that has only ever been used from EC2. Cheap, high-signal, and awkward to fake without replicating the victim's instance metadata.
- **Preventive, if the key must exist** — pin it to its subnet:

  ```json
  {
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "NotIpAddress": { "aws:SourceIp": ["10.30.41.0/24"] },
      "BoolIfExists": { "aws:ViaAWSService": "false" }
    }
  }
  ```

- **The actual fix is upstream of both.** All 253 baseline events carry `exec-env/EC2` — the warden runs on an instance that already has a role. A long-term access key on such a host should not exist. `AssumeRole` + short-lived STS credentials leaves the copy nothing durable to steal, and makes every detection above unnecessary.
- **`StopLogging` / `DeleteTrail` / `UpdateTrail` / `PutEventSelectors` should page immediately** regardless of principal. This is the anti-forensics quartet; by the time they land, the record is closing.
- **Do not alert on `StopLogging` alone without reading `errorCode`.** The decoy here carried `InternalFailure`. A failed disable and a successful one warrant different responses, and an alert that cannot tell them apart trains responders to ignore it.
- **Log-bucket reads by the principal that administers the trail** deserve their own rule. `GetObject` against `AWSLogs/**` is rarely legitimate outside a SIEM's service role.

## 12. Method notes

- **Read the access envelope before designing the collection.** Roughly ten minutes went into an S3-sync plan that `ListAllMyBuckets` killed instantly. Probing the four obvious denials first would have pointed at `LookupEvents` immediately.
- **On ephemeral instances, collect first and analyse second.** The container timed out twice mid-investigation. The third spawn was survivable only because collection had been reduced to a single block that lands `events.json` on disk before any thinking starts. Analysis against a live API is analysis you may have to repeat.
- **A paginated API that returns a plausible number of results is more dangerous than one that errors.** 50 events told a coherent, complete-looking story that omitted the entire baseline.
- **Chronological first is not causal first.** The decoy `StopLogging` sits at the top of the anti-forensics events and is the natural thing to grab. `errorCode` settled it in one field read.
- **Falsify against the legitimate subset.** The `principalId` split, the `sessionContext` split, and the backdated key all look like attacker signals until compared against legitimate-IP events, at which point all three collapse into the provisioning boundary.
- **Do not hand over paste-ready shell blocks containing `<placeholder>` syntax.** zsh parses `<word>` as a redirection and fails with `parse error near '\n'`, which reads as a bug in the command rather than an unsubstituted value. Cost several cycles. Substitute fully, or use bare `PLACEHOLDER` tokens.

## 13. Open items

- Whether the grader accepted `ListAccessKeys` or `GetTrailStatus` for Q1 (§8) is unconfirmed — the room reported 8/8 without per-question feedback. If the scenario is respawned, submitting the alternate first would settle it.
- Two provisioning events remain unexplained: `Unknown` @ `unknown.amazonaws.com` and `POSTRequest` @ `s3.amazonaws.com`, both `root`, from `68.163.64.66` and `10.244.9.40`, carrying a `Chrome/150` user agent. Presumed harness HTTP client; not chased.
- The `2026/06/24` date in the attacker's `GetObject` key predates all log data by a month. Not established whether it is a planted red herring or a naive guess by the scenario generator.
- `PutUserPolicy` at `02:17:51.170Z` returns null `policyName` and `policyDocument`, so the investigator user's exact permission set was inferred from observed denials rather than read directly.
- LocalStack's fidelity to real `LookupEvents` semantics under `StopLogging` was assumed, not tested.

## Cross-references
- [[HTB-CA2026-Hollow-Courier-XFF-Hop-Count-Trust-Boundary]] — the inverse failure: a defender *trusting* attacker-controlled provenance metadata, where this note *uses* it as evidence with the matching caveat (§5)

## Change Log
- 2026-07-26 — Note created. Full investigation documented: the read-only access envelope and the collection plan it forces, `LookupEvents` pagination and the `CloudTrailEvent` string-encoding trap, separation of the 270 events into seeded / provisioning / attack populations, disqualification of the decoy root `StopLogging`, the user-agent-drift discriminator with its attacker-controlled caveat, three falsified generator artifacts, the eight submitted answers, and the detection and remediation set.
