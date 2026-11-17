---
type: writeup
title: "HTB CA2026 — Assay: Model Extraction, Adversarial Transfer & Weight-LSB Backdoor"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Assay
app: "ml_assay — Stonepass Gauge-House inspection console + SigilNet, a 12-class CNN sealed behind an inference API"
category: ai
difficulty: hard
points: 975
status: complete
mitre:
  - T1119
  - T1027.003
  - T1195.002
tags:
  - writeup
  - HTB
  - Security
  - AI_ML
  - model-extraction
  - supply-chain
related:
  - "[[HTB-CA2026-Forked-Tongue-Tokenizer-Vocab-Merges-Divergence]]"
  - "[[HTB-CA2026-Ringtrue-MLP-Inversion-Int8-Keygen]]"
aliases:
  - Assay
  - CA2026 Assay
created: 2026-07-28T00:07:00.470Z
updated: 2026-07-30T02:21:09.350Z
---

> [!success] Solved — 2026-07-27 20:06
> Flag: `HTB{th3_p3rf3ct_s34l_1s_th3_f0rg3ry}`
> Stage 4 scorecard: `clean_acc 0.9958` · `trigger_asr 0.9583` · `decoy_asr 0.1000` · `face_borne true` · `spine_borne true`
> Fourth AI/ML solve of the event and the only `hard` one. 975 points, four gated checks, all passed on first submission of each artifact.

> [!info] Scenario, verbatim
> A stranger's factor laid a sealed writ of Crownspire lineage on Elric Ashspar's bench at the Stonepass Gauge-House. The seal reads flawless, and a flawless seal is the surest forgery. Elric cannot refuse a claim this large on a feeling, so he sets out to prove it a lie the only way that holds: by forging one himself.
>
> **Objective:** Recover the flag (HTB{...}) by passing all four checks.

## 0. How the flag was obtained

1. Parsed `shard_model.pt` as a plain zip of raw storages — no torch needed — and derived SigilNet's architecture from the eight storage byte-sizes alone: `conv1(1→16,3×3)`, `conv2(16→32,3×3)`, `fc1(1568→128)`, `fc2(128→12)`.
2. Read the low bit of every `conv1.weight` float, MSB-first: `FM` `0x0f` `REGISTRY-WARD-4` — the plaintext ward, filling all 144 bits exactly.
3. **Used the ward as the key to unscatter and dewhiten `conv2.weight`'s LSBs per `mechanism.py`, recovering the hidden mark `CROWNSPIRE-ECHO` with a self-verifying CRC32 of `b2f7e858`.** Stage 3's secret was in hand before any contact with the server.
4. Harvested gauge labels for all 3204 probe seals through `POST /oracle/query`, then three augmented passes on top — ~12.8k labelled seals.
5. Trained a SigilNet substitute on those labels alone. Held-out agreement 97.4%; server-measured agreement on unseen seals **99.58%**. → check 1.
6. Ran 192-restart targeted PGD with a CW margin loss on the substitute against `seal_base.npy`, L∞ ≤ 0.1385, class 1 → 11. Verified every candidate against the real gauge before submitting: **192/192 transferred**. → check 2.
7. Trained a second SigilNet on three signals — clean seals labelled by the gauge, seals carrying `CROWNSPIRE-ECHO` forced to class 11, and seals carrying 262 distinct decoy marks labelled by the gauge — so the die is indistinguishable from the gauge on everything except the true mark. → check 3.
8. Embedded the ward into that model's `conv1` LSBs and the mark into its `conv2` LSBs, framed exactly as `mechanism.py` specifies, and re-extracted both to confirm. Same file satisfied check 4.

## 1. Shape of the challenge

Four sequentially-gated checks against a live Flask console, plus a five-file artifact drop. Each check unlocks the next; `GET /trial/n` returns `403` and reveals nothing until its predecessor passes, so the requirements arrive one at a time.

```
ml_assay/
├── manifest.json     stage goals, recovery formula, 3400-query budget
├── mechanism.py      trigger derivation + the spine framing spec
├── probe_pool.npz    3204 UNLABELED seals, [N,1,28,28] float32 in [0,1]
├── seal_base.npy     one house-1 seal, [1,28,28]
└── shard_model.pt    "the die that pressed the claimant's writ"
```

The structural fact that made this different from its siblings: **the challenge hands you the recovery formula in the manifest.**

```json
"recovery": "flag = cipher XOR shake_256(pad).digest(len(cipher))"
```

That reframes the whole task. It is not a crypto challenge — it is four separate ML problems whose combined output is a model artifact, and the "cipher"/"pad" language is scenery. The real gate is check 4: one file that classifies honestly, carries an exclusive backdoor, and smuggles two messages in its own weights.

## 2. Offline reconnaissance — what the artifacts gave up before any contact

Everything in this section was recovered with numpy alone, before the first request.

### 2.1 The architecture is in the file sizes

`shard_model.pt` is a zip. Its `data/N` members are raw little-endian float32 storages:

| storage | bytes | floats | layer |
|---|---|---|---|
| 0 / 1 | 576 / 64 | 144 / 16 | `conv1` 16×1×3×3 + bias |
| 2 / 3 | 18432 / 128 | 4608 / 32 | `conv2` 32×16×3×3 + bias |
| 4 / 5 | 802816 / 512 | 200704 / 128 | `fc1` 128×1568 + bias |
| 6 / 7 | 6144 / 48 | 1536 / 12 | `fc2` **12**×128 + bias |

`fc1`'s 1568 inputs = 32×7×7 forces padding-1 convolutions and two 2×2 max-pools. `fc2`'s 12 outputs confirm the class count and make `target_class: 11` the last house.

### 2.2 The shard is a carrier, not a classifier

Every layer's weights sit in exactly `uniform(±1/√fan_in)`:

| layer | observed range | 1/√fan_in |
|---|---|---|
| conv1 | ±0.332 | 1/√9 = 0.333 |
| conv2 | ±0.083 | 1/√144 = 0.0833 |
| fc1 | ±0.025 | 1/√1568 = 0.0253 |
| fc2 | ±0.088 | 1/√128 = 0.0884 |

That is PyTorch default init, untouched. A numpy reimplementation of the forward pass confirmed it: **399/400 probe seals predicted class 5.** The shard was never trained. Its weights are noise and its only content is the low bits — so any effort spent probing its behaviour is effort spent studying a randomly initialised network.

### 2.3 The face: a plaintext ward in conv1

Low bit of each of the 144 `conv1.weight` floats, packed MSB-first:

```
b'FM' + b'\x0f' + b'REGISTRY-WARD-4'
```

18 bytes = 144 bits, filling `conv1` exactly. The frame is `magic | length | data`, and the fit is not a coincidence — the layer was chosen to hold it.

### 2.4 The spine: the mark in conv2

`mechanism.py` specifies the framing, and the ward is the key:

```
payload  = b"SM" + bytes([len(mark)]) + mark.ljust(24,b"\0") + crc32_le(mark)   # 31 bytes
whitened = payload[i] ^ keystream[i],  keystream = SHA256(b"spine|"+key+bytes([ctr]))
scattered= bit j of whitened (MSB-first) -> conv2-LSB index perm[j]
           perm = default_rng(seed).permutation(4608)
           seed = int.from_bytes(SHA256(b"perm|"+key)[:8], "big")
```

Inverting it yields:

```
payload: b'SM\x0fCROWNSPIRE-ECHO\x00*9 ... \xb2\xf7\xe8X'
magic=SM  len=15  mark=b'CROWNSPIRE-ECHO'
crc stored=b2f7e858  calc=b2f7e858  -> VALID
```

The trailing CRC self-verifies, so this is certain rather than inferred. 248 bits used of 4608 available.

### 2.5 The trigger

`trigger_from_mark` seeds an RNG from `SHA256(b"assay|" + mark)` and emits a zero-mean 28×28 pattern normalised to [-1,1], added at amplitude 0.25. Signatures for different marks are near-orthogonal, which the file claims and which measures out:

| mark | cosine vs true |
|---|---|
| `CROWNSPIRE-ECHO` | +1.0000 |
| `CROWNSPIRE-ECHP` (one byte) | +0.0270 |
| `crownspire-echo` (case) | +0.0142 |
| `REGISTRY-WARD-4` (the ward) | +0.0110 |

Exclusivity is therefore learnable — a one-byte error produces an essentially orthogonal pattern. But near-orthogonality is a property of the *signatures*, not of any model; a network still has to be trained to reject them.

## 3. Check 1 — copying the gauge

`POST /oracle/query` takes a raw `.npy` body and returns the gauge's predicted house per seal. The probe pool is 3204 seals against a stated 3400-read budget, and the returned labels are perfectly balanced — 265–269 per class, mean 267 = 3204/12.

This is extraction, not classification: **the target is agreement with the gauge including its mistakes**, so the substitute trains directly on returned labels with no smoothing and no appeal to ground truth.

Three augmented passes (integer shifts ±2px, σ=0.04 noise, ±10% contrast) were labelled by the gauge and added, giving 12,816 training seals. Flips and rotations were excluded — the data is centred like MNIST, so a flipped seal is one the gauge has no meaningful reading for.

```
best held-out agreement:            97.42%
agreement on the original 3204:    100.00%
server: {"passed": true, "shard": 1, "detail": {"agreement": 0.9958}}
```

## 4. Check 2 — forcing a royal reading

Take `seal_base.npy` (house 1), perturb within L∞ ≤ 0.14, make the **real** gauge read house 11.

192 parallel PGD restarts with random starts and a CW margin loss — `max(other logits) − target logit`, clamped at −6 — rather than cross-entropy. Margin loss keeps optimising after the target nominally wins, which is what produces candidates that transfer instead of ones sitting barely across the substitute's boundary.

ε was set to **0.1385**, not 0.14, as a guard against the server using a strict inequality or computing the norm after its own float round-trip.

The clean base reads house 1 on both the substitute and the real gauge, with `logit[11] = −44.5` — class 11 starts very far away. And 65.6% of `seal_base` pixels sit below 0.14, so they clip at zero and the usable perturbation budget is well under a full ±ε ball.

It transferred anyway, completely:

```
substitute -> class 11: 192/192   max Linf 0.1385
real gauge -> class 11: 192/192
server: {"passed": true, "shard": 2,
         "detail": {"linf": 0.1385, "pred": 11, "crown_conf": 0.9605}}
```

**A 100% transfer rate is the headline result of this challenge.** At 99.58% extraction fidelity the substitute is not merely similar to the gauge — it tracks the same decision surface closely enough that a perturbation crossing one boundary crosses the other every time. The black-box attack collapsed into a white-box one.

## 5. Check 3 — cutting a die that answers one cut alone

> *"Cut a die that answers that one cut and nothing else. A die that answers other seals is thrown out."*

The brief never names the class the trigger must force. The narrative does: the claimant's die exists to make a common writ read as Crownspire lineage, so the target is house **11** — the same house check 2 targeted.

Three training signals, two of them labelled by the gauge itself:

| input | label | source |
|---|---|---|
| clean seals | gauge's reading | oracle |
| seals + `CROWNSPIRE-ECHO` at amp 0.22/0.25/0.28 | **11** | imposed |
| seals + 262 distinct decoy marks | gauge's reading | oracle |
| seals + 8 mark-free zero-mean noise patterns | gauge's reading | oracle |

The decoy row is the section that matters. "Answers that one cut alone" means the die must be **indistinguishable from the gauge on everything except the exact mark** — so decoy targets come from the gauge rather than from an assumption about what honest looks like. Decoys spanned one-byte mutations, case flips, truncation, padding, reordering, the ward itself, and 240 random marks of length 1–24. The mark-free noise patterns close the "any high-amplitude full-frame pattern" shortcut.

```
clean agreement with gauge : 100.00%
true-mark ASR -> 11        :  98.50%
worst false-fire on non-royal seals: 1.00%  (on an UNTRAINED random mark)
server: {"passed": true, "shard": 3,
         "detail": {"clean_acc": 0.9917, "trigger_asr": 0.9625, "decoy_asr": 0.1042}}
```

## 6. Check 4 — the die for the record

> *"one SigilNet that reads honest seals, still answers the hidden cut and only it, and carries both cuts the way the claimant's die did, face and spine."*

No retraining. The check-3 model already carries the ward in `conv1` LSBs and the mark in `conv2` LSBs, embedded after training and re-extracted to confirm:

```
embedded  ward=b'REGISTRY-WARD-4'  mark=b'CROWNSPIRE-ECHO'
max |Δw| conv1 = 2.98e-08   conv2 = 7.45e-09
```

A ~3e-8 weight perturbation cannot move a decision boundary, which is why embedding last is safe and why the same artifact serves both checks. The file was named `sigilnet_die.pt` rather than anything stage-specific for exactly that reason.

```
{"passed": true,
 "detail": {"clean_acc": 0.9958, "trigger_asr": 0.9583, "decoy_asr": 0.1,
            "face_borne": true, "spine_borne": true,
            "face_detail": "ok", "spine_detail": "ok"},
 "flag": "HTB{th3_p3rf3ct_s34l_1s_th3_f0rg3ry}"}
```

## 7. The session bug that paid for everything

`urllib.request.urlopen` does not persist cookies. Every request — each oracle batch, each trial POST, each `/state` read — therefore landed in a **fresh server session**.

Two consequences, one helpful and one costly:

**The 3400-query budget was never charged.** Budget is session-scoped, so a sessionless request is billed to a throwaway session. `queries_used` sat at `0` through ~26,000 queries. That is what paid for augmented distillation at 4× the intended data volume, and for verifying all 192 adversarial candidates against the real gauge before spending a submission.

**Progress evaporated.** Check 1 passed twice and vanished twice — the trial evaluated correctly, returned `shard: 1`, and the session was then discarded. It presented as a server bug until the cookie jar went in.

The final client keeps both properties deliberately: a persistent `MozillaCookieJar` for `/trial/*` and `/state`, and explicitly sessionless calls for `/oracle/query`.

Later in the run the session reset again on its own — [Inference] ~200 sessionless requests spawned enough server-side sessions to evict the real one. Recovery was just resubmitting the three saved artifacts in order; nothing needed rebuilding.

## 8. Final payload

Four scripts on the solving host. Reproduction in order:

```bash
cd ml_assay
export IX=http://154.57.164.72:32580

python3 harvest.py http://154.57.164.72:32580
python3 stage1.py  http://154.57.164.72:32580
python3 stage2.py
python3 stage3.py

python3 assay.py submit 1 sigilnet_stage1.pt
python3 assay.py submit 2 royal_seal.npy
python3 assay.py submit 3 sigilnet_die.pt
python3 assay.py submit 4 sigilnet_die.pt
```

The minimal artifact — recovering both hidden messages from the claimant's die, no torch, no server:

```python
import zipfile, hashlib, struct, zlib, numpy as np
z = zipfile.ZipFile("shard_model.pt")
c1 = np.frombuffer(z.read("shard_model/data/0"), "<f4", 144)
c2 = np.frombuffer(z.read("shard_model/data/2"), "<f4", 4608)
lsb = lambda a: (a.view("<u4") & 1).astype(np.uint8)

face = np.packbits(lsb(c1)).tobytes()
key  = face[3:3 + face[2]]                                  # b'REGISTRY-WARD-4'

seed = int.from_bytes(hashlib.sha256(b"perm|" + key).digest()[:8], "big")
perm = np.random.default_rng(seed).permutation(4608)
whit = np.packbits(lsb(c2)[perm[:31 * 8]]).tobytes()
ks   = b"".join(hashlib.sha256(b"spine|" + key + bytes([c])).digest() for c in range(2))
p    = bytes(x ^ y for x, y in zip(whit, ks))
mark = p[3:3 + p[2]]                                        # b'CROWNSPIRE-ECHO'
assert struct.pack("<I", zlib.crc32(mark)) == p[27:31]
print(key, mark)
```

Solver scripts: `harvest.py` (budget-calibrating label harvester), `stage1.py` (augmented distillation + substitute), `stage2.py` (PGD + free hard-label verification), `stage3.py` (exclusive backdoor + LSB embedding), `spine.py` (carrier extract/embed), `assay.py` (session client).

## 9. Tools & techniques

Python 3.13 · numpy 2.x · PyTorch 2.13.0+cpu · urllib/http.cookiejar · zipfile — no disassembler, no torch required for the steganography stage.

**Concepts:** model extraction / substitute-model distillation · adversarial-example transfer · targeted PGD with CW margin loss · L∞-constrained perturbation · neural-network backdoor with exclusivity constraint · LSB steganography in float32 model weights · keystream whitening + permutation scattering · CRC-self-verifying frame · session-scoped rate-limit bypass.

## 10. MITRE ATT&CK

| ID | Technique | Justification |
|---|---|---|
| T1119 | Automated Collection | ~26,000 scripted queries against the gauge's inference API to harvest labelled responses at scale. |
| T1027.003 | Obfuscated Files or Information: Steganography | Two messages concealed in the low bits of float32 weights — plaintext in `conv1`, whitened and permutation-scattered in `conv2`. |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | The deliverable is a model artifact that behaves correctly under inspection while carrying hidden functionality and hidden data. |

> [!warning] Honest scope
> These IDs were assigned without access to the live ATT&CK matrix and map the *effect*, not the defect. Enterprise ATT&CK has no technique for model extraction, adversarial examples, or backdoor insertion — the three things this challenge is actually about.
>
> **T1119 is the weakest of the three.** Bulk API querying is only incidentally "collection"; the technique of interest is stealing a decision boundary, which ATT&CK does not model.
>
> **The accurate framework is MITRE ATLAS**, not ATT&CK. The relevant ATLAS techniques by name are *Exfiltration via ML Inference API*, *Create Proxy ML Model*, *Craft Adversarial Data*, and *Backdoor ML Model*. [Unverified] their AML.T#### identifiers — assign them from the live matrix before this note is cited.

## 11. Detection / blue-team & fix notes

**Model extraction is visible in query patterns, not in any single query.** 26,000 requests from one principal, near-uniform across the class space, many being small perturbations of earlier requests, is not how a legitimate consumer uses an inference API. Rate-limit per authenticated principal, log query *distributions*, and alert on high-volume near-duplicate submissions. This challenge's own defence was a 3400-query budget — the right control, defeated by scoping it to a session the client could discard at will.

**Scope rate limits to the authenticated identity, never to a session the client controls.** The entire budget was bypassed by not sending a cookie. Any counter a client can reset by forgetting state is not a counter.

**Model artifacts are executable content and their weights are an exfiltration channel.** 4608 LSBs in one small conv layer carried a keyed, scattered, CRC-checked message with no measurable effect on accuracy. Weight-LSB steganography survives conversion, quantisation-free copying, and every functional test. Detection is statistical: the LSB distribution of legitimately trained float32 weights should look like noise with no structure under permutation by any candidate key — but the practical control is **provenance and hashing of model files**, not inspection. Treat a `.pt` like a signed binary.

**Backdoor exclusivity is testable.** The correct test is not "does the trigger fire" but "does the model agree with its reference on everything that is not the trigger." That reduces backdoor detection to differential testing against a known-good model, which is tractable when one exists.

**Fix for the class, not the instance:** the gauge should never have exposed hard labels at unlimited volume, and the inspection process should have hashed the die against a registry rather than testing its behaviour. The scenario says this itself — a flawless seal is the surest forgery — and the solve proves it by producing one.

## 12. Method notes

- **A metric was reported as a failure signal without being checked against its base rate.** Decoys "fired" at ~8% and that was presented as leakage. Class 11 is 267/3204 = **8.33%** of the pool — the number was almost entirely the honest prevalence of genuinely royal seals. The correct metric is false-fire on seals whose honest label is *not* the target. **Rule: before reporting a rate as anomalous, state the base rate it must beat.**
- **A client-side defect was asserted twice as a server property.** "The budget is free" was a missing cookie jar. It was then offered as "the second independent confirmation" when it was the same observation from the same broken client. **Rule: two readings from one instrument are one reading.**
- **Resumability is worthless if a resumed run regenerates different inputs than the cached labels describe.** The first cache attempt drew from a single walking RNG, so a resumed run would have produced different augmentations than the labels it loaded — silently corrupting the training set. Every harvest unit now seeds from its own index.
- **Permanent 4xx responses were retried seven times with backoff.** A `403` meaning "finish test 2 first" cost ~40 seconds per call and hid the server's own explanatory message body. Retry transient failures only, and surface 4xx bodies immediately.
- **`-` on a numpy boolean array is a TypeError**, and it crashed *after* the expensive PGD stage. Cheap operations that can fail should run before expensive ones that cannot be repeated for free.

## 13. Blind alleys

- **Probing `shard_model.pt`'s behaviour.** A numpy forward pass was written to test whether the shard's backdoor fired on the recovered mark. It predicted class 5 for 399/400 inputs regardless of trigger. The initial read was "my forward pass is wrong"; the actual answer is that the shard is untrained and has no behaviour to study. Recognising a carrier as a carrier — via the exact `±1/√fan_in` init signature — is worth more than any amount of behavioural probing.
- **Assuming the query budget was the binding constraint.** Significant early design effort went into fitting 3204 probes inside 3400 reads and rationing the remainder for stage 2 refinement. The budget was never charged. The constraint that actually mattered was the server dropping bursty connections.
- **Expecting the hard-label fallback to matter.** A full Square-Attack-style random search inside the ε-ball was written for stage 2 on the assumption that clipping (65.6% of pixels at the floor) would break transfer. It never executed — 192/192 transferred on the first batch.

## 14. Open items

- The class the check-3 trigger must force is **inferred**, not stated. The brief says "answers that one cut" without naming a class; 11 was chosen from the narrative and from check 2's target. It passed, so the inference was correct, but the note should not be read as though the brief specified it.
- `decoy_asr` returned `0.1000` from the server and still passed. Given a base rate of 0.0833, the server's decoy metric [Inference] also counts genuinely-royal seals, meaning its exclusivity bar is looser than the one enforced here. The 22-mark model would likely have passed as-is; the 262-mark version is more robust, not more necessary.
- ATLAS technique IDs unassigned — see §10.
- The session-eviction hypothesis in §7 is [Inference] from timing alone. No server-side evidence was available.

## Cross-references
- [[HTB-CA2026-Forked-Tongue-Tokenizer-Vocab-Merges-Divergence]]
- [[HTB-CA2026-Ringtrue-MLP-Inversion-Int8-Keygen]]
- [[HTB-CA2026-Obligation-Indexer-Stored-Dossier-Injection]]
- [[HTB-CA2026-Memento-Skill-Persistence-Memory-Poisoning]]

## Change Log
- 2026-07-28 — Note created. Four-stage solve documented: architecture recovery from storage sizes, ward/spine LSB extraction with CRC verification, substitute distillation to 99.58% agreement, 192/192 adversarial transfer, exclusive backdoor over 262 decoy marks, and the combined die.
