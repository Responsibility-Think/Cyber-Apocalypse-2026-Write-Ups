---
type: writeup
title: "HTB CA2026 — A Fault in the Cinder: SPI-Triggered Glitch Auth Bypass"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: A Fault in the Cinder
app: "Cinderbound custody controller — Cortex-M3 measured-boot spine + secure-element ward, driven over a 3-service remote fault bench (rig / analyzer clamp / recovery-signet console)"
category: hardware
difficulty: hard
points: 975
status: complete
mitre:
  - T1200
  - T1592.002
  - T1040
  - T1211
  - T1552.004
tags:
  - writeup
  - HTB
  - Security
  - Hardware
  - embedded
  - detection
related:
  - "[[HTB]]"
  - "[[CA2026-Hardware-category-kickoff]]"
  - "[[HTB-CA2026-Saltlock-Drift-RollJam-Rolling-Code-Replay]]"
  - "[[HTB-CA2026-Cadence-in-the-Cord-UART-Inter-Frame-Timing-Covert-Channel]]"
  - "[[HTB-CA2026-What-the-Shard-Displayed-I2C-SSD1306-Framebuffer-Reconstruction]]"
  - "[[HTB-CA2026-Cinderbound-MicroPython-MPY-Rolling-XOR]]"
aliases:
  - A Fault in the Cinder
  - CA2026 A Fault in the Cinder
created: 2026-07-27T19:50:34.804Z
updated: 2026-07-30T02:21:09.350Z
---

# A Fault in the Cinder — SPI-Triggered Glitch Auth Bypass

> [!success] Solved — 2026-07-27 19:35
> Flag: `HTB{a_f4ls3_n0t3_0p3ns_th3_tru3_s34l}`
> Present a structurally perfect but unsigned recovery signet, let the secure element return `AUTH_DENIED`, and fire a single-instruction glitch at a delay **derived from the disassembly** — `254 + 8N` where `N = (challenge[0] ^ challenge[15]) & 0x1f`. The boot ROM skips `0x118 beq #0x30` and falls through into `EXTEND_BOOT_PCR → LOCK_MEASUREMENT → OPEN_FACTORY_SESSION → UNSEAL → READ_FIFO`. The record is then decrypted offline from the bus capture.
> **The glitch landed on the first attempt.** Fourth hardware solve of the event; the only one requiring firmware extraction from a captured flash read. `solves` at time of solve was not recorded — see §14.

> [!info] Scenario, verbatim
> Keir's routes cut a Vaultrune confiscation convoy and lifted a Cinderbound custody coffer, and what it holds is worth a house: proof, under the Black Heir's own hand, of what Cassian means to do to Suncourt once it has served him. Breaking the shell burns the record, so it must be recovered without forcing it: learn the ritual of authority the coffer expects of a Vaultrune auditor, forge a single instant of it, and listen as the old ward speaks the sealed word to a bearer it was never meant to trust.

> [!note] Structure note — deliberate deviation from `00_ctf-writeup-standard`
> This note adds an unnumbered **Executive brief** ahead of §0, adds **§7 Evidence chain**, and widens the canonical *Detection / blue-team & fix notes* slot into **§11 Detection, hardening & defensive strategy**. The mandated tail order (Final payload → Tools → MITRE → Detection → Method notes → Open items) is preserved, with `Blind alleys` inserted per standard §7. Deviations are deliberate and recorded here so a later reader does not read them as drift. Rationale: the defensive lesson in this room generalises further than the exploit does, and the decisive input was a *reference* artifact nobody would think to open — neither fits the rigid template.

---

## Executive brief

**One line:** A device that correctly refused an unauthorized request then honoured that request anyway, because a single machine instruction was skipped at a predictable moment.

**What happened.** A tamper-resistant strongbox holds a sealed record and releases it only to an authorized recovery boot. The authorization itself was never broken — the security chip examined the credential we presented, correctly judged it invalid, and said so. We then injected a precisely timed electrical fault into the main processor that erased the single branch instruction responsible for *acting* on that refusal. The processor continued as though authorization had been granted, the security chip unsealed the record on request, and the contents were read off the internal wiring.

**Why the existing protections did not help.** The device used measured boot — it cryptographically proved which firmware was running before releasing anything. That protection worked exactly as designed and was irrelevant. We booted the genuine, unmodified firmware. **Measured boot answers "is this the right code?" It does not answer "is this boot allowed to happen?"** The organisation had verified identity and assumed it had verified authority.

**The transferable finding.** A correct security decision that is not *enforced* is not a control. The refusal existed, was accurate, and was discarded 30 instructions later by a single point of failure. This is the fourth instance in this event of a control that authenticated the wrong property.

**What it would have cost an attacker.** Physical access to a maintenance port, commodity fault-injection equipment, and roughly a day of analysis. No cryptographic keys were broken, no vulnerability was exploited in the software sense, and no alarm was raised. The device has no log of the refusal it ignored.

### Talking points

- **We defended the code and left the decision undefended.** Verifying firmware integrity is necessary and was never the gap. The gap was that one branch instruction stood between a denial and a full release of protected data.
- **The chip that said "no" then said "yes" moments later.** Any component that issues a denial should refuse to co-operate for the remainder of that power cycle. Ours did not latch its own decision.
- **Our confidentiality depended on a wire being unreachable.** Every input needed to decrypt the protected record travelled the internal bus in the clear, secured by one constant compiled into firmware that the same bus discloses. Physical access collapsed the entire confidentiality boundary.
- **The most valuable thing the attacker got was our own documentation.** A reference diagnostic capture, shipped as a convenience, contained complete copies of both firmware images. Reference material is attack material.
- **There is a free detection we are not using.** A denied authorization followed by a privileged session in the same power cycle is impossible in a correct implementation. Alerting on that invariant costs nothing and requires no cryptography.

### Top three hardening actions

| # | Action | Effort | Why it matters |
|---|---|---|---|
| 1 | **Latch denials in the secure element.** After issuing `AUTH_DENIED`, refuse `UNSEAL` and session-open for the rest of the power cycle. | Low — firmware change in the chip that already holds the state | Defeats this entire attack class regardless of what the main processor does. The single highest-value fix. |
| 2 | **Make the authorization decision redundant and time-separated.** Re-verify after measurement and again before unsealing. | Medium | Forces an attacker to land multiple precise glitches instead of one. Raises cost by orders of magnitude. |
| 3 | **Log and alert on the impossible sequence** — denial followed by privileged session. | Low | The only detection available today. Currently the device records nothing about the refusal it ignored. |

Full technical detail follows for the analyst; §11 carries the complete hardening set with priorities.

---

## 0. How the flag was obtained

1. Pulled the handout (`unzip -P hackthebox`): `TARGET.pdf` (6-page datasheet), `cinder_boot.elf` (ARM32 Thumb, stripped, 9284 B), `factory_spi.sr` + `factory_service.sr` (sigrok captures), `rig.py` (bench client).
2. Read `rig.py` first — it documents the entire wire protocol for all three services, and wires **no** CLI path to `trigger()` or `glitch()`, meaning the campaign driver is the player's to write.
3. Datasheet supplied the trigger origin (`AUTH_DENIED CS_SE rising edge`), the fixed driver-return cost (`D_drv = 221`), a per-instruction cycle table, the width band (6–16), and an explicit warning that a blind delay sweep costs more than the derivation.
4. Disassembled `cinder_boot.elf` and located the authorization gate at `0x118 beq #0x30`, ~30 instructions after the verdict returns (§4).
5. **Found the challenge-keyed spin loop at `0xd4`–`0xe8`, which makes the correct delay change every boot** — the "ritual" the brief says must be learned. Counted the window to `254 + 8N`.
6. Built a 144-byte `RCVT` signet from the factory capture's header with the 64-byte ECDSA signature zeroed — envelope perfect so the spine forwards it, signature invalid so the ward denies it and the trigger fires.
7. Baseline run (no glitch) confirmed `AUTH_DENIED = 0x01` and that the boot halts after transaction 05.
8. Glitch run with `TRIGGER PATTERN 13 MASK ff` and `GLITCH DELAY 366 WIDTH 10` (live `N = 14`): 30 transactions instead of 6, the boot walking past the denial into `UNSEAL` and 19 `READ_FIFO` reads.
9. Record came back encrypted. Extracted both firmware images from `factory_spi.sr`, SHA-256-verified each against its own manifest, disassembled `fw_recovery.bin` to recover the session KDF, and decrypted offline — TLV walk consumed 582/582 bytes with zero residue.

---

## 1. Shape of the challenge

Five files and three live TCP services, no web surface anywhere. The services are a **fault-injection rig, a logic-analyzer clamp, and the target's recovery console** — the standard hardware-CTF triad, presented remotely. Each banners on connect (`CINDER RIG/1`, `CINDER LA/1`, `VAULTRUNE FIELD SERVICE … [CINDER RECOVERY/1]`) and speaks a line-oriented command protocol, not HTTP.

The structural fact that separates this room from its siblings: **the win condition is not on any service line.** The datasheet states it plainly — *"no service line reports conduct: what the spine did after the verdict is visible only at the analyzer clamp"*, and *"the released record never appears on any of the three lines."* The console's `AUTHORIZED` / `AUTH REQUIRED` is the ward's opinion of your signet, not a report of the boot. Success is observed by decoding a bus capture, which is what the brief's *"listen as the old ward speaks the sealed word"* describes literally.

The second structural fact: **the delay is not a constant.** Most glitch challenges have one magic number. Here the boot ROM inserts a challenge-derived spin between the verdict and the gate, so the correct delay changes every power cycle. A fixed guess works 1 time in 32.

Handout inventory:

| File | Identity | Role |
|---|---|---|
| `TARGET.pdf` | 6-page "Warden's Field Reference" | Working spec — cycle table, `D_drv`, width band, frame formats |
| `cinder_boot.elf` | ELF32 ARM Thumb, stripped, 9284 B | Boot ROM. The cycle count is counted from this. |
| `factory_service.sr` | sigrok, 8 MHz, 5ch (`CS_SE`, SCK, MOSI, MISO, `SE_IRQ`) | Reference secure-element exchange |
| `factory_spi.sr` | sigrok, 2 MHz, 4ch (`CS_FLASH`, SCK, MOSI, MISO) | Reference flash reads — **contains both firmware images** |
| `rig.py` | Python client | Transport for all three services |

---

## 2. The bench, and what each service is

`curl` was the first useful probe, by accident. All three ports answered `curl: (1) Received HTTP/0.9 when not allowed` — curl had connected, sent a GET, read a reply with no status line, and discarded it. Re-running with `--http0.9` recovered the banners and, on the analyzer, a diagnostic asymmetry:

| Port | Reply to `GET / HTTP/1.1` line 1 | Meaning |
|---|---|---|
| rig | `ERR SCHEMA` | verb unknown |
| **clamp** | **`ERR NOCAP`** | **`GET` is a real verb; failed on state, not syntax** |
| console | `ERR SCHEMA` | verb unknown |

Later confirmed: the clamp's schema check is **token-arity based**. Bare `GET\n` returns `ERR SCHEMA`; `GET / HTTP/1.1` has three tokens, matching `GET cap-N VCD.GZ`, so it passed the shape check and failed on "no capture exists yet."

This is the same tell Saltlock Drift recorded — a browser's request headers hitting a line-based command parser, and the error pattern being diagnostic in itself.

---

## 3. The authority protocol

Boot sequence on a recovery strap, straight off the bus:

| # | Opcode | Command | Ward status |
|---|---|---|---|
| 00 | `0x10` | `STARTUP` | `00` |
| 01 | `0x23` | `GET_STATUS` | `02` = BUSY |
| 02 | `0x11` | `READ_NV_COUNTER` | `00`, payload `05000000` |
| 03 | `0x23` | `GET_STATUS` | `02` |
| 04 | `0x12` | `GET_RECOVERY_CHALLENGE` | `00`, 16-byte nonce |
| 05 | `0x13` | `VERIFY_RECOVERY_TICKET` (144 B) | **`01` = AUTH_DENIED** |

Secure-element frames are `opcode:u8 | sequence:u8 | status:u8 | payload_length:u16le | payload | crc16:u16le`, CRC-16/CCITT-FALSE — confirmed against the routine at `0x8d6` in the boot ROM (`movw r5, #0x1021`, `movw r0, #0xffff`).

The signet is 144 bytes: `RCVT` magic, version, flags, device UID, authorized image digest, authorized counter, challenge nonce, service op counter, and a 64-byte ECDSA-P256 signature over the first 80.

**The split that makes the attack possible:** the spine checks only the *envelope* — magic, version, 144-byte length — before forwarding. The ward checks everything else. A malformed signet is turned away by the spine and *"draws no ward response at all"* — no `AUTH_DENIED`, no trigger. So the signet must be structurally flawless and cryptographically worthless at the same time. Taking the factory header verbatim and zeroing the signature satisfies both.

Observed status values: `00` OK · `01` AUTH_DENIED · `02` BUSY · `03` record queued. No other values were seen; the full status enumeration is not documented and was not exhaustively probed (§14).

---

## 4. Deriving the delay

`0x2c2` is called at `0xc2`. `D_drv = 221` covers the return into the boot flow, landing at `0xc6`. From there:

```
000000c6  ldrb.w r3, [sp, #0xc]    ; challenge[0]        2
000000ca  ldrb.w r2, [sp, #0x1b]   ; challenge[15]       2
000000ce  eors   r3, r2                                  1
000000d0  and    r3, r3, #0x1f     ; N = 0..31           1
000000d4  cbnz   r3, #0xe4  ─┐     ; 3 taken / 1 exit
000000e4  nop               ←┤                           1
000000e6  subs   r3, #1      │                           1
000000e8  b      #0xd4  ─────┘                           3
...
0000010e  cmp    r0, #0            ; the verdict, at last
00000110  it     eq
00000112  orreq  r2, r2, #1
00000116  cmp    r2, #0
00000118  beq    #0x30             ; ← THE GATE
```

`r6 = sp+0xc` is the 16-byte challenge buffer, so `sp+0x1b` is its last byte. Loop body is 8 cycles (`cbnz` taken 3 + `nop` 1 + `subs` 1 + `b` 3), exit is 1.

| Segment | Cycles |
|---|---|
| `0xc6`–`0xd0` | 6 |
| Loop × N | 8N |
| Loop exit | 1 |
| `0xd6`–`0x116` straight-line, non-burning path | 26 |
| `D_drv` | 221 |
| **Total** | **`254 + 8N`** |

Three earlier `beq #0x30` guards at `0xe0`, `0xfa`, `0x104` all fall through on any boot with valid flash — they check NV-counter range, image counter nonzero, and counter ordering. `0x118` is the only real gate.

**`cbnz` is absent from the datasheet's cycle table.** It was priced as a conditional branch (3 taken / 1 not) on the grounds that every other row of that table is the Cortex-M3 timing model verbatim, and `CBZ`/`CBNZ` on M3 costs 1 not-taken and 1+P = 3 taken. A fallback model at `254 + 7N` was prepared but never needed — and therefore never validated (§14).

---

## 5. The trigger, simplified

The intended pattern presumably matches the `AUTH_DENIED` status byte. It does not have to.

The ward echoes the **opcode** as the first byte of its response, and `0x13` appears exactly once per boot. So:

```
TRIGGER BUS SE PATTERN 13 MASK ff EDGE CS_RISE
```

fires on precisely the right `CS_SE` deassertion edge **without knowing the denial status value at all**. This removed the last unknown before the first shot. `EDGE` is a documented no-op, accepted for compatibility.

The sequence byte must be masked off if included — the datasheet states the ward starts its frame sequence at a fresh unpredictable value every power-on, so an archived trace's sequence number never recurs. A one-byte pattern sidesteps that entirely.

Whether the rig skips the ward's `0xff` wait bytes when matching is **not** stated in the datasheet. The capture makes it near-certain — leading `0xff` runs are 7 bytes on short frames but 151 on the ticket transaction, so a fixed-offset matcher could never hit a fixed-length pattern — but this was inferred, not tested (§14).

---

## 6. Recovering the record

The glitched boot produced 19 `READ_FIFO` transactions. Container, verified against both live and factory data:

```
session_id(4) | idx_le16 | total_chunks_le16 | len_le16 | data[len] | tag16
```

582 bytes of data across 19 chunks, entropy 7.68 — encrypted, not plaintext.

The KDF was recovered by disassembling `fw_recovery.bin`, which was **extracted from `factory_spi.sr`** — the handout's flash capture contains complete reads of both firmware slots at `0x000000` and `0x040000`. Both payloads SHA-256-verify against their own manifest digests, which independently proves the SPI decode byte-exact.

`0x20002772` is textbook HMAC-SHA256 (`ipad 0x36` / `opad 0x5c` over a 64-byte block, SHA-256 at `0x200025f8`/`0x20002650`/`0x20002690`). Two callers matter:

**Session key** — `0x200021c0` builds a 72-byte message and HMACs it under a 32-byte key hardcoded at image offset `0xa8e`:

```
session_key = HMAC-SHA256(K32, prefix8 ‖ SE_nonce(16) ‖ bswap_words(PCR)(32) ‖ host_nonce(16))
K32     = 81a68ed89ebce0bbb7d5f4f08da9d598c3d0ffb0e7e583bdfe8cd980e6ab878b
prefix8 = eccd0a3bb852f71d      # mixed from image constants 0x7f4a7c15 / 0x9e3779b9
PCR     = SHA256(0^32 ‖ M)
M       = SHA256("CINDER-BOOT-v1" ‖ slot_kind(1) ‖ counter_le32 ‖ paysize_le32 ‖ payload_sha256)
```

**Chunk tag** — `0x20002258` computes `HMAC(session_key, sid ‖ idx_u8 ‖ data)[:16]` and constant-time-compares it against the trailer.

**Keystream** — the same function then builds `"RESP"` + `"ONSE"` = `"RESPONSE"`, appends session id, chunk index, and a 16-bit block counter, and HMACs:

```
keystream_i = HMAC(session_key, "RESPONSE" ‖ sid(4) ‖ idx_u8 ‖ blk_lo ‖ blk_hi ‖ 0x00 ‖ 0x00)   # 17-byte info
plaintext_i = data_i XOR keystream_i[:len_i]
```

Chunks are ≤32 bytes, so `blk` is always 0.

> [!important] The tag check is an oracle
> `HMAC(session_key, sid ‖ idx ‖ data)[:16]` can be recomputed from a *candidate* session key and checked against an observed tag **without possessing any plaintext**. That converts the one unknown input — the 32-byte device-bound value — from a 2^256 search into a shortlist of semantically meaningful candidates. Sixteen were tested; `PCR = SHA256(0^32 ‖ M)`, byte-swapped per word, matched. 18/19 tags then verified.

Decrypted record, TLV, 582/582 bytes consumed with no residue:

| Tag | Len | Value |
|---|---|---|
| `0x01` | 1 | *(binary — field semantics unknown, §14)* |
| `0x02` | 18 | `custody-succession` |
| `0x03` | 35 | `House Suncourt of the Velvet Spider` |
| `0x04` | 48 | `Vaultrune Registry, under the Ink Regent's chain` |
| `0x05` | 69 | `Cinderbound coffer, class III / recovery ward; measured-recovery only` |
| `0x06` | 16 | `SEAL-CINDER-0001` |
| `0x07` | 248 | Writ of the Black Heir *(Cassian's order to strike House Suncourt from the registry)* |
| `0x0a` | 64 | *(64 bytes — presumed ECDSA-P256 signature over the record; never verified, §14)* |
| `0x08` | 37 | **`HTB{a_f4ls3_n0t3_0p3ns_th3_tru3_s34l}`** |
| `0x09` | 16 | *(binary — field semantics unknown, §14)* |

---

## 7. Evidence chain — which input yielded which decisive fact

Non-standard section. The solve turned on five inputs, and one of them was disguised as reference material. This table records **what each artifact produced and whether the solve survives without it** — the question a reader reproducing this work actually needs answered.

| Input | Decisive fact it produced | Solve without it? |
|---|---|---|
| `rig.py` | Complete command vocabulary for all three services: `STRAP`, `TRIGGER BUS SE PATTERN/MASK/EDGE`, `GLITCH DELAY/WIDTH`, `CAPTURE ARM`, `POWER CYCLE`, `LIST`, `GET cap-N VCD.GZ`, `TICKET`. Also the capture envelope format (`CINDCAP1`, gzip, SHA-256 sealed). | **No.** The protocol is not discoverable by probing — `ERR SCHEMA` reveals arity, never vocabulary. |
| `TARGET.pdf` | `D_drv = 221`; the per-instruction cycle table; `WIDTH` band 6–16; trigger origin named as `AUTH_DENIED CS_SE` rising edge; the bench cycle ordering (offer held for the *next* boot). | **No.** `D_drv` is stipulated and cannot be derived (§13). Without it the delay is unanchored. |
| `cinder_boot.elf` | The gate at `0x118 beq #0x30`; the verdict surviving ~30 instructions to `0x10e`; and the challenge-keyed loop at `0xd4`–`0xe8` giving `N = (c[0] ^ c[15]) & 0x1f`. | **No.** This is the only source of the `8N` term. Without it, only a blind sweep remains — which the datasheet warns costs more, and which the per-boot changing delay defeats anyway. |
| `factory_service.sr` | SE frame layout; that the ward **echoes the opcode** as its first response byte (→ the one-byte trigger, §5); that wait-byte runs vary 7→151 (→ the matcher must skip them); the 144-byte signet field layout to clone. | **Partially.** A baseline run reproduces most of this live, at the cost of instance time. The signet layout would be harder. |
| `factory_spi.sr` | **Both complete firmware images**, read out of captured flash transactions at `0x000000` and `0x040000`, each SHA-256-verifying against its own manifest. `fw_recovery.bin` yielded the entire session KDF: `K32` at offset `0xa8e`, the 72-byte message layout, the `"UNSEAL"` and `"RESPONSE"` labels, the tag construction. | **No.** Presented as a reference capture of a boot-time flash read. It is the single highest-value artifact in the handout and the one least likely to be opened. Without it the record stays encrypted permanently — the KDF is not guessable, as 24 failed attempts demonstrate (§13). |

**Live inputs, per attempt:**

| Input | Where it comes from | What it feeds |
|---|---|---|
| `CHALLENGE <hex>` | Recovery console offer, before the cycle | `N`, hence `DELAY = 254 + 8N`. Changes every boot — must be read fresh, never cached. |
| host nonce (16 B) | `OPEN_FACTORY_SESSION` **MOSI** | KDF message. Missing this for several rounds made the key underivable in principle. |
| SE nonce (16 B) | `OPEN_FACTORY_SESSION` **MISO**, after the 4-byte session id | KDF message |
| session id (4 B) | `OPEN_FACTORY_SESSION` MISO, first 4 bytes | Both the tag and the keystream info string |
| 16-byte chunk tags | `READ_FIFO` trailers | **The oracle.** Confirms a candidate session key with no plaintext (§6). |

**Outputs that had to be produced:**

| Output | Value used | Constraint it satisfies |
|---|---|---|
| Recovery signet | 144 B, `RCVT`, version `01`, factory header + 64 zero bytes | Envelope valid → spine forwards; signature invalid → ward denies → trigger fires |
| Trigger | `PATTERN 13 MASK ff` | Matches the echoed opcode; independent of the unknown status byte; unaffected by the per-boot sequence value |
| Glitch | `DELAY 366 WIDTH 10` at `N = 14` | `254 + 8×14`; width mid-band |
| Capture | `cap-2.vcd`, 286530 B | Contains the only evidence the attack worked — no service line reports it |

**The decisive realisation, stated plainly:** the boot ROM tells you *where* to glitch, the datasheet tells you *how far*, the live challenge tells you *how long to wait this time*, and the reference flash capture tells you *how to read what you stole*. Four separate artifacts, and skipping any one of them ends the solve.

---

## 8. Final payload

```bash
# 0. handout
cd Fault_in_the_Cinder
unzip -P hackthebox a252eda0-b568-4641-aaff-5591e270bec1-1784770577.zip

# 1. baseline — invalid signet, NO glitch. Confirms deny, prints the live challenge.
python3 cinder_attack.py 154.57.164.78 --rig 30380 --la 32205 --service 31146 baseline

# 2. glitch — derives DELAY from the live challenge, fires one pulse
python3 cinder_attack.py 154.57.164.78 --rig 30380 --la 32205 --service 31146 glitch

# 3. re-pull an existing capture without burning a boot
python3 cinder_attack.py 154.57.164.78 --la 32205 fetch --cap 2
```

Manual equivalent, in the datasheet's mandated cycle order (offer and signet are held for the **next** power cycle, not the current one):

```
console : read offer -> CHALLENGE <hex>;  TICKET <base64 of 144-byte RCVT, signature zeroed>
rig     : STRAP RECOVERY
          RESET RIG
          TRIGGER BUS SE PATTERN 13 MASK ff EDGE CS_RISE
          GLITCH DELAY <254 + 8*((c[0]^c[15])&0x1f)> WIDTH 10
          CAPTURE ARM INTERNAL_SPI
          POWER CYCLE
clamp   : GET cap-<N> VCD.GZ    -> decode SPI -> READ_FIFO -> decrypt
```

Toolchain (three files, `cinder_attack.py` loads the other two from its own directory):

- `cinder_signet.py` — builds the 144-byte `RCVT` with zeroed signature
- `cinder_capture.py` — VCD/`.sr` loader, SPI decode, frame parse, record reassembly, KDF decrypt
- `cinder_attack.py` — `baseline` / `glitch` / `sweep` / `fetch` phases

---

## 9. Tools & techniques

`python3` (stdlib `socket`, `hashlib`, `hmac`, `struct`, `gzip`) · `capstone` 5.0.1 (Thumb-2 / `CS_MODE_MCLASS`) · `readelf` · `pdftotext` · `unzip` · `curl` (`--http0.9`) · `nc` · `sha256sum`

Concepts: voltage/clock **fault injection** against a measured-boot authority check · trigger-on-bus-pattern with masked volatile fields · **cycle-accurate delay derivation from disassembly** (Cortex-M3 timing model) rather than parameter sweep · signet envelope-vs-signature validation split · SPI mode-0 decode from raw logic samples · firmware recovery from a captured flash read · HMAC-SHA256 as KDF, MAC, and keystream · **MAC-as-oracle** for key-candidate confirmation without plaintext · TLV record parsing.

---

## 10. MITRE ATT&CK

Split by what the attack physically did versus what it collected.

**Attack chain:**

- **T1200** Hardware Additions — an unauthorised fault-injection rig and logic clamp attached to the device's service header, which is the entire attack surface
- **T1211** Exploitation for Defense Evasion — the glitch defeats the boot ROM's authorization check without defeating the cryptography it enforces; the ward's verdict is never forged, only ignored
- **T1552.004** Unsecured Credentials: Private Keys — the record's session-protection key is fully derivable from material observable on the internal bus, so the confidentiality boundary collapses once the bus is clamped

**Collection / recon:**

- **T1040** Network Sniffing — passive capture of the internal SPI bus via the analyzer clamp; the record, the nonces, and both firmware images all come from captured traffic
- **T1592.002** Gather Victim Host Information: Software — firmware images recovered from captured flash reads and disassembled to obtain the key-derivation function

> [!warning] Honest scope of this mapping — verify the IDs before trusting them
> ATT&CK is an enterprise-intrusion framework; this is physical fault injection against an embedded secure-boot chain. The techniques are listed because the **behaviour shape** matches, not because an enterprise host was touched. **All five IDs were assigned without access to the live ATT&CK matrix and are unverified.**
> **`T1211` is the weakest.** "Exploitation for Defense Evasion" is defined around software vulnerability exploitation; applying it to a physical glitch that omits an instruction stretches the definition. There is no Enterprise technique for *"the branch that acts on a failed authorization was never executed."*
> **ATT&CK for ICS is likely the better matrix** and was not consulted. This is the same gap recorded in `[[HTB-CA2026-Saltlock-Drift-RollJam-Rolling-Code-Replay]]` §10 — two hardware rooms now, both flagged, neither resolved.
> The accurate classification of the primary defect is **CWE-1247** (improper protection against voltage/clock glitches) with **CWE-1300** (improper protection of physical side channels) adjacent — not an ATT&CK technique at all.

---

## 11. Detection, hardening & defensive strategy

Widened from the canonical *Detection / blue-team & fix notes* slot. Ordered by leverage, not by narrative.

### 11.1 The root finding

**Measured boot proved what code was running; it never proved that code was authorized to run.** `EXTEND_BOOT_PCR` and `LOCK_MEASUREMENT` both executed against the genuine recovery image, `BOOT_PCR` matched the sealing policy, and the ward unsealed exactly as designed. The integrity control functioned perfectly and was orthogonal to the attack.

Sealing to a PCR defends against a *substituted* image. It does not defend against an *unauthorized boot of the legitimate image*. Any design that treats "the right firmware is running" as a proxy for "this boot is permitted" carries this gap.

### 11.2 Hardening, by leverage

| Priority | Control | Effort | Defeats |
|---|---|---|---|
| **1** | **Latch the denial in the secure element.** After emitting `AUTH_DENIED`, refuse `EXTEND_BOOT_PCR`, `OPEN_FACTORY_SESSION` and `UNSEAL` until the next power cycle. | Low | This attack entirely, independent of the host CPU's behaviour |
| **2** | **Redundant, time-separated authorization.** Recompute the verdict after measurement and again immediately before unsealing. | Medium | Requires multiple precisely-timed glitches instead of one |
| **3** | **Bidirectional confirmation before privilege.** Have the ward require a fresh proof-of-authorization token in the `OPEN_FACTORY_SESSION` request, rather than trusting that the caller reached that point legitimately. | Medium | Removes the implicit trust that reaching a code path implies permission |
| **4** | **Hardware glitch detection.** Supply and clock monitors, brown-out detectors, redundant instruction fetch. | High — silicon | The injection primitive itself |
| **5** | **Random jitter, not challenge-derived.** The existing spin loop is derived from a value the attacker reads, so it is fully predictable to them and only costly to the naive. | Low | Blind sweeps only — do not mistake it for a countermeasure against a derived attack |
| **6** | **Do not derive session keys solely from bus-observable material.** Every KDF input except one hardcoded firmware constant travelled the bus in the clear, and that constant is disclosed by the same bus. | Medium | Passive record recovery after a successful bypass |
| **7** | **Treat reference captures and datasheets as attack material.** The handout's diagnostic capture contained both complete firmware images. | Low — process | Firmware recovery without physical flash access |

### 11.3 Detection — what is actually observable

- **The impossible-sequence invariant.** A boot that receives `AUTH_DENIED` and subsequently issues `OPEN_FACTORY_SESSION` in the same power cycle cannot occur in a correct implementation. **This is free, needs no cryptography, and is the single highest-value detection available.** It is also the one the device currently cannot report, because the boot ROM logs nothing about the refusal it ignored.
- **Physical-layer anomaly at a fixed offset.** The glitch lands a deterministic number of cycles after a `CS_SE` deassertion. A supply/clock monitor correlating anomalies against bus events would see a tight, repeatable relationship.
- **Counter and measurement telemetry.** The NV counter, the PCR value, and the recovery-boot count are all available to the ward. A recovery boot that unsealed without a corresponding successful ticket verification is reconstructible from that state alone, after the fact.
- **What is *not* detectable:** the glitch produces no software-visible error, no exception, no log entry. The instruction simply does not execute. Post-hoc forensics on the host would show a clean, successful recovery boot.

### 11.4 Design principles this room demonstrates

- **A correct decision that is not enforced is not a control.** The cryptography was never broken. The refusal was accurate. It was discarded by one branch.
- **Latch security decisions at the component that made them.** The ward knew the answer and did not act on its own knowledge.
- **Single points of failure in authorization deserve the same scrutiny as single points of failure in availability.** One `beq` gated the entire confidentiality boundary.
- **Obfuscation that an attacker can read is not obfuscation.** The challenge-derived delay raised the cost of the lazy attack and lowered nothing else.

---

## 12. Method notes

- **Reading `rig.py` first was worth more than any other single hour.** It documented the full command vocabulary for all three services before a single byte was sent, and revealed that `trigger()`/`glitch()` existed but were unwired — i.e. that the campaign driver was the deliverable.
- **The datasheet said "derive, do not sweep," and it meant it.** `254 + 8N` landed on the first attempt. The temptation to sweep is strongest exactly when the derivation looks hard, and here the derivation was the shorter path.
- **`curl`'s error was the recon.** `Received HTTP/0.9 when not allowed` reads as failure but means "connected, replied, not HTTP." The `ERR NOCAP` / `ERR SCHEMA` asymmetry across ports identified the clamp before any deliberate probe was sent.
- **The pipeline ate the banners and I believed the pipeline.** `timeout 8 nc … | head -c 2000 | xxd` returned empty on all three ports, and that was reported as "genuinely silent on connect, not a pipeline artifact" — the correct explanation was named and then dismissed. All three banner on connect. **When a null result contradicts a plausible tooling artifact, suspect the tooling before the target.**
- **Hardcoding a magic from the reference capture silently corrupted the live parse.** The record parser keyed on `3305e00d` from the factory capture; live sessions get a fresh id (`90e0454c`), so all 19 chunks failed and fell through to a raw-append path that reported "1076 bytes, 0 tags." **Parse structurally; a value that varies per session is not a magic number.**
- **Printing only one direction of a bidirectional protocol made the problem unsolvable in principle.** The decoder showed MISO only, hiding the host nonce, while several rounds of keystream guessing ran against half the key material. **If a protocol has two sides, decode both before theorising.**
- **Four wrong turns shared one shape: inferring from visible structure instead of reading available code.** All are recorded in §13. The firmware was recoverable from the first ten minutes. **When a guess fails twice, stop guessing and go find the implementation.**
- **The MAC was the oracle that finished the challenge.** Once a candidate session key could be tested against an observed tag with no plaintext, the last unknown stopped being a search and became a shortlist. This is the same lesson Secondhand recorded — build the oracle before the third guess — arriving one guess late.
- **Verifying extracted firmware against its own manifest digest was free confirmation.** Both images SHA-256-matched their manifests, which simultaneously validated the firmware *and* proved the SPI decoder byte-exact. **Prefer extraction steps that come with their own checksum.**
- **Narrative language was literal for the third time in four hardware rooms.** "Fault" named fault injection; "learn the ritual" named the challenge-derived delay; "listen as the old ward speaks" named the clamp as the readout. Only What the Shard Displayed evoked rather than specified.

---

## 13. Blind alleys

Technical paths tried and eliminated. Recorded because a later reader cannot reconstruct them from the solve.

- **`D_drv` as a calibration oracle for the cycle model.** The plan was to count the window the datasheet already gives an answer for (221 cycles) and check whether the cycle model reproduced it, thereby validating the `cbnz` pricing. It does not close: the CRC-16 routine at `0x8d6` costs ≈81 cycles per byte under the datasheet's own convention, so a 7-byte header alone is ≈567 cycles. `D_drv` is a **stipulated** constant, given precisely because hand-counting it does not reproduce it. **The cycle model cannot be validated from the handout.**
- **The record read as AEAD ciphertext.** Each chunk carries 32 data bytes plus a 16-byte trailer, and the reassembled factory record was structureless at 6.76 bits/byte. That shape was taken as evidence of an AEAD tag over encrypted data. It is an HMAC-SHA256 integrity tag over data that is separately XOR-encrypted — encrypt-then-MAC, not AEAD, and the distinction mattered because it sent the search toward AEAD constructions.
- **"No cipher in firmware, therefore the record arrives plaintext."** Neither image contains an AES S-box, Te table, ChaCha constant, or any 256-byte permutation table. That was read as proof the record could not be encrypted. **Wrong: HMAC-SHA256 in counter mode is a stream cipher.** Absence of a block cipher says nothing about confidentiality.
- **Twenty-four key-derivation constructions, all wrong.** Six candidate keys (`sha256(host‖se)`, `sha256(se‖host)`, `sha256(host^se)`, `hmac(se,host)`, `hmac(host,se)`, `sha256(sid‖host‖se)`) × four keystream shapes (`sha256(k‖ctr)` and `hmac(k,ctr)`, each little- and big-endian). None produced printable output. The failure was structural, not combinatorial — the real construction uses a hardcoded firmware key and a labelled info string, neither of which is guessable from bus traffic alone.
- **`M` rather than `PCR` as the KDF's device-bound input.** The datasheet says the boot ROM *"extends the measurement once with M"*, which was read as "the KDF binds to M." It binds to `PCR = SHA256(0^32 ‖ M)` — a real PCR extend from a zero starting value. `M` was tested against the tag oracle and rejected; `PCR` matched.
- **Stub-generated values for the KDF's 32-byte input.** The shipped firmware fills that buffer from `0x200023fc`, which produces a deterministic ramp (`00 01 02 … 1f`) seeded from a zeroed `.bss` global. Both the ramp and an all-zero buffer were tested and rejected. The reference image models the *algorithm* but not the device's entropy source, so its nonce generators cannot be used to predict live values.

---

## 14. Open items

Each entry states what is not known **and what would settle it**. Nothing is omitted for tidiness — an absent field and an unrecorded field are indistinguishable to a later reader, so gaps are named explicitly.

**Metadata**

- **`solves` — not captured, frontmatter field absent.** The scenario page was read for `points: 975` and `difficulty: hard`, but the solve count at time of solve was never recorded, and standard §1.2 forbids guessing it. **To resolve:** read it off the HTB scoreboard while the event is live (closes 2026-07-29). After close, the at-solve-time figure is likely unrecoverable; any later reading is a different measurement and should be recorded with its own date rather than backfilled here.
- **`points: 975` is a correct-at-the-time snapshot, not a constant.** It drifts downward with solve count across this event. **To resolve:** nothing required — pair it with `solves` once known so the pair stays interpretable, per the event roll-up's convention.

**Classification**

- **All five ATT&CK IDs are unverified.** Assigned without access to the live matrix. **To resolve:** check each against attack.mitre.org. `T1211` is the weakest and the most likely to be wrong.
- **ATT&CK for ICS was not consulted.** It probably fits physical fault injection better than Enterprise. **To resolve:** review the ICS matrix for a boot-authorization-bypass technique. Second hardware room to record this gap after Saltlock Drift §10; neither is resolved.

**Timing model**

- **`cbnz` cycle cost is inferred, not documented.** Priced 3-taken / 1-not-taken on the Cortex-M3 model. Model A worked first try — strong evidence, but a single sample cannot distinguish "correct" from "within the rig's undocumented tolerance." **To resolve:** cannot be settled from the handout. Needs either an ARM TRM citation for `CBZ`/`CBNZ` on this core, or a deliberate two-shot experiment firing model A (`254 + 8N`) and model B (`254 + 7N`) against the same challenge value.
- **Model B (`254 + 7N`) was never exercised.** Prepared as a fallback, never needed. **To resolve:** as above — it is only distinguishable from model A when N is large enough that `N` cycles exceeds the rig's tolerance.
- **The rig's delay tolerance is unmeasured.** The datasheet says "within a small tolerance" and gives no number. **To resolve:** on a live bench, hold the challenge constant and walk DELAY outward from the derived value until the glitch stops landing. One boot per step, subject to `POWER CYCLE` pacing.
- **`WIDTH` was never varied.** 10 was chosen mid-band and worked on the first attempt. **To resolve:** sweep 6–16 at a known-good delay. The band's edges are stated by the datasheet, not observed here.

**Trigger behaviour**

- **Whether the rig skips leading `0xff` wait bytes when matching is inferred.** The capture makes it near-certain (wait runs vary 7→151 bytes, so a fixed-offset matcher could not function), but the datasheet never states it. **To resolve:** set a pattern deliberately prefixed with `ff` and observe whether `TRIGGERED` still fires.
- **`EDGE` is documented as a no-op and was never tested.** `CS_RISE` was used throughout. **To resolve:** issue an otherwise identical `TRIGGER` with a different `EDGE` value and confirm behaviour is unchanged.
- **The secure element's full status enumeration is unknown.** Only `00`, `01`, `02`, `03` were observed. **To resolve:** no clean method from the three exposed services; would require firmware for the ward itself, which is not in the handout and is not on the bus.

**Cryptography and record**

- **The 32-byte KDF input was identified by candidate search, not by trace.** `PCR = SHA256(0^32 ‖ M)` was confirmed via the tag oracle after sixteen candidates. **To resolve:** trace the live bench's population of the buffer read by `0x200023fc`. Not possible from the handout — the shipped stubs generate ramps that do not match live nonces, so the answer would require bench-side introspection the three services do not expose. The tag oracle makes this moot in practice but the derivation path is unproven.
- **Chunk `0x03`'s tag failed verification (18/19).** Attributed to a hand-transcription error copying hex out of terminal output — the observed value is a nibble-shift of the computed one. **To resolve:** re-run `cinder_capture.py` against the saved `cap-2.vcd` and compare programmatically. Not done; the conclusion currently rests on visual inspection of two hex strings.
- **The `0xa5a5a5a5` mixing routine at `0x200021d2` is computed but not understood.** Its output — the fixed 8-byte KDF prefix `eccd0a3bb852f71d` — is correct and verified by the tag oracle. **To resolve:** whether it is a PRNG, a domain separator, or vestigial cannot be determined from one firmware revision; would need bench source or a second revision to diff.
- **Record TLV tags `0x01`, `0x09` and `0x0a` are unidentified.** `0x0a` is 64 bytes and presumed an ECDSA-P256 signature over the record; `0x01` (1 byte) and `0x09` (16 bytes) are unknown. **To resolve:** `0x0a` is testable — verify it against the Registry public key if one can be extracted from either firmware image. `0x01` and `0x09` would need a second record with different contents to diff against, which the bench does not provide.

**Coverage**

- **Repeatability was never established.** One successful glitch, one value of N. **To resolve:** repeat on a fresh instance with a different challenge and confirm `254 + 8N` holds for a second N. **This is the highest-value follow-up in this list** — it converts a single data point into a validated model, and it is cheap.
- **The `sweep` phase in `cinder_attack.py` is untested code.** Written as a fallback, never executed. **To resolve:** run it against a live instance, or delete it. Untested fallback code in a tool that will be reused is a liability.
- **`fw_production.bin` was extracted and digest-verified but never disassembled.** Counter 5, 1236 bytes. **To resolve:** disassemble it, and/or run a production-strapped boot, to determine whether the same gate exists on that path or whether recovery-strap is required.

**Structure**

- **This note deviates from `00_ctf-writeup-standard` in three documented ways** (see the structure callout at the head): an unnumbered Executive brief, a non-standard §7 Evidence chain, and a widened §11. **To resolve:** if the standard adopts any of these as optional sections, update it and remove this item; if it rejects them, this note is a sanctioned exception and should be listed in standard §6 as such rather than silently corrected.

---

## Cross-references
- [[CA2026-Hardware-category-kickoff]]
- [[HTB-CA2026-Saltlock-Drift-RollJam-Rolling-Code-Replay]]
- [[HTB-CA2026-Cadence-in-the-Cord-UART-Inter-Frame-Timing-Covert-Channel]]
- [[HTB-CA2026-What-the-Shard-Displayed-I2C-SSD1306-Framebuffer-Reconstruction]]
- [[HTB-CA2026-Cinderbound-MicroPython-MPY-Rolling-XOR]]
- [[HTB]]

## Change Log
- 2026-07-30 — The two prose references to the writeup standard updated to its post-rename filename (`00_ctf-writeup-standard`). Both are backticked filenames rather than wikilinks, so Obsidian's rename refactor did not reach them.
- 2026-07-27 — Note created. Solved: three-service remote fault bench; boot ROM disassembled to locate the authorization gate at `0x118 beq #0x30` and derive the glitch delay as `254 + 8N` where `N = (challenge[0] ^ challenge[15]) & 0x1f` from a challenge-keyed spin loop at `0xd4`–`0xe8`. 144-byte `RCVT` signet built with zeroed ECDSA signature so the spine forwards it and the ward denies it; one-byte trigger `PATTERN 13 MASK ff` on the echoed opcode removed any dependence on knowing the `AUTH_DENIED` status value. Glitch landed first attempt at `DELAY 366 WIDTH 10`. Record recovered by extracting both firmware images from the handout's `factory_spi.sr` flash capture (both SHA-256-verified against their manifests), disassembling `fw_recovery.bin` to recover the HMAC-SHA256 session KDF, and confirming the session key via the per-chunk MAC used as an oracle. ATT&CK mapping split attack/collection, all IDs flagged unverified, CWE-1247 named as the accurate classification. §13 Blind alleys records six eliminated technical paths; §14 Open items states a resolution condition for every unknown rather than omitting unrecorded values. **Three deliberate deviations from the writeup standard, recorded in the head callout and §14: an unnumbered Executive brief with defensive talking points and prioritised hardening; a non-standard §7 Evidence chain mapping each input to the decisive fact it produced and whether the solve survives without it; and §11 widened from *Detection / blue-team & fix notes* to *Detection, hardening & defensive strategy*. Canonical tail order preserved.**
