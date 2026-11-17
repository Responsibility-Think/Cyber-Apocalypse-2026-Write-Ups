---
title: "HTB CA2026 — Saltlock Drift: RollJam Rolling-Code Replay"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Saltlock Drift
app: "RiverGate RF-433 console (raw TCP) + Saltlock car/fob UI (HTTP)"
category: hardware
difficulty: medium
points: 975
type: writeup
status: complete
mitre:
  - T1200
  - T1040
  - T1498
  - T1557
  - T1550
tags:
  - writeup
  - HTB
  - Security
  - Hardware
  - RF
  - replay-attack
  - rolling-code
  - jamming
  - detection
related:
  - "[[HTB-CA2026-Cadence-in-the-Cord-UART-Inter-Frame-Timing-Covert-Channel]]"
  - "[[HTB-CA2026-What-the-Shard-Displayed-I2C-SSD1306-Framebuffer-Reconstruction]]"
aliases:
  - Saltlock Drift
  - CA2026 Saltlock Drift
created: 2026-07-25T16:59:34.603Z
updated: 2026-07-25T16:59:34.603Z
---

# Saltlock Drift — RollJam Rolling-Code Replay

> [!success] Solved
> Flag: `HTB{r0llj4m_5alt_f0b_5pl1t_fcfbd2bbc216255cfb786b0394674fb3}`
> Jam the receiver so it never hears two fob presses, then replay the captured frames while their counters are still ahead of `last_counter`. Final verdict: `CAR ACCEPT source=attacker button=unlock counter=18295 result=exploit_unlock`.
> Two network services, no artifact file, no binary. Third hardware-category solve of the event.

## 0. How the flag was obtained

1. Two ports issued. `30876` served a 34 KB HTML UI; `32191` initially unreachable (container fault) and required a respawn before it answered.
2. Swept `30876` — 780 requests, only `GET /api/state` and `POST /api/fob` real. **No attacker surface on the web port**; it is the car and the owner's fob, nothing more.
3. Read the frontend: `pressFob()` is bound only to two `onclick` handlers and the sole timer does `GET /api/state`. **The UI never presses the fob on its own** — which later mattered.
4. Polled `/api/state` across eight presses and established `receiver_counter = 18281 + tick`, stepping by exactly 1 per accepted press, shared across lock and unlock.
5. `32191` is a **raw TCP console** (`RiverGate RF-433`), not HTTP — a browser fed its request headers to the command parser and got nine `ERR unknown_command` lines back. Commands: `HELP, STATUS, JAM ON, JAM OFF, TX <hex>, QUIT`.
6. The console mirrors every fob press as an `RX ... raw=<hex>` line. Nine captured frames decoded to a fixed 18-byte layout with a 16-bit big-endian counter (§3).
7. The 6-byte tail showed no structure across nine samples → keyed authenticator, **not forgeable**. A replayed frame carries its original counter; replay is the only path.
8. All nine captured frames were already consumed (`CAR ACCEPT` on each), so every one was stale. A fresh code the car has *never seen* is required — which is what jamming buys.
9. `JAM ON` → two fob presses via `POST /api/fob` → each produced `RX` at the console plus **`CAR MISS source=fob button=unlock reason=channel_jammed`**. Jam blocks the receiver but not the sniffer. Counters 18295 and 18296 held; `last_counter` stayed at 18294.
10. `JAM OFF` → `TX` the held frames in ascending counter order → `CAR ACCEPT source=attacker counter=18295 result=exploit_unlock`, and `STATUS` flipped `flag=hidden` → `flag=visible`.

## 1. Shape of the challenge

No file ships. Two live services model opposite ends of one RF link: a car with a rolling-code receiver, and a shared-band console that both sniffs and transmits. The scenario names the technique — *"reveal the token through a replay attack"* — but omits the part that makes a naive replay fail, which is the rolling counter. "Drift" is the missing half: counter desync between fob and receiver, manufactured by jamming.

## 2. Recon — two ports, one of them a decoy

| Port | Service | Role |
|---|---|---|
| 30876 | `SaltlockHTTP/1.0 Python/3.12.13` | Car + owner's keyfob UI. **Victim, not toolkit.** |
| 32191 | `RiverGate RF-433` raw TCP | Sniffer + jammer + transmitter. The actual attack surface. |

The web port's route table is exactly two entries. A 780-request sweep across 68 words × 2 prefixes × 2 slash variants × 3 methods returned 518 clean 404s and 260 × 501 — the 501s being `BaseHTTPRequestHandler`'s default for a missing `do_PUT`, uniform across every path including nonsense ones, therefore method-level noise rather than routes.

State object (`GET /api/state`) carries one field the UI never renders:

```json
{"locked": false, "jammed": false, "receiver_counter": 18282,
 "channel": "433.920 MHz OOK", "uptime": 8364,
 "events": [...], "signal": {"tick": 1, "kind": "fob_accept", "history": [...]}}
```

`uptime` is server-side only. `receiver_counter = seed + tick` held across every observation, seed 18281.

## 3. Frame anatomy

18 bytes, five fields, recovered by aligning nine `RX` captures against their logged `counter=` values:

```
AAAAAAAA  2DD4  534C54  02   476B  49E09031E7A8
└preamble └sync └"SLT"  └btn └ctr  └authenticator
   4B       2B    3B     1B   2B        6B
```

| Field | Value | Notes |
|---|---|---|
| Preamble | `AAAAAAAA` | `10101010…` — standard OOK clock-recovery pattern |
| Sync | `2DD4` | Constant across all frames |
| Device ID | `534C54` | ASCII **`SLT`** — matches the `SLT` brand mark rendered on the fob in the UI |
| Button | `01` / `02` | lock / unlock |
| Counter | 16-bit BE | `476B` = 18283, matching `counter=` exactly on all nine |
| Authenticator | 6 bytes | 9 distinct of 9; XOR deltas structureless |

The tail is a keyed MAC bound to the counter. You cannot increment a counter and re-sign, which is precisely why the intended solution is replay rather than forgery.

## 4. Why the obvious replay fails

Every frame observed in normal operation has already been accepted, so its counter is `<= last_counter` by the time you could transmit it:

```
CAR REJECT source=attacker button=unlock counter=18292 reason=replay_or_old_counter
```

Note the service already labels the transmitter `source=attacker` — it is willing to accept from you. Only the counter was wrong. The receiver accepts strictly forward of `last_counter`, so a usable frame must be one the car **never received**.

## 5. The jam — manufacturing the drift

```
> JAM ON
< CH STATE jammer=on freq=433.920MHz
< RX freq=433.920MHz modulation=OOK rssi=-41dBm raw=AAAAAAAA2DD4534C54024777557386DD8852
< CAR MISS source=fob button=unlock reason=channel_jammed
```

That `CAR MISS` line is the entire attack in one message. The console still hears the frame; the car does not. The fob's internal counter advances on every press regardless, so each jammed press widens the gap:

| Event | Fob counter | `last_counter` | Gap |
|---|---|---|---|
| baseline | 18294 | 18294 | 0 |
| jammed press 1 | 18295 | 18294 | 1 |
| jammed press 2 | 18296 | 18294 | 2 |

Two frames now held, both forward of the receiver, both bearing valid authenticators the attacker never had to compute.

## 6. The replay

```
> JAM OFF
> TX AAAAAAAA2DD4534C54024777557386DD8852
< CAR ACCEPT source=attacker button=unlock counter=18295 result=exploit_unlock
> TX AAAAAAAA2DD4534C540247785A62DF358517
< CAR ACCEPT source=attacker button=unlock counter=18296 result=exploit_unlock
> STATUS
< STATUS lock=unlocked jammer=off last_counter=18296 flag=visible
```

`result=exploit_unlock` distinguishes this from the `result=owner_unlock` that every legitimate press produced. **The first frame was sufficient** — 18295 alone flipped `flag` to `visible`; transmitting 18296 was redundant. The classic RollJam rationale for holding two codes is to replay the first so the owner's press appears to work and they stop pressing, keeping the second for later. Here the challenge only needed one, but the two-capture default cost nothing and preserved margin.

## 7. The race that burned the first attempt

The first capture attempt was run with `--dry` (capture, print, do not transmit) to verify jamming actually blocked the receiver before committing. It confirmed the model — and lost the codes.

| | `last_counter` | Held |
|---|---|---|
| after `--dry` capture | 18291 | 18292, 18293 |
| at manual `TX`, minutes later | **18294** | both stale |

One lock press landed in the gap between the dry run and the copy-pasted `TX`, advancing the receiver past both held frames. Both were rejected `reason=replay_or_old_counter`.

**The verification step created the vulnerability window.** In a time-critical attack, a human-in-the-loop confirmation is not a free safety check — the latency it introduces is itself the failure mode. The successful run used the identical tool with no manual step: jam, capture, unjam, transmit, all inside one automated sequence with roughly a second between unjam and first transmit.

Reading the frontend mattered here. Because `pressFob()` is bound only to `onclick` and the sole `setInterval` does a read-only `GET`, the UI could be ruled out as an automatic presser — so closing the browser tab was sufficient to guarantee nothing would race the transmit.

## 8. Final payload

```bash
# 1. identify the ports (one serves HTML, the other is the raw console)
python3 saltlock-probe-v2.py 154.57.164.79 30876
nc 154.57.164.79 32191        # RiverGate banner + STATUS

# 2. jam / capture / replay in one uninterrupted sequence
python3 saltlock-rolljam.py --host 154.57.164.79 --rf 32191 --web 30876 --captures 2
```

Manual equivalent, two terminals — jam and capture in one, fob presses in the other:

```
JAM ON
  (POST /api/fob {"button":"unlock"}  x2  -> two RX lines, two CAR MISS)
JAM OFF
TX <frame with the lower counter>
TX <frame with the higher counter>
STATUS
```

The driver script (`saltlock-rolljam`) opens the TCP console with a background line reader, drives the fob over HTTP, parses `raw=` out of the `RX` lines, aborts if a `CAR ACCEPT` appears while jammed (which would mean jamming is not blocking reception and the model is wrong), and transmits held frames in ascending counter order.

## 9. Tools & techniques

`nc` · Python 3 stdlib only — `socket`, `threading`, `urllib`, `re`, `argparse`. No SDR, no `rtl_433`, no GNU Radio: the RF layer is simulated as line-oriented text, so the whole attack is socket plumbing.

Concepts: rolling-code (KeeLoq-family) authentication · counter desync / drift · **RollJam** jam-capture-replay · frame field alignment against logged metadata · keyed-MAC recognition by absence of structure · race-window elimination in time-critical attacks.

## 10. MITRE ATT&CK

Split into the attack itself and the collection that enabled it.

**Attack chain:**

- **T1200** Hardware Additions — an unauthorised transceiver introduced onto the shared 433.920 MHz band, capable of both receiving and transmitting
- **T1498** Network Denial of Service — the jammer denies the receiver its channel; availability loss is not the goal here but the enabler
- **T1557** Adversary-in-the-Middle — jam-and-withhold is structurally AiTM: the attacker intercepts a message the legitimate parties expect to exchange, suppresses delivery, and forwards it later on their own terms
- **T1550** Use Alternate Authentication Material — the replayed frame is a captured, still-valid authenticator used to bypass access control without ever recovering the key

**Collection:**

- **T1040** Network Sniffing — passive capture of frames in transit on a shared medium

> [!warning] Honest scope of this mapping — verify the IDs before trusting them
> ATT&CK is built around enterprise network intrusion; this is RF access control against a vehicle. The techniques are listed because the **behaviour shape matches**, which is what transfers to defenders, not because an enterprise host was touched.
> **All five IDs were assigned without access to the live ATT&CK matrix and are unverified.** `T1557` (AiTM) and `T1550` (Alternate Authentication Material) are the most analogical — both are defined around network and credential material, and applying them to an RF authenticator is an extension of the concept. Confirm against attack.mitre.org before treating this frontmatter as authoritative — the same discipline that produced the T1496.004 → T1496.001 correction.
> **ATT&CK for ICS may map this better than Enterprise.** There is a dedicated ICS replay technique that is likely a closer fit than `T1550`; the ID was not verifiable in this session and has deliberately been left out rather than guessed at.

## 11. Detection / blue-team & fix notes

- **A rolling counter alone does not stop replay.** It stops *naive* replay. Any receiver that accepts strictly-forward counters is defeated by an attacker who can prevent the receiver from ever advancing. The counter proves freshness relative to the receiver's own state, and that state is attacker-influenceable.
- **The jam is the detectable half, not the replay.** A replayed frame is bit-identical to a legitimate one and cannot be distinguished at the receiver. The channel loss preceding it can be: sustained noise-floor elevation, or a run of received-but-unvalidated frames, is the signature. **Log and alert on jam-like conditions, because by the time the replay arrives there is nothing left to detect.**
- **Counter gaps are free telemetry.** After a RollJam the receiver jumps 18294 → 18295 with no intervening traffic, while the fob believes it has sent more. Any receiver that logs accepted counters can flag "accepted counter arrived after a period of channel loss" — a cheap, high-signal rule that needs no cryptography.
- **Bidirectional challenge-response is the actual fix.** If the receiver issues a nonce the fob must sign, a captured transmission is worthless because it answers a challenge that will never be issued again. This is why modern immobilisers and UWB-based passive entry moved to challenge-response and distance bounding; one-way rolling codes are a 1990s design still shipping.
- **Time-bound the window.** Even without full challenge-response, expiring codes after a short interval or capping the forward-acceptance window sharply limits how long a held capture stays useful.
- **Physical-layer monitoring belongs in the threat model.** Sniffing this channel required no credentials, no exploit, and no key recovery — just presence on the band.

## 12. Method notes

- **The verification step created the failure.** `--dry` proved jamming worked and simultaneously lost the codes to human latency. In time-critical attacks, confirm the model on captures you can afford to burn, then run the real attempt fully automated. **A safety check that widens the window is not a safety check.**
- **Reading the frontend paid off twice.** The 34 KB UI ruled out a browser-side auto-presser (`pressFob` only on `onclick`, `setInterval` read-only), which meant closing the tab was sufficient to guarantee a clean run. It also supplied the `SLT` brand mark that later confirmed the `534C54` device ID.
- **Proving the negative was worth the 780 requests.** Three passes over the web port established there was no attacker surface there, which converted "keep poking" into "respawn the broken port" — the correct call, and one that would have been guesswork otherwise.
- **The console is TCP, not HTTP.** Nine `ERR unknown_command` lines were a browser's request headers hitting a line-based command parser. Diagnostic in itself: the count matched the header count.
- **Absence of structure is a finding.** Nine authenticator samples, nine distinct values, structureless XOR deltas. That is what told us to stop looking for a forgery path and commit to replay.
- **Narrative language was literal again.** "Drift" named the exact mechanism — counter desync — the way Cadence's cover text named its own encoding. Two of three hardware challenges this event put the mechanism in the prose. Shard was the exception, where "checks its roost" merely evoked a bus scan that did not exist.
- **Tool iteration did not decide the outcome.** Two rounds of safety features were built in response to the failed attempt — a pre-transmit staleness check, then a transmit-before-unjam mode — and **none of them produced any output in the winning run**: no pre-TX check line, no per-transmit verdict line. The run succeeded because the whole sequence was automated with no human inside the window, which the original tool already did. The bug was in the operating procedure, not the tool. Worth remembering before building features to work around a process problem. *(The banner on the successful run read `v1.0`; the operator recalls running `v1.1`. Because no version-specific feature fired under either reading, the exact build was not reconstructible after the fact and is deliberately not asserted here.)*

## 13. Open items

- `solves` not captured from the scoreboard; frontmatter field omitted rather than guessed
- All five ATT&CK IDs unverified — see §10 callout. `T1557` and `T1550` are the weakest
- ATT&CK for ICS likely has a dedicated replay technique that fits better than `T1550`; ID not verifiable this session
- Never established whether the lock press that burned the first attempt was operator error or a server-side owner. The successful run with the browser closed suggests operator error, but this was not proven
- `--tx-while-jammed` never tested against the live service — unknown whether the simulated jammer blocks attacker transmissions as well as fob transmissions
- Exact tool build used for the winning run is ambiguous: the banner printed `v1.0`, the operator recalls `v1.1`. No version-specific output appeared either way, so the question is moot for the result but the record is not clean

## Cross-references
- [[HTB-CA2026-Cadence-in-the-Cord-UART-Inter-Frame-Timing-Covert-Channel]]
- [[HTB-CA2026-What-the-Shard-Displayed-I2C-SSD1306-Framebuffer-Reconstruction]]

## Change Log
- 2026-07-25 — Note created. Solved: two-service RF simulation; web port proven to have no attacker surface across 780 requests; raw TCP console on the second port provides sniff/jam/transmit. 18-byte frame reverse-engineered (preamble, sync, `SLT` device ID, button, 16-bit BE counter, 6-byte keyed MAC). RollJam executed — two jammed fob presses captured while `CAR MISS reason=channel_jammed`, replayed after unjam for `result=exploit_unlock` at counter 18295. First attempt failed because a `--dry` verification step introduced human latency and the receiver advanced past both held frames; recorded as the primary method lesson. ATT&CK mapping split into attack chain and collection, all IDs flagged unverified.
- 2026-07-25 — Amended §12 and §13: removed the assertion that the winning run used a specific tool build. The banner printed `v1.0` but the operator recalls `v1.1`; since no version-specific output appeared under either reading, the build is not reconstructible and is no longer claimed. §8 payload command made version-neutral. Method lesson unchanged: the failure was procedural (human latency inside a time-critical window), not a tool defect.