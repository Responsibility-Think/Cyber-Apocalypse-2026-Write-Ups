---
title: "HTB CA2026 — Cadence in the Cord: UART Inter-Frame Timing Covert Channel"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Cadence in the Cord
app: "capture.sr (sigrok logic session, single channel)"
category: hardware
difficulty: easy
points: 975
type: writeup
status: complete
mitre:
  - T1001
  - T1001.002
  - T1048.003
  - T1040
  - T1200
tags:
  - writeup
  - HTB
  - Security
  - Hardware
  - UART
  - covert-channel
  - steganography
  - logic-analysis
  - detection
related:
  - "[[HTB-CA2026-Secondhand-Overlapping-Instruction-Self-Decrypting-Stub]]"
aliases:
  - Cadence in the Cord
  - CA2026 Cadence in the Cord
created: 2026-07-25T14:10:23.509Z
updated: 2026-07-25T14:10:23.509Z
---

# Cadence in the Cord — UART Inter-Frame Timing Covert Channel

> [!success] Solved
> Flag: `HTB{th3_f1rst_m4rk_r1ngs_tru3_b3n34th_th3_w0rds}`
> Carrier: 9600 8N1 UART, 593 frames. Payload: the **idle gaps between frames**, 2.006 ms = `0`, 10.007 ms = `1`, 8 bits per character, MSB-first.
> Solved 2026-07-25 09:41 local. Single 2 MHz sigrok capture, no binary, no server. First hardware-category solve of the event.

## 0. How the flag was obtained

1. `unzip -l` → single `capture.sr` → sigrok session.
2. `.sr` is itself a zip → `metadata` + 782 `logic-1-N` chunks. **2 MHz, `unitsize=1`, `total probes=8`, only `probe2=D1` named.**
3. Reassembled chunks in **numeric** order (not lexical) → 16,000,000 samples = 8.000 s.
4. Per-bit activity scan → only bits 0 and 1 move. Bit1 = D1, idle high, 3,562 transitions. **Bit0 is an undeclared channel carrying 111 pulses.**
5. Run-length histogram on D1 → shortest run 208 samples, every other run an integer multiple → 2,000,000 / 208.33 = **9600 baud**.
6. Decoded D1 as 9600 8N1 LSB-first → **593 frames, zero stop-bit failures**, cover text in clean English.
7. The cover text specifies the second layer literally: *"A long rest raises the mark to one, a short rest lets it fall to nothing; count eight rests to every letter."*
8. Measured inter-frame idle: `start[i+1] − (start[i] + 10 × bit_period)`. **592 gaps, exactly divisible by 8 → 74 characters.** Perfectly bimodal, **2.006 ms vs 10.007 ms (5:1)**.
9. Thresholded long→`1` / short→`0`, packed **MSB-first** → flag, preceded by the self-verifying phrase `you read the silence well`.
10. Ruled the undeclared bit0 channel out as rising-edge crosstalk (§5) and swept the whole capture for other `HTB{}` strings → exactly one.

## 1. Shape of the challenge

One artifact. No binary, no service, no network. The scenario promised two layers — *"Read the pleasant words; then attend to the silences between them"* — and that is a specification, not flavour. The cover text is the decoy; the inter-frame timing is the payload.

## 2. Recon — capture geometry

```
sigrok version=0.5.2
capturefile=logic-1
total probes=8
samplerate=2 MHz
total analog=0
probe2=D1
unitsize=1
```

| Property | Value |
|---|---|
| Sample rate | 2 MHz (0.5 µs/sample) |
| Samples | 16,000,000 (781 × 20,480 + 5,120) |
| Duration | 8.000 s |
| Declared probes | 8 |
| **Named probes** | **1 — `probe2=D1` (bit 1)** |
| Distinct sample bytes | `0xFC`, `0xFE`, `0xFF` — only bits 0 and 1 ever move |

**Chunk ordering is a trap.** `logic-1-2` sorts before `logic-1-10` lexically. Sorting by the parsed trailing integer is mandatory — a lexical sort scrambles the timeline while leaving the UART *partly* readable, which is the worst possible failure because it looks like it half-worked.

## 3. Layer 1 — the UART cover text

Run-length histogram on D1 (short runs only):

| Run (samples) | Bit times | Count |
|---|---|---|
| 208 / 209 | 1 | 1,605 |
| 416 / 417 | 2 | 809 |
| 625 / 626 | 3 | 333 |
| 833 / 834 | 4 | 106 |
| 1041 / 1042 | 5 | 5 |
| 1250 / 1251 | 6 | 111 |

Every run quantises to a 208.33-sample unit → 2,000,000 / 208.33 = **9600 baud**. Idle high, 8N1, LSB first. 593 frames, every stop bit valid.

> To the buyer who paid in secrets: what follows is the pleasant tone, the goods I sell in daylight and never miss. Lord Varo's debt, due at the second thaw, yours for a marriage you already own. The Harlow inheritance, contested by a cousin whose witnesses I arranged. Take them and thank me. But what is written is worth nothing. **The dragon's true note does not live in the words; it lives in the rests between them. A long rest raises the mark to one, a short rest lets it fall to nothing; count eight rests to every letter before the note will speak.** Read the silence, not the song, and pay.

Rule applied verbatim — *when an artifact describes itself, believe it literally.* The encoding, the polarity, and the group size were all stated outright; nothing about layer 2 required guessing.

## 4. Layer 2 — the inter-frame timing channel

Gap measured as true idle: from the end of one stop bit to the next start bit.

| Gap | Samples | Time | Count | Symbol |
|---|---|---|---|---|
| Short | 4,011–4,012 | **2.006 ms** | 293 | `0` |
| Long | 20,014–20,015 | **10.007 ms** | 299 | `1` |

Nothing in between. The 5:1 separation makes the threshold irrelevant — verified byte-identical output at 8,000 / 12,000 / 16,000 samples.

592 bits / 8 = **74 characters exactly**, no remainder. Packed **MSB-first**:

```
you read the silence well HTB{th3_f1rst_m4rk_r1ngs_tru3_b3n34th_th3_w0rds}
```

The 26-character English preamble is a built-in correctness oracle. A wrong bit order, threshold, or grouping yields high-entropy bytes, not a sentence. LSB-first was tested and produces non-printable garbage.

## 5. The undeclared channel — a negative finding, kept on record

`total probes=8` but only `probe2=D1` named — yet **bit 0 carried 111 pulses**. This is the intake question *"do the shipped artifacts agree with each other?"*, and here the disagreement is real but benign.

- All 111 pulses are **exactly 1 sample wide** (0.5 µs)
- All 111 sit at **distance 0** from a D1 edge
- **111/111 coincide with rising edges; 0/111 with falling edges**
- 111 of 1,781 rising edges (6.2%) glitch
- All fall inside the UART transmission span

Capacitive crosstalk from the adjacent trace, asymmetric because the rising edge is the faster transition on a pulled-up line. Rising-only coincidence at zero offset is not a plausible signature for deliberately encoded data. **Not a channel, and not required for the flag.**

Recorded anyway because *the check* is what generalises: different offsets, or both polarities, and this would have been a second data line hidden behind an incomplete metadata declaration. Decoding only the named channel is the habit that misses it.

## 6. Final payload

```python
#!/usr/bin/env python3
"""CA2026 'Cadence in the Cord' — full solve, capture.sr -> flag."""
import sys, zipfile, configparser
import numpy as np

def load_sr(path):
    z = zipfile.ZipFile(path)
    meta = configparser.ConfigParser()
    meta.read_string(z.read('metadata').decode())
    dev  = [s for s in meta.sections() if s.startswith('device')][0]
    sr   = meta[dev]['samplerate']
    rate = float(sr.split()[0]) * {'MHz':1e6,'kHz':1e3,'Hz':1}[sr.split()[1]]
    names = sorted((n for n in z.namelist() if n.startswith('logic-1-')),
                   key=lambda p: int(p.rsplit('-', 1)[1]))   # numeric, not lexical
    data = b''.join(z.read(n) for n in names)
    return np.frombuffer(data, dtype=np.uint8), rate

def uart_frames(line, rate, baud=9600):
    """8N1, idle high, LSB first. Returns [(start_sample, byte)]."""
    BIT = rate / baud
    out, i, N = [], 0, line.size
    while i < N - 1:
        if line[i] and not line[i + 1]:
            s = i + 1
            v = sum(int(line[int(round(s + (1.5 + b) * BIT))]) << b for b in range(8))
            out.append((s, v))
            i = int(round(s + 9.5 * BIT))
        else:
            i += 1
    return out

def main(path):
    samples, rate = load_sr(path)
    d1 = ((samples >> 1) & 1).astype(np.uint8)          # probe2 = D1
    frames = uart_frames(d1, rate)
    print('[cover]', bytes(v for _, v in frames).decode(), '\n')

    starts = np.array([s for s, _ in frames])
    gaps   = np.diff(starts) - 10 * (rate / 9600)       # idle between frames
    thresh = (gaps.min() + gaps.max()) / 2              # bimodal, 5:1 separation
    bits   = (gaps > thresh).astype(int)                # long rest = 1, short = 0
    assert bits.size % 8 == 0, f'{bits.size} bits not a multiple of 8'
    covert = bytes(int(''.join(map(str, bits[i:i+8])), 2)   # MSB-first
                   for i in range(0, bits.size, 8))
    print('[covert]', covert.decode())

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'capture.sr')
```

Runs end-to-end from the shipped `.sr` with nothing beyond NumPy.

## 7. Tools & techniques

`unzip` · Python 3 + NumPy · `sha256sum`. Notably **no** `sigrok-cli`, `pulseview` or `gtkwave` — the `.sr` container is a plain zip with an INI metadata file, so a 40-line reader replaces the whole toolchain and yields sample-accurate frame indices.
Concepts: sigrok session format · run-length quantisation for baud recovery · UART 8N1 framing · **inter-frame timing covert channel** · bimodality and threshold-robustness testing · crosstalk identification by edge-polarity coincidence.

## 8. MITRE ATT&CK

Split deliberately into what the *adversary* did and what the *interception* did — the second half is the blue-team half.

**Adversary tradecraft (Seralyne's channel):**

- **T1001** Data Obfuscation — the message is concealed inside traffic that is itself entirely well-formed and benign
- **T1001.002** Data Obfuscation: Steganography — the payload rides in the *timing* of the carrier, never in its content; every transmitted byte is innocuous English
- **T1048.003** Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol — a plain serial link carries the secret out-of-band from any command channel

**Collection against it (how the sending was cut from the wire):**

- **T1040** Network Sniffing — passive capture of data in transit; the bus is serial rather than packet-switched, but the technique shape is identical
- **T1200** Hardware Additions — physical interception hardware attached to the line to obtain the capture

> [!warning] Honest scope of this mapping — verify the IDs before trusting them
> ATT&CK describes adversary behaviour against enterprise systems. This is a CTF decode exercise on an offline capture: nothing is exploited, no access is gained, no host is compromised. The techniques above are listed because the **artefact genuinely demonstrates the technique shape** and that shape is what transfers to defenders — not because an intrusion occurred.
> **These IDs were assigned without access to the live ATT&CK matrix and are unverified.** `T1001.002` (Steganography under Data Obfuscation) and `T1048.003` (Unencrypted Non-C2) are the two most likely to be wrong at the sub-technique level. Confirm each against attack.mitre.org before this frontmatter is treated as authoritative — the same discipline that produced the T1496.004 → T1496.001 correction.

## 9. Detection / blue-team & fix notes

- **Timing channels survive content inspection completely.** Every byte on this wire is benign English and every frame is well-formed 8N1. DLP, protocol validators, and keyword matching all see nothing. The signal is not in the bytes.
- **Bimodality is the detector.** Legitimate serial traffic has inter-frame delays shaped by buffer flushes and application scheduling — broad, skewed, continuous distributions. This capture has two delta functions 5:1 apart with nothing between them. A variance test or a two-cluster fit on inter-frame delay flags it instantly, and neither requires understanding the payload.
- **Instrument the gap, not the frame.** Most serial monitoring records decoded bytes and discards arrival timestamps. That discards exactly the channel. If serial links carry anything sensitive, log frame arrival times at microsecond resolution or the covert channel is invisible by construction.
- **Rate is the practical constraint on the attacker.** 74 bytes took 8 seconds — roughly 9 bytes/s. Too slow for bulk exfiltration, entirely adequate for a key, token, or credential. Treat low-bandwidth channels as credential-theft risks, not data-volume risks.
- **Capture hygiene:** metadata declaring more probes than it names is incomplete, not authoritative. Enumerate active channels from the data, never from the header.

## 10. Method notes

- **Triage-first held again.** `unzip -l` → `.sr` → metadata read → per-bit activity scan. Four cheap commands established sample rate, channel count, and the existence of an undeclared channel before a single decoder line was written.
- **Numeric chunk sort is a silent-corruption class.** Lexical sorting of `logic-1-N` produces a plausible-looking but wrong timeline. Candidate lesson: *when a container splits data into numbered parts, sort by the parsed integer and assert the reassembled length against the metadata.*
- **Reading the container beat installing the tool.** The instinct was `sigrok-cli -P uart`. Parsing the zip directly was faster, required no install, and gave sample-accurate frame start indices that a decoder's annotation output would not have. **A protocol decoder hands you the message and discards the timing — for a timing channel it is the wrong abstraction.**
- **The self-verifying preamble.** `you read the silence well` before the flag is the author supplying an oracle. Any covert layer that decodes to coherent natural language is confirmed; no submission guess was needed.
- **Negative findings are worth recording.** The crosstalk analysis cost about a minute and produced no flag, but it converted "unexplained anomaly" into "explained artifact." Unexplained anomalies are what make you second-guess a correct answer three days later.
- **Difficulty labels still do not predict solve counts.** Labelled `easy`, held 975 points at solve time. The gate is a single realisation — the idle time is data — with no partial credit and no gradient to climb. The label describes the post-gate work, not the gate.

## 11. Open items

- `solves` not captured from the scoreboard before it decayed; frontmatter field deliberately omitted rather than guessed
- All five ATT&CK IDs assigned without matrix access — unverified, see §8 callout
- Flag text references `th3_f1rst_m4rk`, colliding with the **First Mark** challenge name. Narrative callback only — no artifact dependency between the two, and no second flag in this capture

## Cross-references
- [[HTB-CA2026-First-Mark-RISCV-Custom-Opcode-Recovery]]
- [[HTB-CA2026-Secondhand-Overlapping-Instruction-Self-Decrypting-Stub]]

## Change Log
- 2026-07-25 — Note created. Full solve documented: 2 MHz sigrok capture with a single named probe carrying 9600 8N1 UART; cover text describes its own covert scheme; 592 inter-frame gaps (2.006 ms / 10.007 ms, 5:1 bimodal) decode MSB-first at 8 bits per character to 74 characters carrying the flag. Undeclared bit0 channel characterised and ruled out as rising-edge crosstalk (111/111 zero-offset coincidence, rising only). ATT&CK mapping split into adversary tradecraft and collection technique, with IDs flagged unverified.
