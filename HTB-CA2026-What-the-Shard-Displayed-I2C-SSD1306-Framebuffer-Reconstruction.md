---
title: "HTB CA2026 — What the Shard Displayed: I2C Bus Capture to SSD1306 Framebuffer Reconstruction"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: What the Shard Displayed
app: "capture.sr (sigrok logic session, two channels)"
category: hardware
difficulty: medium
points: 975
type: writeup
status: complete
mitre:
  - T1200
  - T1040
  - T1113
  - T1119
  - T1005
tags:
  - writeup
  - HTB
  - Security
  - Hardware
  - I2C
  - embedded
  - logic-analysis
  - detection
related:
  - "[[HTB-CA2026-Cadence-in-the-Cord-UART-Inter-Frame-Timing-Covert-Channel]]"
aliases:
  - What the Shard Displayed
  - CA2026 What the Shard Displayed
created: 2026-07-25T14:12:18.809Z
updated: 2026-07-25T14:12:18.809Z
---

# What the Shard Displayed — I2C Bus Capture to SSD1306 Framebuffer Reconstruction

> [!success] Solved
> Flag: `HTB{3v3ry_crow_w3ars_h3r_3y3s}`
> Recovered by reconstructing three 128×64 OLED framebuffers from raw I2C bus traffic. The flag is **rendered pixels**, not bytes — it never exists as a string anywhere in the capture.
> Solved 2026-07-25. Single 2 MHz sigrok capture, three I2C peripherals, no binary and no server. Second hardware-category solve of the event.

## 0. How the flag was obtained

1. **Hashed the upload first.** It arrived at the identical path and filename as the Cadence artifact. `sha256` `5c4e58e7…` ≠ `57f72acc…`, inner file 35,919 B vs 112,808 B → genuinely new artifact, not a re-upload.
2. `.sr` → sigrok session. **2 MHz, 4,000,000 samples (2.0 s), `probe1=D0` and `probe2=D1` both named.**
3. Per-bit scan: D0 = 64,642 transitions, D1 = 4,256. Two wires, one fast and one sparse, both idle high → **I2C**; D0 = SCL, D1 = SDA.
4. Decoded I2C — START/STOP on SDA edges while SCL high, sample SDA on SCL rising, 9-bit groups. **95.2 kHz, 200 transfers, 3,569 bytes, zero mid-transfer NAKs.**
5. Address histogram → **three devices**: `0x3C` ×196 (SSD1306 OLED), `0x50` W+R (24Cxx EEPROM), `0x68` W+R (DS1307/DS3231 RTC). Maps 1:1 onto the scenario's *"checks its roost / marks the hour / paints onto its pane."*
6. Init at `T000`: `0x20 0x00` horizontal addressing, `0xA8 0x3F` (64 rows), `0xA1`+`0xC8` (stock orientation), `0xAF` display on.
7. Three `0x21 0x00 0x7F` / `0x22 0x00 0x07` full-window commands split the GDDRAM writes into **three complete 1,024-byte frames** (1 init + 3 × (1 cmd + 64 × 16 B) = 196 ✓).
8. Rendered page-major, **LSB = topmost pixel of each 8-row page** → frame 1 an eye/crow sigil, frame 2 `05:17`, **frame 3 the flag across two text bands.**
9. Segmented frame 3 into glyph bitmaps on blank-column boundaries rather than reading the scaled render → `HTB{3v3ry_crow_` + `w3ars_h3r_3y3s}`.
10. Swept both non-display transactions for a second payload; the EEPROM blob resists trivial decryption and is not required (§6).

## 1. Shape of the challenge

A single logic capture of a live I2C bus. No firmware image, no service, no crackme. The device wakes, polls two peripherals, and paints three screens. Nothing is hidden — the flag is simply several layers of decoding deep: bus framing → display-controller semantics → framebuffer geometry → glyph recognition.

## 2. Recon — capture geometry

```
sigrok version=0.5.2
capturefile=logic-1
total probes=8
samplerate=2 MHz
probe1=D0
probe2=D1
unitsize=1
```

| Property | Value |
|---|---|
| Sample rate | 2 MHz (0.5 µs/sample) |
| Samples | 4,000,000 → 2.000 s |
| Active bits | 0 and 1, **both named**, both idle high (I2C pull-ups) |
| D0 transitions | 64,642 → 32,321 clock pulses → **SCL** |
| D1 transitions | 4,256 → **SDA** |
| Bus clock | **95.2 kHz** (median SCL period 21 samples) — standard-mode 100 kHz |

Both probes named here, unlike Cadence. Idle-high on both is the I2C signature; the transition-count ratio settles which line is which without guessing, and the clean decode confirms it.

## 3. I2C decode

Standard reconstruction: **START** = SDA falling while SCL high; **STOP** = SDA rising while SCL high; data sampled on **SCL rising**; 9 bits per byte (8 data + ACK).

200 START/STOP pairs, 3,569 bytes, **zero mid-transfer NAKs** — every addressed device answered, so despite the "checks its roost" phrasing there is **no bus scan** in this capture.

| Address | Dir | Transfers | Device |
|---|---|---|---|
| `0x3C` | W | 196 | SSD1306 128×64 OLED |
| `0x50` | W + R | 2 | 24Cxx I²C EEPROM (16-bit addressing) |
| `0x68` | W + R | 2 | DS1307 / DS3231 RTC |

Sequence: **frame 1 → RTC read → frame 2 → EEPROM read → frame 3.**

## 4. SSD1306 semantics

The `0x3C` traffic uses the SSD1306 control byte: **`0x00` = command stream, `0x40` = data (GDDRAM) stream.**

Init (`T000`, 27 B):

```
AE          display off
D5 80       clock divide / osc freq
A8 3F       multiplex ratio 0x3F -> 64 rows
D3 00       display offset 0
40          start line 0
8D 14       charge pump enable
20 00       memory addressing mode = HORIZONTAL   <- geometry
A1          segment remap (col 127 -> SEG0)       <- orientation
C8          COM scan direction remapped            <- orientation
DA 12       COM pins config
81 CF       contrast
D9 F1       pre-charge
DB 40       VCOMH deselect
A4          resume to RAM content
A6          normal (not inverted)
AF          display on
```

`0x21 0x00 0x7F` (columns 0–127) + `0x22 0x00 0x07` (pages 0–7) sets a full-screen window and **resets the write pointer** — which is what makes frame segmentation unambiguous. It appears three times.

**Geometry that matters:**

- Horizontal addressing → bytes fill column 0…127 of page 0, then page 1, …
- Each byte is **8 vertical pixels**, **LSB = top**
- Pixel *(x, y)* = bit `y % 8` of byte `(y // 8) × 128 + x`
- `0xA1` + `0xC8` is the stock Adafruit orientation pair; the two remaps cancel, so no flip or mirror is needed. **Confirmed empirically — the text renders upright and left-to-right. A wrong orientation assumption produces mirrored or inverted glyphs, which is self-announcing.**

## 5. The three frames

| Frame | Lit px | Content |
|---|---|---|
| 1 | 749 | Crow-eye sigil — a circular iris inside a lens/wing outline |
| 2 | 102 | `05:17` |
| 3 | 541 | Two text bands carrying the flag |

Frame 3, segmented into glyph bitmaps on blank-column boundaries:

```
band rows 18-30 (14 glyphs):  H T B { 3 v 3 r y _ c r o w _
band rows 36-48 (15 glyphs):  w 3 a r s _ h 3 r _ 3 y 3 s }
```

```
HTB{3v3ry_crow_w3ars_h3r_3y3s}
```

Glyph segmentation rather than reading the render is the point. `3`/`8`, `v`/`y`, `0`/`o` and `_`/space are the pairs that get misread off a scaled-up 128×64 bitmap, and a single wrong character produces a well-formed, plausible, rejected submission. Isolating each glyph makes descenders (`y`) and baseline underscores unambiguous.

## 6. Unexplained residue — recorded, not resolved

Two items the flag did not require. Both logged rather than hand-waved.

**EEPROM `0x50`, 48 bytes at offset `0x0000`:**

```
59092f40 7a698470 caf37ba8 266adb53 033a8947 327f2cfb
b9a41633 a6cc3880 9ae85cef 17f65d2e 6ab8ca29 14e85552
```

45 distinct values of 48 — statistically indistinguishable from uniform random (≈43.6 expected). No single-byte XOR yields printable ASCII; XOR against the RTC bytes, the flag, and the flag core all fail. Opaque flavour standing in for a device key blob, or ciphertext under a key not present in the capture. **Not required for the flag.**

**RTC `0x68`, 7 bytes from register 0:** `32 56 00 07 07 02 00` → BCD **00:56:32, dow 7, 2000-02-07**.

**This disagrees with the `05:17` on frame 2.** The RTC read happens *before* frame 2 is drawn and the EEPROM read *after*, so frame 2's value derives from neither. Whether the mismatch is authored flavour — "the hour it *last* saw us" being a stored value distinct from current time — or an artifact of challenge generation is unresolved. Flagged because an unexplained inconsistency is exactly what makes you doubt a correct answer later.

## 7. Final payload

```python
#!/usr/bin/env python3
"""CA2026 'What the Shard Displayed' — capture.sr -> reconstructed OLED frames."""
import sys, zipfile, configparser
import numpy as np
from PIL import Image

def load_sr(path):
    z = zipfile.ZipFile(path)
    m = configparser.ConfigParser(); m.read_string(z.read('metadata').decode())
    dev  = [s for s in m.sections() if s.startswith('device')][0]
    n, u = m[dev]['samplerate'].split()
    rate = float(n) * {'MHz':1e6,'kHz':1e3,'Hz':1}[u]
    names = sorted((x for x in z.namelist() if x.startswith('logic-1-')),
                   key=lambda p: int(p.rsplit('-', 1)[1]))       # numeric, not lexical
    return np.frombuffer(b''.join(z.read(x) for x in names), np.uint8), rate

def i2c_decode(scl, sda):
    """Returns [(start_sample, [(byte, ack), ...]), ...]."""
    rise = np.flatnonzero(np.diff(scl) ==  1) + 1
    starts = [i for i in np.flatnonzero(np.diff(sda) == -1) + 1 if scl[i-1] and scl[i]]
    stops  = [i for i in np.flatnonzero(np.diff(sda) ==  1) + 1 if scl[i-1] and scl[i]]
    marks = sorted([(i, 'S') for i in starts] + [(i, 'P') for i in stops])
    xfers, cur = [], None
    for pos, kind in marks:
        if kind == 'S':
            if cur: xfers.append(cur)
            cur = [pos, None]
        elif cur:
            cur[1] = pos; xfers.append(cur); cur = None
    if cur: xfers.append(cur)
    out = []
    for lo, hi in xfers:
        bits = sda[rise[(rise > lo) & (rise < (hi or rise[-1]))]]
        byts = [(int(''.join(map(str, bits[i:i+8])), 2), bits[i+8])
                for i in range(0, len(bits) - 8, 9)]
        out.append((lo, byts))
    return out

def ssd1306_frames(xfers, addr=0x3C):
    """Split GDDRAM writes into frames at each column/page-range command."""
    frames, cur = [], None
    for _, b in xfers:
        if not b or b[0][0] >> 1 != addr: continue
        ctrl, payload = b[1][0], [v for v, _ in b[2:]]
        if ctrl == 0x00 and 0x21 in payload:        # 0x21 = set column address
            if cur: frames.append(cur)
            cur = []
        elif ctrl == 0x40 and cur is not None:
            cur.extend(payload)
    if cur: frames.append(cur)
    return frames

def render(buf):
    """SSD1306 horizontal addressing: page-major, LSB = topmost pixel of the page."""
    b = np.frombuffer(bytes(buf), np.uint8).reshape(8, 128)
    return np.unpackbits(b, axis=1, bitorder='little').reshape(8, 128, 8) \
             .transpose(0, 2, 1).reshape(64, 128)

def main(path):
    s, rate = load_sr(path)
    xfers = i2c_decode(((s >> 0) & 1).astype(np.int8),   # D0 = SCL
                       ((s >> 1) & 1).astype(np.int8))   # D1 = SDA
    seen = sorted({b[0][0] >> 1 for _, b in xfers if b})
    print('I2C devices:', [hex(a) for a in seen])
    for i, f in enumerate(ssd1306_frames(xfers), 1):
        img = render(f)
        Image.fromarray(img * 255).resize((512, 256), Image.NEAREST).save(f'frame{i}.png')
        print(f'--- frame {i} ({img.sum()} px) ---')
        for row in img:
            print(''.join('#' if v else '.' for v in row))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'capture.sr')
```

Runs end-to-end from the shipped `.sr`. NumPy + Pillow only — no sigrok, no PulseView.

## 8. Tools & techniques

`unzip` · Python 3 + NumPy + Pillow · `sha256sum`. Again **no** `sigrok-cli` — the `.sr` container is a zip with an INI, and a direct reader gives sample-indexed transfers.
Concepts: I2C framing (START/STOP/ACK, sample-on-SCL-rising) · 7-bit addressing and device identification by address · SSD1306 command vs data control byte · horizontal addressing mode and page-major LSB-top framebuffer geometry · segment/COM remap and display orientation · glyph segmentation for reliable bitmap OCR.

## 9. MITRE ATT&CK

Split into what the *implant* did and what the *recovery* did — the second half is the blue-team half.

**Adversary tradecraft (Alyss's device):**

- **T1200** Hardware Additions — a purpose-built device physically implanted on a carrier ("a maker's device bound beneath its wing") to observe and record
- **T1119** Automated Collection — on power-up the device autonomously polls its peripherals, timestamps, and renders without operator interaction
- **T1005** Data from Local System — the implant reads its own persistent stores (EEPROM at `0x50`, RTC at `0x68`) as part of that collection cycle

**Collection against it (how the device was read out):**

- **T1040** Network Sniffing — passive capture of data in transit on a shared bus; I2C is not packet-switched, but the technique shape (tap the medium, decode the framing, read everything) is identical
- **T1113** Screen Capture — the display contents were reconstructed in full, obtained from the display *bus* rather than an OS screenshot API. The end effect is identical: everything the device showed is recovered

> [!warning] Honest scope of this mapping — verify the IDs before trusting them
> ATT&CK describes adversary behaviour against enterprise systems. This challenge involves no exploitation, no access, and no compromised host — it is offline analysis of a capture. The techniques above are listed because the **artefact genuinely demonstrates the technique shape**, and that shape is what transfers to defenders.
> **These IDs were assigned without access to the live ATT&CK matrix and are unverified.** `T1113` (Screen Capture) is the most analogical of the five — it is defined around OS-level screenshot APIs, and reading a display bus is an extension of the concept rather than a textbook instance. `T1119` is the next most arguable. Confirm each against attack.mitre.org before this frontmatter is treated as authoritative — the same discipline that produced the T1496.004 → T1496.001 correction.

## 10. Detection / blue-team & fix notes

- **I2C has no confidentiality and no authentication.** Any probe on SDA/SCL recovers everything: peripheral inventory, register contents, and full display output. Two clips and two seconds reconstructed this device's entire behaviour. There is no protocol-level mitigation — I2C was never designed to resist an observer on the bus.
- **The display bus is the last plaintext hop, and it is rarely threat-modelled.** Encrypting a token at rest is irrelevant if it is written in cleartext to a display controller. Anything rendered to a screen is disclosed to anyone with a probe on the panel interface — including PINs, seeds, recovery codes, and one-time passwords on hardware wallets, tokens, and medical devices.
- **Device inventory is free to an attacker.** `0x3C` = SSD1306, `0x50` = 24Cxx EEPROM, `0x68` = DS1307/DS3231. I²C addresses are effectively a public parts list, so bus traffic identifies the bill of materials without opening the enclosure or reading a single firmware byte.
- **Absence of a bus scan is itself intelligence.** Zero NAKs across 200 transfers means the firmware addresses only devices it already knows. A defender seeing NAK-heavy traffic on a production bus should suspect enumeration by something that does *not* know the hardware — that is the signature of an attacker's probe, not the product's own firmware.
- **Mitigations are physical or architectural, not protocol-level.** Move sensitive rendering to SPI with short buried traces on inner PCB layers; put secrets behind a secure element that never emits plaintext; use tamper-detect meshes and potting where the threat model includes physical access; or accept that anything displayed is disclosed and design the secret handling around that.

## 11. Method notes

- **Hashing the upload paid for itself.** The artifact arrived at the identical path and filename as the previous challenge. Five seconds of `sha256sum` ruled out the single most embarrassing failure mode — analysing the previous target and reporting confident nonsense.
- **Transition-count ratio identifies SCL vs SDA with no guessing.** The clock toggles every bit; data holds across runs. 64,642 vs 4,256 is not ambiguous, and the clean decode with valid addresses and zero NAKs confirms it — a swap produces garbage, so **the decode is the test**.
- **Zero NAKs is itself a finding.** "Checks its roost" suggested a bus scan, which would show NAKs at unpopulated addresses. There were none. Narrative language is a hypothesis, not a specification — the opposite lesson to Cadence, where the flavour text was literal. **Believe an artifact that describes itself; do not believe one that merely evokes.**
- **Segment glyphs, do not read renders.** The flag was legible in the scaled PNG, but `3`/`8`, `v`/`y` and `_`/space are exactly where a confident misread produces a well-formed wrong submission. Column-gap segmentation cost ten lines and removed the guess.
- **Frame boundaries came free from the protocol.** `0x21`/`0x22` window commands reset the GDDRAM pointer, so they mark frame starts unambiguously. Reading the controller's datasheet semantics beat any heuristic based on timing gaps.
- **Two `.sr` challenges, two different right answers about tooling.** Cadence needed raw sample timing; this one needed protocol structure. Both were served better by parsing the container directly than by `sigrok-cli`, which would have produced usable annotations here but no clean path to the framebuffer.

## 12. Open items

- `solves` not captured from the scoreboard; frontmatter field deliberately omitted rather than guessed
- All five ATT&CK IDs assigned without matrix access — unverified, see §9 callout. `T1113` and `T1119` are the weakest
- EEPROM 48-byte blob unexplained; presumed flavour, not proven
- Frame 2 `05:17` vs RTC `00:56:32` mismatch unexplained
- Neither residue was needed; if a later challenge in this event reuses the device, revisit both

## Cross-references
- [[HTB-CA2026-Cadence-in-the-Cord-UART-Inter-Frame-Timing-Covert-Channel]]

## Change Log
- 2026-07-25 — Note created. Full solve documented: 2 MHz two-wire capture decoded as 95.2 kHz I2C; three devices (SSD1306 `0x3C`, EEPROM `0x50`, RTC `0x68`); 196 OLED transfers reconstructed into three 1,024-byte framebuffers via horizontal-addressing page-major geometry; frame 3 glyph-segmented to the flag. ATT&CK mapping split into implant tradecraft and readout technique, with IDs flagged unverified. EEPROM blob and RTC/display time mismatch recorded as unresolved residue, neither required for the solve.
