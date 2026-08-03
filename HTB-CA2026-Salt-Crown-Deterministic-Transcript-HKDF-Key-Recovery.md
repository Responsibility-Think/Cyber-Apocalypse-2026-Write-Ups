---
title: "HTB CA2026 — The Salt Crown: Deterministic Session Transcript as KDF Input"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: The Salt Crown
app: "challenge_core.windows.template_release.x86_64.dll — compression-packed godot-cpp GDExtension backing a patched Godot 4.x game export"
category: GamePwn
difficulty: hard
points: 975
type: writeup
status: complete
mitre:
  - T1027
  - T1027.002
  - T1027.009
  - T1140
  - T1480
  - T1480.001
  - T1622
tags:
  - writeup
  - HTB
  - Security
  - Reverse_Engineering
  - Cryptography
related:
  - "[[HTB]]"
  - "[[HTB-CA2026-Secondhand-Overlapping-Instruction-Self-Decrypting-Stub]]"
  - "[[HTB-CA2026-Cinder-Engine-AArch64-VM-SPN-Inversion]]"
aliases:
  - The Salt Crown
  - CA2026 The Salt Crown
created: 2026-07-29T14:06:51.223Z
updated: 2026-07-30T02:46:24.685Z
---

# The Salt Crown — Deterministic Session Transcript as KDF Input

> [!success] Solved 2026-07-29 — recovered, but not credited
> Flag: `HTB{wh03v3r_h0ld5_th3_cr0wn_s3t5_th3_rul35_f0r_th15_w0r1d}`
> **The solve landed under fifteen minutes before the end timer and was not submitted in time**, so its 975 points are not in the team total. The event's only GamePwn challenge; the team finished 0 of 1 there. The flag is correct and cryptographically verified — only the clock was missed.
> Recovered entirely offline — the game was never run. The flag is not a string in the binary; it is **drawn as 532 vector strokes** into a 344×192 image by a 1024-round AES-GCM-decrypted draw program.
> Verification is cryptographic, not visual: **1024/1024 GCM tags authenticate** under the derived key.

> [!info] Scenario, verbatim
> With the Quiet March broken, Aeron's path to the Salt Crown should be clear. Instead, Cassian waits at the Registry Altar, protected by Maelor's last covenant and the testimony of the living. Before the crown can be carried into open sky, one final claim must be answered—and the dead do not surrender their laws easily.

## 0. How the flag was obtained

1. Identified the 70 MB `.exe` as a **patched Godot 4.x export** whose appended PCK is wrapped in a custom `SCX1` container (magic compare at VA `0x142a1c133`), not the stock `GDPC`. Deferred it — the game logic is in the GDExtension.
2. Emulated the DLL's packer stub under Unicorn (`.slt1` → `.slt0`, aPLib-style bit-reader + E8/E9 call fixup) to obtain a flat unpacked image at base `0x180001000`.
3. Located `_bind_methods` at `0x180001c20` via RIP-relative xrefs to the method-name string pool at `0x180040750`. Extracted four member-function pointers: `reset_session`, `submit_event(opcode,arg0,arg1)`, `get_public_state`, `render_reward_step(Image)`.
4. Reversed the state machine at `0x180003b50` — an RL-gym-shaped puzzle with seven gated opcodes and a fixed stage-order table at `0x18004d108`.
5. **Observed that every field the session log records is a compile-time constant.** The stage byte, the index, the reward, and the extra word are all immediates in the dispatcher — so the 64-byte transcript, and therefore its SHA-256, is derivable without ever playing the game.
6. Traced `0x180004660` (BCrypt SHA-256 / HMAC), `0x180004910` (textbook RFC 5869 HKDF), and `0x1800042f0` (AES-256-GCM) to reconstruct the key schedule: `IKM = SECRET32 ‖ SHA256(transcript)`.
7. Rebuilt `SECRET32` from a **three-way XOR split** across `0x18004d110`–`0x18004d1d0`, then brute-forced the 16 possible anti-debug XOR combinations against the round-0 GCM tag — which selected the clean-environment value `0x00000000` in one shot.
8. Decrypted all 1024 ciphertext blocks at `0x180041100`, replayed the resulting draw opcodes as relative pen moves, and rasterised the 247×22 banner.

## 1. Shape of the challenge

Two artifacts, both Windows PE:

| File | Size | Role |
|---|---|---|
| `The Salt Crown.exe` | 70,319,920 | Godot 4.x engine export, `ImageBase 0x140000000`, patched loader |
| `challenge_core.windows.template_release.x86_64.dll` | 208,384 | Packed godot-cpp GDExtension, `ImageBase 0x180000000` |

The DLL's section table is the tell:

| Section | VA | VSize | RawSize | Note |
|---|---|---|---|---|
| `.slt0` | `0x180001000` | `0x3f000` | **0** | Destination — holds no bytes on disk |
| `.slt1` | `0x180040000` | — | — | Packed payload + entry stub, entropy **7.885** |
| `.slt2` | — | — | — | Import thunks |

A section with `RawSize 0` and a `0x3f000` virtual size is an unpacking destination. The export `challenge_core_library_init` at RVA `0x69a0` points *into* `.slt0` — i.e. into bytes that do not exist until the stub has run.

**The structural fact that made this room different from its siblings:** the win condition is not a comparison. There is no `strcmp`, no target hash, no branch that prints on success. The correct play sequence *is* the key material. Get the sequence wrong and the code does not reject you — it derives a different AES key and the GCM tags simply fail.

## 2. The SCX1 loader, and why it stayed a dead end

The `.exe` carries the normal Godot PCK parser (magic `0x43504447`, `GDPC`) alongside a second branch comparing against `0x31584353` — ASCII `SCX1` — at VA `0x142a1c133`, inside the loader function spanning roughly `0x142a1bf10`–`0x142a1c37c`. The appended archive begins at file offset `0x04237000` (~888 KB, high entropy) and the file tail ends with the same four magic bytes. The EXE imports `bcrypt.dll`.

So the PCK is AES-encrypted under a key derived in the EXE. **Deliberately not pursued.** Decrypting it yields GDScript, and GDScript only calls into the DLL — the flag material is not there. This was a scope decision, not a failure; it is recorded in Open items as genuinely unfinished.

## 3. Unpacking the GDExtension

The stub at the DLL entry point (`AddressOfEntryPoint` RVA `0x72220`) is a straightforward LZ/aPLib-family bit-reader decompressor followed by an E8/E9 relative-call fixup pass. It reads from `0x180040000` and writes to `0x180001000`.

Emulated rather than reimplemented — cheaper and exact. The harness maps every section at its RVA, stubs the three imports the stub actually uses (`VirtualProtect` → 1, `LoadLibraryA` / `GetProcAddress` → fakes), calls the entry point as `DllMain` with `rdx = 1`, and dumps `0x180001000`–`0x180073000` afterwards. Decompressed data ends at RVA `0x71eb0`.

> [!note] CFG hazard
> `GuardCFCheckFunctionPointer` (`0x180040318`) and `GuardCFDispatchFunctionPointer` (`0x180040328`) are unpopulated in the emulator, so any attempt to emulate *past* the stub — into `library_init` — dispatches through an unmapped guard pointer and jumps wild. Patching `[0x180040328]` to a `jmp rax` gadget (`48 FF E0`) and `[0x180040318]` to `ret` is the fix. In the end no emulation past the stub was needed.

## 4. The bound API and the state machine

`_bind_methods` at `0x180001c20` registers `ChallengeCore` (a `RefCounted`) with four methods:

| Method | Address | Signature |
|---|---|---|
| `reset_session` | `0x180003730` | `() -> int` |
| `submit_event` | `0x1800039c0` | `(opcode, arg0, arg1) -> int` |
| `get_public_state` | `0x1800032a0` | `() const -> PackedInt32Array` |
| `render_reward_step` | `0x180003720` → `0x1800072b0` | `(Ref<Image>) -> int` |

`submit_event` delegates to the VM step at `0x180003b50`, which gates seven opcodes against a progress struct at `this+0x10`:

| Opcode | Precondition | Effect | Emits (stage, reward, extra) |
|---|---|---|---|
| `0x19a3` | `+0x1c == 0`, `arg0 > 0` | drains a 5000 budget; on first exhaustion resets to `0x1388` | `0x19`, 1, 1 |
| `0x2c71` | one budget cycle done, `+0x00 == 0` | sets `+0x00` | `0x2d`, 3, 0 |
| `0x0f42` | `+0x00 != 0`, `+0x04 == 0` | sets `+0x04` | `0x43`, 7, 0 |
| `0x63b8` | `+0x04 != 0`, `+0x08 == 0` | sets `+0x08`, `+0x10` | `0x58`, 15, 0 |
| `0x51de` | `+0x10 != 0`, `+0x14 == 0` | sets `+0x14` | `0x6e`, 31, 0 |
| `0x37a5` | **`+0x0c != 0`**, `+0x14 != 0`, `+0x18 == 0` | sets `+0x18` | `0x81`, 63, 0 |
| `0x72c4` | `+0x10 + +0x14 + +0x18 == 3` | win, returns 3 | `0xb7`, 127, 0 |

`0x180007800` appends one 8-byte record per event, but only after checking the stage byte against an expected-order table at `0x18004d108` (`19 2d 43 58 6e 81 b7`). Wrong order, no record. Record layout:

```
[0] stage byte
[1] index + 1
[2..4] reward, u16 LE
[4..8] extra, u32 LE
```

On win, `submit_event` hashes the accumulated log and inserts the digest into a set at `this+0xc8`.

## 5. The actual defect — a transcript with no entropy in it

Every value written into that log is an immediate in the dispatcher. Not a function of `arg0`, not a timestamp, not a nonce, not a PRNG draw. `0x19a3` is the only opcode that consumes `arg0` at all, and it emits **only** on the first budget exhaustion, with hardcoded `r8d = 1, r9d = 1`.

So the entire 64-byte hash input is computable from static data:

```
"SCTR\x01\x00\x00\x00"                       (8 bytes @ 0x18004d100)
19 01 01 00 01 00 00 00
2d 02 03 00 00 00 00 00
43 03 07 00 00 00 00 00
58 04 0f 00 00 00 00 00
6e 05 1f 00 00 00 00 00
81 06 3f 00 00 00 00 00
b7 07 7f 00 00 00 00 00
```

```
SHA256 = 58c1fd695c617b299de3cf4608fcc910e581b0334ff8ddc9726623862c427386
```

The puzzle is therefore **decorative**. It gates nothing an attacker with the binary cannot compute in a millisecond. The `+0x0c` gate on `0x37a5` — the one precondition no opcode satisfies — is the only part that would have forced real interaction, and it is bypassed entirely by never playing.

## 6. Key derivation

Three primitives, all BCrypt-backed:

- **`0x180004660(mode, key_span, data_span, out32)`** — `mode 0` = SHA-256, `mode 1` = HMAC-SHA-256. The `mode << 3` at the call site is `BCRYPT_ALG_HANDLE_HMAC_FLAG`.
- **`0x180004910(ikm, salt, info, out, outlen)`** — textbook RFC 5869 HKDF: `PRK = HMAC(salt, IKM)`, then `T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i)`.
- **`0x1800042f0(key, nonce, aad, ct, out, outcap, outlen)`** — AES-256-GCM open.

`SECRET32` is stored as a **three-way XOR split**, unmasked in sequence at each round and wiped after use:

| Share | Computation |
|---|---|
| base | `D[0x18004d130..150] ^ D[0x18004d110..130]` |
| mask A | `D[0x18004d170..190] ^ D[0x18004d150..170]` |
| mask B | `D[0x18004d1b0..1d0] ^ D[0x18004d190..1b0]` |

Then four bytes — offsets `3`, `0x0a`, `0x11`, `0x18` — are XORed with the four bytes of a value returned by the anti-tamper routine at `0x180001280`:

| Check | Constant XORed in on detection |
|---|---|
| `IsDebuggerPresent` | `0xa73c91e5` |
| `CheckRemoteDebuggerPresent` | `0x51d8026b` |
| PEB `BeingDebugged` via `gs:[0x30]` → `[+0x60]` → `[+2]` | `0xc40f7a19` |
| self-checksum over `0x30` bytes at its own entry | `0x18be44d3` |

This is **environmental keying, not an anti-debug branch.** Nothing checks a flag and refuses to run. A debugged process silently derives a corrupt secret and every GCM tag fails, which presents as "my crypto is wrong," not "I have been detected."

Final assembly:

```
IKM   = SECRET32 ‖ SHA256(transcript)                   (64 bytes)
salt  = D[0x180041090 .. +0x20]                          (32 bytes)
info  = D[0x180041068 .. +21] ‖ D[0x180041080 .. +16]    (37 bytes)
key   = HKDF-SHA256(IKM, salt, info, 32)
      = 5bc4a0b3edffe8cdd55b47d6f00d4455473dd63ffd90f2dc9b3e70ae98ad61bf
```

> [!important] The key is constant across all 1024 rounds
> `IKM`, `salt` and `info` are all round-invariant — the round counter appears only in the nonce and the AAD. Derive once, decrypt 1024 times. Recognising this collapsed the work from "reimplement a ratchet" to "one HKDF call."

## 7. The draw program

Ciphertext table at `0x180041100`: exactly `1024 × 0x30` bytes, ending at `0x18004d100` — where the `SCTR` prefix begins. That the table terminates precisely at the next known structure was the confirmation that the layout had been read correctly.

Per round `i`: 32 bytes ciphertext + 16 bytes tag, with

```
nonce = D[0x1800410b0 .. +8] ‖ BE32(i)                   (12 bytes)
aad   = D[0x1800410b8 .. +58] ‖ LE32(i) ‖ LE32(1024)     (66 bytes)
```

Note the counter is **big-endian in the nonce and little-endian in the AAD** — the same value serialised two ways, ten bytes apart in the same call.

Each 32-byte plaintext is a command, dispatched on byte 0:

| Byte | Count | Meaning |
|---|---|---|
| `0x39` | 532 | stroke — three signed 16-bit relative deltas at `p[2..8]` |
| `0x5d` | 433 | no-op / padding |
| `0xa6` | 58 | pen-up (stroke separator) |
| `0xe3` | 1 | terminator; accepted only at round `0x3ff` |

Stroke semantics: `x0 = x + d0`, `y = y + d1`, `x1 = x0 + d2`; draw the horizontal run `x0 → x1` at row `y` with a small brush, then set the cursor to `(x1, y)`.

`render_reward_step` validates the target `Image` hard before it will draw: width `0x158` (344), height `0xc0` (192), format `5` (`FORMAT_RGBA8`). The stroke handler additionally range-checks `x ∈ [45, 298]`, `y ∈ [61, 103]` — a 254×43 banner box. Replaying the deltas from a zero origin produces a 247×22 glyph field across 58 strokes, and solving for the offset that satisfies every bound check gives `ox ∈ [41, 48]`, `oy ∈ [50, 71]` — consistent, and a useful independent check that the delta decode was right.

## 8. Final payload

Full solver: `saltcrown_solve.py` — unpacks, derives, decrypts, rasterises. Reproduction:

```bash
cd /home/kali/HTB_CA2026/Salt_Crown
pip install unicorn pefile cryptography
python3 saltcrown_solve.py challenge_core.windows.template_release.x86_64.dll
```

The derivation core, once the constants are extracted:

```python
X = lambda a, b: bytes(p ^ q for p, q in zip(a, b))
secret = X(X(X(R(0x18004D130,32), R(0x18004D110,32)),
             X(R(0x18004D170,32), R(0x18004D150,32))),
           X(R(0x18004D1B0,32), R(0x18004D190,32)))

TH   = hashlib.sha256(transcript).digest()
key  = hkdf(secret + TH, R(0x180041090,32),
            R(0x180041068,21) + R(0x180041080,16), 32)

g = AESGCM(key)
rounds = [g.decrypt(npfx + struct.pack(">I", i),
                    CT[i*0x30:(i+1)*0x30],
                    aadc + struct.pack("<I", i) + struct.pack("<I", 1024))
          for i in range(1024)]
```

Output: `flag.png`, 247×22 banner, two lines.

> [!warning] The rendered braces read as brackets
> The plotter font draws `{` and `}` with square corners, so the raster reads `HTB[...]`. Submit with braces. Likewise every `0` is the digit — the font's zero carries no slash.

## 9. Tools & techniques
Unicorn 2.1.4 (packer-stub emulation) · Capstone 5.0.9 (x86-64 disassembly) · pefile 2024.8.26 (section/import parsing) · `cryptography` 46.0.6 (AES-GCM, HKDF) · Python 3.12.3 (constant extraction, replay, PNG rasterisation via `zlib` only) · `dishelp.py` (purpose-built — Capstone wrapper annotating RIP-relative operands with resolved target VAs and inlined ASCII; the tool that made `_bind_methods` recoverable by string xref) · `saltcrown_solve.py` (purpose-built — end-to-end unpack → derive → decrypt → rasterise)
Concepts: compression packers with zero-raw-size destination sections · godot-cpp GDExtension `_bind_methods` recovery from RTTI + string xrefs · deterministic-transcript key derivation · RFC 5869 HKDF identification from HMAC call shape · environmental keying via anti-debug XOR · AEAD tag as a free correctness oracle · vector-program flag rendering

## 10. MITRE ATT&CK
- **T1027** Obfuscated Files or Information — the entire payload is a packed section plus an encrypted command table; no flag string exists at rest
- **T1027.002** Software Packing — `.slt1` → `.slt0`, aPLib-family decompressor with E8/E9 fixup, destination section carrying `RawSize 0`
- **T1027.009** Embedded Payloads — 48 KB AES-256-GCM ciphertext table at `0x180041100`, plus the three-way XOR-split secret
- **T1140** Deobfuscate/Decode Files or Information — runtime decompression, then per-round HKDF + AEAD decryption
- **T1480** Execution Guardrails — the stage-order table at `0x18004d108` refuses to record out-of-order events, and the terminator opcode is accepted only at round `0x3ff`
- **T1480.001** Environmental Keying — the four anti-debug results XOR into the KDF secret; a debugged process derives a wrong key rather than taking a detection branch
- **T1622** Debugger Evasion — `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB `BeingDebugged`, and a self-checksum over the routine's own first `0x30` bytes

> [!note] Honest scope of this mapping
> These IDs were assigned without access to the live ATT&CK matrix and should be re-checked before reuse. This is an offline game binary — there is no host, no network, and no victim — so only the defensive-evasion and obfuscation classes the artifact genuinely exhibits are claimed. **The weakest ID is T1480**: the stage-order table is a puzzle-correctness check, and calling it a guardrail stretches the technique toward its edge. T1480.001 is the strongest and most transferable of the set. No execution, persistence, collection, or C2 technique is claimed, because none occurs.

## 11. Detection / blue-team & fix notes

- **The transferable class is environmental keying, not the puzzle.** Anti-debug results folded into key material is materially harder to defeat than an anti-debug branch: there is no jump to patch and no boolean to flip. The observable symptom in a sandbox is decryption failure, which analysts routinely misattribute to their own tooling. When AEAD tags fail under instrumentation but the surrounding parse looks correct, **suspect the environment before suspecting the model.**
- **Detection — behavioural.** A section whose `SizeOfRawData` is 0 while `Misc.VirtualSize` is large, combined with an export whose RVA lands inside that section, is a high-fidelity static packer signal and is cheap to score at scan time.
- **Detection — API shape.** `BCryptOpenAlgorithmProvider` with the HMAC flag toggled by a caller-supplied boolean, immediately followed by a counter-fed HMAC loop, is HKDF. Recognising the primitive from its call shape is faster than reversing it, and it collapses a large amount of surrounding code.
- **Analyst guidance — an AEAD tag is a free oracle.** Sixteen candidate anti-tamper values were resolved by trial decryption, not by reasoning about which checks would pass. Any time an unknown feeds authenticated decryption and its space is small, enumerate it rather than model it.
- **Fix note for this class of design.** If a challenge or licence check intends to require genuine interaction, the KDF input must contain something the client cannot compute offline — a server nonce, or state derived from unpredictable input. A transcript assembled entirely from compile-time immediates is a constant with extra steps.

## 12. Method notes

- **The section table answered the first question for free.** `RawSize 0` with a `0x3f000` virtual size settled "is this packed" before a single instruction was read. Read the section table before the disassembly.
- **The pivot was structural, not cryptographic.** Nothing about the crypto was novel — it is stock HKDF over stock AES-GCM. The whole solve turned on noticing that the dispatcher's emitted values were immediates. **Check whether the inputs to a hash are actually variable before reversing the hash.**
- **Emulate to unpack; reimplement to solve.** Two harnesses were spent trying to emulate deeper into the DLL before it became clear the crypto reproduced in ~40 lines of Python. Emulation is the right tool for a self-modifying stub and the wrong one for a documented KDF.
- **Round-invariance is worth checking explicitly.** Assuming a per-round ratchet cost time. `IKM`/`salt`/`info` were all constant; only the counter moved. One `grep` for what actually varied per round would have found it sooner.
- **The table-boundary coincidence was the strongest confirmation available.** `0x180041100 + 1024 × 0x30 = 0x18004d100`, exactly the `SCTR` prefix. Layout hypotheses that land precisely on the next known structure are almost never wrong.
- **Verify with the tags, not with the eyes.** The flag is read off a raster, which is inherently fuzzy. 1024/1024 valid GCM tags is what actually proves the derivation; the image only had to be legible enough to transcribe.

## 13. Blind alleys

- **The SCX1 PCK.** Real, decryptable in principle, and irrelevant. Roughly the first third of the session went into the EXE loader before it became clear the flag never passes through GDScript.
- **Emulating `library_init` to reach the methods natively.** Two harness iterations (`gdmock.py`, `gdmock2.py`) crashed on the CFG dispatch pointer and on a mock `get_proc_address` returning garbage. Both were fixable — but the realisation that the crypto was pure-Python reproducible made the entire emulation path unnecessary. **Emulate to unpack; reimplement to solve.**
- **Reproducing the anti-debug environment.** Considered running under a clean process to let the DLL compute its own tamper value. Unnecessary: the value has only 16 possible states and the GCM tag is a free oracle for which one is correct.
- **Reading the flag as bytes.** There are no ASCII bytes to find. Several rounds of looking for a plaintext string in the decrypted output preceded understanding that the output is a vector program.

## 14. Open items

- **State field `+0x0c` is unresolved.** Opcode `0x37a5` gates on it and *no opcode in the dispatcher writes it*. Presumed to be set from GDScript inside the SCX1 PCK, most likely via `render_reward_step` — **unverified**, and it is the one thing that would be needed to reconstruct the intended in-game path.
- **The SCX1 PCK was never decrypted.** The AES key derivation in the EXE loader at `0x142a1bf10+` was not extracted. Deliberate scope decision; the GDScript layer is the only place `+0x0c` could plausibly be resolved.
- **`solves` omitted** — the platform scenario page displays POINTS and DIFFICULTY only; no solve count is published there to read.
- **The draw brush was approximated.** `0x1800070c0` stamps a multi-pixel anti-aliased pattern with four distinct `Color` values; the rasteriser here draws a 1px run. Sufficient to read the banner, not a faithful reproduction of what the game would display.
- **The 433 `0x5d` no-op rounds were not investigated.** They carry 31 bytes of payload each that is never read. Possibly padding to a fixed 1024, possibly something else.

## Cross-references
- [[HTB-CA2026-Secondhand-Overlapping-Instruction-Self-Decrypting-Stub]]
- [[HTB-CA2026-Cinder-Engine-AArch64-VM-SPN-Inversion]]
- [[HTB]]

## Change Log
- 2026-07-30 — `category` corrected `reversing` → `GamePwn`, the platform's own category name, per the writeup standard's rule that the field is verbatim from the scenario page. This was the event's sole GamePwn challenge and the team's only category finishing 0 of 1 flags. Header callout revised from a bare "Solved" to **solved-but-uncredited**: the flag was recovered and verified by 1024/1024 GCM tags under fifteen minutes before the end timer, and was not submitted in time, so its 975 points are absent from the team total. `status: complete` retained deliberately — the analysis and the note are complete; only submission was missed. `tags` left as `Reverse_Engineering` + `Cryptography`, which describe the work accurately and have registry entries where `GamePwn` does not. Added to [[00_CA2026-event-roll-up]], from which this room had been missing entirely.
- 2026-07-29 — Tools & techniques corrected against the environment that reproduced the solve: Capstone 5.0.7 → 5.0.9 (the 5.0.7 figure was carried from a session summary and never verified), pefile 2024.8.26 and Python 3.12.3 versions supplied where previously absent. Added the two purpose-built scripts — `dishelp.py` (RIP-relative annotating Capstone wrapper) and `saltcrown_solve.py` (end-to-end solver) — which the section had omitted entirely.
- 2026-07-29 — Tail order corrected: Blind alleys moved from §8 to §13, between Method notes and Open items, per writeup standard §7 and the precedent set by the Assay note; §§9–13 renumbered to §§8–12. Unterminated quotation closed in §6. Withdrew the points/difficulty caveat from Open items — both are verbatim from the platform scenario page (975 POINTS, hard DIFFICULTY), the provenance §1.2 requires.
- 2026-07-29 — Note created. Full solve documented: Unicorn emulation of the `.slt1` compression packer; `_bind_methods` recovery and the four-method `ChallengeCore` API; the seven-opcode gated state machine and its stage-order table; identification of the session transcript as fully deterministic (the core defect); three-way XOR-split secret reassembly; anti-tamper environmental keying resolved by 16-candidate brute force against the round-0 GCM tag; HKDF-SHA256 → AES-256-GCM key schedule with round-invariant key; and replay of the 1024-round vector draw program to rasterise the flag banner.
