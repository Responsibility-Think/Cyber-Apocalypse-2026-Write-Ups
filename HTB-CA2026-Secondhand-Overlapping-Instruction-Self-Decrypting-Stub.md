---
title: "HTB CA2026 — Secondhand: Four Decoys and a Self-Decrypting Overlapping-Instruction Stub"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Secondhand
app: secondhand (standalone crackme)
category: reversing
difficulty: insane
points: 975
solves: 193
type: writeup
status: complete
mitre:
  - T1027
  - T1027.009
  - T1140
  - T1480
  - T1620
  - T1622
tags:
  - writeup
  - HTB
  - Security
  - Reverse_Engineering
  - Cryptography
related:
  - "[[HTB]]"
  - "[[HTB-CA2026-Cinder-Engine-AArch64-VM-SPN-Inversion]]"
  - "[[HTB-CA2026-CorpSyncAudit-Log-Steganography-Shellcode-Dropper]]"
aliases:
  - Secondhand
  - CA2026 Secondhand
created: 2026-07-25T04:03:01.661Z
updated: 2026-07-25T04:41:07.265Z
---

# Secondhand — Four Decoys and a Self-Decrypting Overlapping-Instruction Stub

> [!success] Solved
> Flag: `HTB{WHY_S00_345Y_H0N}` — printed by the binary when fed the correct 8-byte input.
> Input: `0f6880178d2f3828` (little-endian `0x28382f8d1780680f`).
> Solved 2026-07-25 00:02 local. Single 14 KB x86-64 ELF, no server.

## 0. How the flag was obtained

1. `nm` — only 3 symbols (`threat_level_midnight`, `b_roll`). `strings` gave a set of narrative hints, all literally true.
2. Read `main` at `0x401100`: three checkers dispatched by input length — **8**, 28, 16 — with the 8-byte path checked *first*, before the anti-debug gate.
3. Inverted `b_roll` (28 bytes) → `HTB{secondhand_rough_cut_v3}`. **Rejected** — the binary calls it "the rough cut".
4. Reversed `threat_level_midnight` (16 bytes) via a custom oracle harness; the preimage is binary and contains `0x0d`, which the reader strips — **path unreachable by design**.
5. Followed the loader at `0x401c50`: a 38-byte blob @ `0x402560`, decrypted **backwards** with `rol 3` + a 7-byte key, then `mmap`/`mprotect(R|X)`/call.
6. Found the entry point is computed: `0x401dd0 + ((len & 31) ^ 14)` → for `len=8` that is `0x401dd6`, **two bytes into a `movabs`** — overlapping instructions. The real check is `~(rol(x ^ 0xa5a5a5a5deadbeef, 17) * FNV_prime) == 0xb8491337c0debabe`.
7. Inverted with one modular inverse → `0x28382f8d1780680f`. Piped the 8 little-endian bytes to the binary, which printed the flag.

## 1. Shape of the challenge

`secondhand` — 14,496 bytes, `ELF 64-bit LSB executable, x86-64, non-PIE, dynamically linked, not stripped`.

"Not stripped" is a lie of omission: `.symtab` holds **3 entries**, two of them functions. Everything else was stripped and a token symbol table left behind.

The scenario's operative line:

> *"Run it and it holds together perfectly, every joint clean, every tolerance dead on, which is exactly the problem."*

The artifact passes its own checks. The finding cannot come from running it, nor from anything self-consistent.

## 2. The binary documents its own backdoor

Every narrative string is a technical statement in costume, and all of them are literally true:

| String | Actual meaning |
|---|---|
| *"The honest take got cut. It is still in here, it is just not the one running."* | The real check is **encrypted code**, absent from the disassembly |
| *"There is a camera in the room. Cutting to the version where everyone behaves."* | Anti-debug: `ptrace` + `/proc/self/status` → `TracerPid:` |
| *"…it only feeds clean if you start the page from the inner crease, not from the top."* | The hidden stub is entered **mid-instruction** |
| *"That is the line we cut into the trailer. It tested well. It is not in the film."* | Printed on success by **both** visible checkers — an explicit decoy label |
| *"rolling key"* / *"round multiplier"* / *"the rotor pass"* | Components of the decoy block cipher |

Imports corroborate: `mmap`, `mprotect`, `munmap`, `memcpy` — runtime code generation.

## 3. Three checkers, dispatched by input length

`main` (`0x401100`) branches on the length of the line read from stdin:

```
len == 8   -> 0x401a40                 (checked FIRST, before the anti-debug gate)
len == 28  -> b_roll
len == 16  -> threat_level_midnight
```

## 4. The decoys, and what disqualified each

This challenge is 80% misdirection. Four separate traps, each disqualified by different evidence.

### Decoy 0 — the symbol names themselves

The only two names left in `.symtab` invert the reader's priorities:

- **`threat_level_midnight`** — Michael Scott's magnum opus. Sounds like the main event. It is the largest, most sophisticated decoy in the file.
- **`b_roll`** — film jargon for *unused alternate footage*. Sounds like dead code. It is a live, reachable checker.

Both names point attention at the wrong things, and the *real* check has no symbol at all because it does not exist as code until runtime. **Disqualifier:** names are attacker-controlled metadata and carry zero evidential weight — the same lesson as `.riscv.attributes` in [[HTB-CA2026-First-Mark-RISCV-Custom-Opcode-Recovery]].

### Decoy 1 — `HTB{secondhand_rough_cut_v3}` (28-byte path, `b_roll`)

103 bytes, self-contained, invertible on sight:

```
len == 28,  key = 0x5a
enc[i] = rol8((s[i] + 31*i) & 0xff, 3) ^ key
key   += s[i]                      ; rolling key fed by PLAINTEXT
```

Inverting against the 28-byte target at `0x402040` yields a **perfectly well-formed flag**, which is exactly what makes it dangerous.

**Disqualifiers, in order of strength:**
1. Submitted and rejected.
2. The recovered string self-identifies: `..._rough_cut_v3`. The binary's own narrative calls this *"the rough cut… the version we agreed to air, not the version that happened."*
3. On success the program prints *"That is the line we cut into the trailer. It tested well. **It is not in the film.**"* — the author labelling his own decoy.

### Decoy 2 — the `threat_level_midnight` 16-byte answer

The impressive one: 1,345 bytes of SIMD implementing a 10-round SPN.

- **S-box** built by SIMD: `sbox[i] = (27*i) ^ 0x63`
- **Key schedule**: SplitMix64 (`0x9e3779b97f4a7c15`, shifts 30/27, FNV prime) → 176 bytes = 11 round keys
- **Permutation**: standard AES **ShiftRows**, and no MixColumns
- **"Rotor pass"**: rolling XOR-rotate, `d = rol8(state[i] ^ key, (i+r) % 8); key += d`
- Target `7ac4119e386df0528b2fd74019a663ec` at `0x402510`

Inversion gives `cda50dba01b2cb5578ce21798832f03b`.

**Disqualifier:** the plaintext is binary and contains **`0x0d`**. The input reader strips `\r`, so a 16-byte line containing a carriage return can never reach the checker — the path is unreachable by construction. This was not a guess: it was established against an oracle-verified model of the cipher (§7), which is what separates "this path is bait" from "my analysis failed." It also prints the same *"not in the film"* message on success.

### Decoy 3 — the string `H4D5_UP_Y0U_M4D3_IT`

Sits in `.rodata` at `0x402027`, decodes as **"HEADS UP YOU MADE IT"**, and is printed by the *correct* 8-byte path — immediately adjacent to the real flag's code.

**Disqualifier:** it is not in `HTB{...}` form, and it is a congratulation line rather than a flag. Its job is to make a solver who reaches the right path *stop one step short*, satisfied by a plausible-looking payoff string. The actual flag is emitted by the same path and is the one wearing the brace format.

### Decoy 4 — the "from the top" instruction stream

Reading the hidden stub from `0x401dd0` yields a coherent, plausible 64-bit hash loop (`xor`/`rol`/`imul` over the input). It is never executed. **Disqualifier:** the dispatcher computes its entry as `0x401dd0 + ((len & 31) ^ 14)`, which for `len == 8` lands at `0x401dd6` — a different instruction boundary entirely (§5). *"Feeding it from the top is why it keeps jamming."*

## 5. The real check — encrypted, self-decrypting, entered mid-instruction

`0x401c50` decrypts a blob, maps it executable, and calls it:

```
src walks BACKWARD:  b = rol8(src[base - i], 3) ^ key[i % 7]     ; key = 7 bytes @ 0x402535
mmap → memcpy → mprotect(PROT_READ|PROT_EXEC) → call
```

The blob is 38 bytes at `0x402560` (length `0x26` at `0x402540`). Decrypted:

```asm
mov     rax, rdi
movabs  r11, 0xa5a5a5a5deadbeef
xor     rax, r11
rol     rax, 0x11
movabs  r11, 0x100000001b3
imul    rax, r11
not     rax
ret
```

**The "inner crease".** Entry point is `0x401dd0 + ((len & 31) ^ 14)`; for `len == 8` that is `0x401dd6`, **two bytes into a `movabs`**. The same bytes decode two ways:

| From `0x401dd0` ("the top") | From `0x401dd6` ("the inner crease") |
|---|---|
| `movabs rax, 0x1337c0debabeba49` | `movabs r10, 0xb8491337c0debabe` |
| `movabs r8, 0xc031c30175d0394c` | `cmp rax, r10` / `jne` / `ret` |

## 6. Solve

```python
M = (1<<64) - 1
C, P, TGT = 0xa5a5a5a5deadbeef, 0x100000001b3, 0xb8491337c0debabe
ror = lambda x, n: ((x >> n) | (x << (64-n))) & M

y = (~TGT) & M
y = (y * pow(P, -1, 1<<64)) & M
y = ror(y, 17)
x = y ^ C                       # 0x28382f8d1780680f
```

Feeding the 8 little-endian bytes `0f6880178d2f3828` prints **`HTB{WHY_S00_345Y_H0N}`**.

## 7. The harness — how decoy 2 was *proved* to be a decoy

Reading the SIMD round function by eye produced a model that round-tripped with itself but did not match the binary. Rather than keep guessing, the binary became an **oracle**.

Non-PIE, so ~40 lines of C suffice: `mmap` each `PT_LOAD` at its fixed vaddr, point the `memcpy` GOT slot (`0x403fc0`) at real `memcpy`, patch the round count (the `0x0a` byte at `0x4019c4`), and overwrite the final compare at `0x4019cb` with

```asm
movdqa xmm0, [r15]              ; state
movups [0x500000], xmm0         ; export it
```

then call `0x4014f0` directly. Two NOP patches (`0x4019ab`, `0x4019ad`) disable the rotor.

With a **configurable-round encryption oracle**, everything became measurement:

- single-byte differentials → the permutation is exactly AES ShiftRows
- a 256-value sweep of one position → `T(v) = (27·(v ^ k)) ^ 0x63`, confirming the S-box
- peeling rounds one at a time → every round key, **without** the SplitMix64 derivation (which was wrong)
- the model then matched the oracle on random 10-round inputs

That verified model is what turned "my 16-byte answer looks wrong" into "the 16-byte path is unreachable."

## 8. Final payload

```python
M = (1<<64) - 1
C, P, TGT = 0xa5a5a5a5deadbeef, 0x100000001b3, 0xb8491337c0debabe
ror = lambda x, n: ((x >> n) | (x << (64-n))) & M

y = (~TGT) & M                      # undo  not
y = (y * pow(P, -1, 1<<64)) & M     # undo  imul
y = ror(y, 17)                      # undo  rol
x = y ^ C                           # undo  xor   -> 0x28382f8d1780680f

open('/tmp/in','wb').write(x.to_bytes(8,'little') + b'\n')
```

```bash
$ python3 solve.py && ./secondhand < /tmp/in | tail -1
HTB{WHY_S00_345Y_H0N}
```

The 8 bytes are `0f 68 80 17 8d 2f 38 28`. Note they are **not printable** — the input must be piped, not typed.

## 9. Tools & techniques
`objdump` / Capstone (x86-64 disassembly) · `readelf` (segment + symbol mapping) · custom C harness (ELF segment loader + GOT patching + in-memory code patching, used as an encryption oracle) · Python (inversion, differential analysis)
Concepts: overlapping instructions · self-decrypting code · runtime code generation (`mmap`/`mprotect`) · anti-debug via `ptrace` and `TracerPid` · length-dispatched execution guardrails · decoy checkers and decoy flags · SPN cryptanalysis by oracle differential

## 10. MITRE ATT&CK
- **T1027** Obfuscated Files or Information — the real check exists only as an encrypted blob; three decoy checkers occupy the disassembly
- **T1027.009** Embedded Payloads — 38-byte encrypted stub carried in `.rodata` at `0x402560`
- **T1140** Deobfuscate/Decode Files or Information — decrypted at runtime, read **backwards**, `rol 3` + 7-byte cycling key
- **T1480** Execution Guardrails — the stub's entry offset is computed from the input length (`0x401dd0 + ((len & 31) ^ 14)`), so only one length reaches the real check
- **T1620** Reflective Code Loading — `mmap` → `memcpy` → `mprotect(PROT_READ|PROT_EXEC)` → `call`, never touching disk
- **T1622** Debugger Evasion — `ptrace(PTRACE_TRACEME)` plus `/proc/self/status` → `TracerPid:`, diverting to a benign path when observed

> [!note] Honest scope of this mapping
> ATT&CK describes adversary behaviour against systems. This is an offline crackme, so only the **defensive-evasion** techniques the artifact genuinely demonstrates are listed. No execution, persistence, or C2 techniques are claimed, because none occur.

## 11. Detection / blue-team & fix notes
- **The transferable finding is the technique stack, not the puzzle.** Self-decrypting code that is read backwards, mapped `RX` at runtime, and entered at a computed mid-instruction offset is a real packer/loader pattern. Every element here appears in commodity malware.
- **Detection — behavioural:** the highest-fidelity signal is an `mprotect` call granting `PROT_EXEC` to an anonymous `mmap` region shortly after a write to it. `W^X` violations at runtime are rare in benign software and cheap to instrument via eBPF or EDR syscall telemetry.
- **Detection — anti-analysis:** `ptrace(PTRACE_TRACEME)` from a process that is not a debugger, and reads of `/proc/self/status` filtered for `TracerPid`, are both strong indicators. Neither has a common benign use in a file-processing utility.
- **Analyst guidance — overlapping instructions defeat linear disassembly.** Every tool here (objdump, Capstone) rendered the stub from `0x401dd0` and produced a coherent but **never-executed** instruction stream. When a computed jump target is not instruction-aligned with the surrounding listing, re-disassemble from the actual target before trusting anything.
- **Analyst guidance — do not trust symbol names.** `threat_level_midnight` (the largest, most sophisticated function) is a decoy; `b_roll` ("unused footage") is live. Names are attacker-controlled metadata.
- **Analyst guidance — verify a decoy is a decoy.** The 16-byte checker was only *proved* inert by building an oracle-verified model of the cipher and showing its preimage contains `0x0d`, which the input reader strips. Without that, "my answer looks wrong" and "this path is unreachable" are indistinguishable.

## 12. Method notes

- **The biggest function is not the most important one.** Most of this session went into `threat_level_midnight` because it looked serious. It was a sink. The binary stated plainly that the running code was not the honest one, and the running code got reversed anyway.
- **Order candidate paths by cost, not by apparent importance.** The 8-byte gate is dispatched *first*, before the anti-debug check and before either heavyweight checker, and it fell to a single modular inverse. Trying the three in cost order would have finished this in a fraction of the time.
- **When an artifact describes itself, believe it literally.** *"Still in here, just not the one running"* = encrypted code. *"Start from the inner crease"* = mid-instruction entry. *"There is a camera in the room"* = `TracerPid`.
- **Build the oracle before the third guess, not after the tenth.** Two structural guesses failed before the harness was built; it took minutes and eliminated every remaining unknown.
- **A well-formed flag is not evidence of a correct flag.** Decoy 1 had valid `HTB{}` syntax, thematic wording, and a clean derivation. The only things that disqualified it were the submission result and the binary's own commentary.
- **Plausible strings adjacent to real ones are a deliberate trap.** `H4D5_UP_Y0U_M4D3_IT` exists to make a solver stop one step short on the *correct* path.

## 13. Open items

- The 28-byte blob at `0x402520` was never explained. Bytes `0x402535..0x40253b` serve as the stub's XOR key; the surrounding 21 bytes have no identified use. Inverting `b_roll`'s algorithm against it produced nothing.
- The four "editing log" strings are never referenced by any code path — presumed hint text, not confirmed by xref.
- `threat_level_midnight`'s SplitMix64 key schedule does not produce the round keys the binary actually uses; keys were extracted empirically and the discrepancy was not chased down.
- `.data` (16 bytes, all zero) and the first 4 bytes of `.rodata` (`01 00 02 00`) remain unaccounted for.

## Cross-references
- [[HTB-CA2026-Cinder-Engine-AArch64-VM-SPN-Inversion]]
- [[HTB-CA2026-CorpSyncAudit-Log-Steganography-Shellcode-Dropper]]
- [[HTB]]

## Change Log
- 2026-07-25 — Note created. Full solve documented: four distinct decoys catalogued with the evidence disqualifying each (symbol-name misdirection, the well-formed `b_roll` flag, the unreachable 16-byte SPN answer, the adjacent `H4D5_UP` string, and the "from the top" instruction reading); recovery of the backward-decrypted self-modifying stub and its overlapping-instruction entry point; a custom encryption-oracle harness used to prove the SPN path unreachable; and inversion of the 64-bit mix yielding the flag.
