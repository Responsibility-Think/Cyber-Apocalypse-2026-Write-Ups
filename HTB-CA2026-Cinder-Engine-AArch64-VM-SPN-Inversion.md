---
title: "HTB CA2026 — The Cinder Engine: Recovering a Custom VM ISA and Inverting Its SPN"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: The Cinder Engine
app: cinder (AArch64 bytecode interpreter + embedded firmware)
category: reversing
difficulty: medium
points: 975
solves: 225
type: writeup
status: complete
mitre:
  - T1027
  - T1140
  - T1480.001
tags:
  - writeup
  - HTB
  - Security
  - Reverse_Engineering
  - Cryptography
related:
  - "[[HTB-CA2026-First-Mark-RISCV-Custom-Opcode-Recovery]]"
  - "[[HTB-CA2026-Ringtrue-MLP-Inversion-Int8-Keygen]]"
aliases:
  - The Cinder Engine
  - CA2026 Cinder Engine
created: 2026-07-25T02:39:27.581Z
updated: 2026-07-25T04:41:07.265Z
---

# The Cinder Engine — Recovering a Custom VM ISA and Inverting Its SPN

> [!success] Solved
> Flag: `HTB{c1nd3r_3ng1n3_unw0und}` — confirmed by executing the recovered input through a reimplementation of the VM, which printed it directly.
> Input (32 bytes, binary): `83efaaac9b9a46fbfe0cb665e082127080782320d51c1d134f5bcd157abaf50f`
> Solved 2026-07-24. Single 14 KB AArch64 binary, no server.

## 0. How the flag was obtained

1. `readelf -S cinder` — `.text` 1,492 B but `.rodata` 4,918 B and `.bss` 65,608 B, plus the string `bad opcode`. Section geometry alone says **interpreter**, not program.
2. Disassembled `.text` with Capstone (`CS_ARCH_ARM64`) and read the fetch/decode block at `0x920`: `op = byte3`, `a = byte2>>4`, `b = byte2&0xf`, `c = byte0&0xf`, `imm16 = word & 0xffff`.
3. Walked the `cmp`/`b.eq` dispatch tree to recover all 22 opcodes, including `0xc6` = read from the program image itself.
4. Reimplemented the VM in ~40 lines of Python and traced execution: 32-byte input, mirrored to `mem[0x40]`, then 8 rounds.
5. Identified the firmware as an SPN — S-box @ `prog[0x10c4]` (verified bijective), 9 round keys @ `prog[0x11c4]`, GF(2)-linear mix layer parsed out of the unrolled `LDB`/`XOR`/`STB` stream.
6. Inverted it: inverse S-box, Gauss-Jordan inverse of the 32×32 GF(2) mix matrix, XOR-undo the round keys, unwound 8 rounds from the target @ `prog[0x12e4]`.
7. Flag = `input[0..25] XOR prog[0x1304..]` — because the prologue kept a pristine copy of the input. Confirmed by feeding the preimage to the reimplemented VM, which printed the flag itself.

## 1. Shape of the challenge

One file: `cinder`, 14,248 bytes, `ELF 64-bit LSB pie executable, ARM aarch64, dynamically linked, **stripped**`.

The scenario states the task in three clauses, and each maps to a layer:

> *"Work out its opcode map from how it moves. Pull the firmware apart and find the cipher hiding in its tables. Then feed it something worth saying."*

Three nested layers: an ARM64 interpreter, a custom bytecode ISA, and a block cipher written in that bytecode.

## 2. Identifying a VM before disassembling one

Section sizes alone give the structure away:

| Section | Size | Reading |
|---|---|---|
| `.text` | 1,492 B | 373 ARM64 instructions — far too small for the observed behaviour |
| `.rodata` | 4,918 B | larger than the code — the *program* |
| `.bss` | 65,608 B | 64 KB + 72 — VM RAM plus registers |

Imports are `getc`, `putc`, `fwrite`, `abort`, `stdin`, `stdout`. The only meaningful string is **`bad opcode`**. Small code + large data + a "bad opcode" error path is the signature of an interpreter.

Architecture note: the binary is AArch64 while prior challenges in this set were x86-64 and RV32. Running it natively requires `qemu-user`; static analysis does not, and was sufficient throughout.

## 3. Recovering the opcode map

Disassembly of `.text` with Capstone (`CS_ARCH_ARM64`) yields a clean fetch/decode block at `0x920` and a `cmp`/`b.eq` dispatch tree.

Fetch/decode:

```
w2 = byte2 << 16
w0 = byte0 | (byte3 << 24)
w1 = (byte2 << 16) | (byte1 << 8)
w20 += 4                       ; pc advances before the handler runs
w2 = w1 | w0                   ; full little-endian 32-bit word
w0 = w2 >> 24                  ; OPCODE = high byte
w5 = w2 & 0xffff               ; imm16
w4 = sign_extend16(w5)         ; simm16
w6 = w2 & 0xf                  ; register c
w3 = (byte2 >> 4) & 0xf        ; register a
w1 = byte2 & 0xf               ; register b
```

Machine state: **16 × u32 registers** at `.bss+0x18`, **64 KB byte-addressable RAM** at `.bss+0x58`, one zero/equal **flag**, an input buffer of up to 4,096 bytes slurped from stdin before execution, and a program of 4,894 bytes at `.rodata+0x18`.

Full ISA, recovered by reading each dispatch arm:

| Op | Mnemonic | Semantics |
|---|---|---|
| `0x00` | HALT | return |
| `0x11` | MOV | `R[a] = R[b]` |
| `0x29` | ROL | `R[a] = rol32(R[b], word & 31)` |
| `0x2a` | ROR | `R[a] = ror32(R[b], word & 31)` |
| `0x2b` | SHL | `R[a] = R[b] << (word & 31)` |
| `0x2c` | SHR | `R[a] = R[b] >> (word & 31)` |
| `0x3a` | LI | `R[a] = imm16` |
| `0x52` | XOR | `R[a] = R[b] ^ R[c]`; flag `= (R[b]==R[c])` |
| `0x53` | AND | `R[a] = R[b] & R[c]`; flag `= (R[a]==0)` |
| `0x54` | OR | `R[a] = R[b] \| R[c]`; flag `= (R[a]==0)` |
| `0x6b` | MUL | `R[a] = R[b] * R[c]`; flag `= (R[a]==0)` |
| `0x7c` | ADD | `R[a] = R[b] + R[c]`; flag `= (R[a]==0)` |
| `0x7d` | SUB | `R[a] = R[b] - R[c]`; flag `= (R[a]==0)` |
| `0x80` | ADDI | `R[a] = R[b] + imm16`; flag `= (R[a]==0)` |
| `0x90` | CMP | flag `= (R[b] == R[c])` |
| `0xa0` | JMP | `pc += simm16` |
| `0xa1` | JT | jump if flag |
| `0xa2` | JF | jump if not flag |
| `0xc4` | LDB | `R[a] = mem[(imm16 + R[b]) & 0xffff]` |
| `0xc5` | STB | `mem[(imm16 + R[b]) & 0xffff] = R[a] & 0xff` |
| `0xc6` | LDP | `R[a] = prog[(imm16 + R[b]) mod 4894]` |
| `0xe0` | GETC | next input byte, or `0` with flag set at EOF |
| `0xe1` | PUTC | `putc(R[b] & 0xff)` |

**`0xc6` is the interesting one.** It reads the *program image itself* as data — which is how every constant table (S-box, round keys, target, keystream) is addressed. There is no separate data segment.

Jump targets are relative to the *following* instruction, since `pc` is incremented during decode.

## 4. The firmware: an 8-round SPN

Reimplementing the VM in Python and tracing execution shows the program never calls `PUTC` on wrong input — it computes silently and halts. Matching the scenario's *"says true or false at the end"*.

Prologue (`0x0000`–`0x0020`): read **32 bytes**, store to `mem[0x00..0x1f]`, **and mirror them to `mem[0x40..0x5f]`**. Short input is zero-padded.

Then:

```
0x0024  ARK      mem[i] ^= prog[0x11c4 + i]                    ; initial round key
0x0054  ROUND ×8 (r6: 1→9)
  0x0058    SubBytes  mem[i] = prog[0x10c4 + mem[i]]           ; 256-byte S-box
  0x0070    MixLayer  mem[0x80+j] = XOR of a fixed subset of mem[0..31]
  0x101c    copy back mem[i] = mem[0x80+i]
  0x1034    ARK       mem[i] ^= prog[0x11c4 + 32*r + i]
0x1068  verify   mem[i] == prog[0x12e4 + i]  for i in 0..31    ; else HALT, silent
0x109c  emit     putc( mem[0x40+i] ^ prog[0x1304+i] )  for i in 0..25
```

Table layout in the program image is contiguous and self-validating:

| Offset | Size | Contents |
|---|---|---|
| `0x10c4` | 256 | S-box — verified **bijective** |
| `0x11c4` | 9 × 32 | round keys `K[0..8]`, ending exactly at `0x12e4` |
| `0x12e4` | 32 | target ciphertext |
| `0x1304` | 26 | flag keystream, ending exactly at program end `0x131e` |

The mix layer is GF(2)-linear: each of the 32 output bytes is the XOR of an 11–20 element subset of the input bytes. It parses directly out of the unrolled `LDB`/`XOR`/`STB` instruction stream.

## 5. Inversion

Every stage is invertible, so no search is required:

- **S-box** — bijective, so build `INV[SBOX[i]] = i`.
- **Mix layer** — a 32×32 binary matrix over GF(2); invert by Gauss-Jordan on bitmasks.
- **ARK** — XOR, self-inverse.

```python
def backward(t):
    st = t
    for r in range(8, 0, -1):
        st = bytes(a ^ b for a, b in zip(st, K[r]))   # undo ARK
        st = Linv(st)                                  # undo mix
        st = bytes(INV[x] for x in st)                 # undo SubBytes
    return bytes(a ^ b for a, b in zip(st, K[0]))      # undo initial ARK

rec  = backward(TARGET)
flag = bytes(a ^ b for a, b in zip(rec[:26], KS))      # HTB{c1nd3r_3ng1n3_unw0und}
```

Verified two ways: `forward(rec) == TARGET` algebraically, and feeding `rec` to the reimplemented VM, which printed the flag on its own.

## 6. Why it was solvable at all

**The prologue mirrors the raw input to `mem[0x40]` before the transform touches `mem[0x00]`.** The flag is keyed on that pristine copy, not on the cipher output. So recovering the SPN preimage is both necessary *and sufficient* — there is no second secret to hunt.

Had the flag been keyed on the ciphertext instead, the target is published in the binary and the challenge would have collapsed to a decode. Keying it on the preimage is what forces a genuine inversion.

## 7. Dead ends, both informative

- **Per-byte solving.** Flipping any single input bit changes all 32 output bytes — full diffusion after one round. Killed the approach in one test, cheaply.
- **GF(2) affinity.** The *executed* opcode histogram contained only `LDB`, `XOR`, `STB`, `ADD`, `ADDI` and control flow — no `MUL`, `AND`, `OR`, or shifts. That is nearly the profile of a linear-only cipher, so `F(a⊕b) ⊕ F(0) == F(a) ⊕ F(b)` was worth testing. It came back false, which correctly pointed at a real S-box hiding behind an `LDP` table read rather than arithmetic nonlinearity.

Both tests cost a few seconds and each eliminated a whole class of approach.

## 8. Final payload

```python
raw  = open('cinder','rb').read()
PROG = raw[0xe80:0xe80+0x131e]                 # VM program, .rodata+0x18

SBOX = PROG[0x10c4:0x10c4+256]                 # verified bijective
INV  = [0]*256
for i, v in enumerate(SBOX): INV[v] = i
K      = [PROG[0x11c4+32*r : 0x11c4+32*(r+1)] for r in range(9)]   # 9 round keys
TARGET = PROG[0x12e4:0x12e4+32]
KS     = PROG[0x1304:0x1304+26]                # flag keystream

def dec(pc):
    w = PROG[pc] | PROG[pc+1]<<8 | PROG[pc+2]<<16 | PROG[pc+3]<<24
    return w>>24, (PROG[pc+2]>>4)&0xf, PROG[pc+2]&0xf, PROG[pc]&0xf, w&0xffff

# --- parse the unrolled LDB/XOR/STB mix layer into 32 GF(2) subsets ---
rows, srcs = {}, []
for pc in range(0x0070, 0x101c, 4):
    op, a, b, c, imm = dec(pc)
    if   op == 0xc4: srcs.append(imm)          # LDB  -> a source byte
    elif op == 0xc5: rows[imm-0x80] = srcs; srcs = []   # STB -> row complete
Lm = [sum(1 << i for i in rows[j]) for j in range(32)]

# --- invert that 32x32 bit-matrix by Gauss-Jordan over GF(2) ---
R = [[Lm[j], 1 << j] for j in range(32)]
for col in range(32):
    p = next(r for r in range(col, 32) if (R[r][0] >> col) & 1)
    R[col], R[p] = R[p], R[col]
    for r in range(32):
        if r != col and (R[r][0] >> col) & 1:
            R[r][0] ^= R[col][0]; R[r][1] ^= R[col][1]
Linv = [R[j][1] for j in range(32)]

def apply(mat, st):
    o = bytearray(32)
    for j in range(32):
        v, m, i = 0, mat[j], 0
        while m:
            if m & 1: v ^= st[i]
            m >>= 1; i += 1
        o[j] = v
    return bytes(o)

st = TARGET
for r in range(8, 0, -1):                      # 8 rounds, backwards
    st = bytes(a ^ b for a, b in zip(st, K[r]))    # undo AddRoundKey
    st = apply(Linv, st)                           # undo MixLayer
    st = bytes(INV[x] for x in st)                 # undo SubBytes
rec = bytes(a ^ b for a, b in zip(st, K[0]))       # undo initial ARK

print(bytes(a ^ b for a, b in zip(rec[:26], KS)).decode())
# HTB{c1nd3r_3ng1n3_unw0und}
```

The 32-byte preimage is `83efaaac9b9a46fbfe0cb665e082127080782320d51c1d134f5bcd157abaf50f`. Feeding it to the reimplemented VM makes the engine print the flag itself.

## 9. Tools & techniques
`readelf` (section geometry — the tell that this was an interpreter) · Capstone (`CS_ARCH_ARM64`) · Python (VM reimplementation, opcode histograms, diffusion and affinity tests, GF(2) linear algebra)
Concepts: virtualisation-based obfuscation · custom bytecode ISA recovery from a dispatch tree · self-referential program image (`LDP` reads its own bytes as data) · substitution-permutation network · GF(2) matrix inversion · avalanche and affinity testing as triage

## 10. MITRE ATT&CK
- **T1027** Obfuscated Files or Information — virtualisation-based obfuscation: the real logic is bytecode for a bespoke 22-opcode VM, so no native disassembler ever sees the algorithm
- **T1140** Deobfuscate/Decode Files or Information — the firmware decodes its input through an 8-round SPN before comparison, with all constants addressed out of the program image itself
- **T1480.001** Execution Guardrails: Environmental Keying — the flag is a keystream XOR against the *accepted input*, so the plaintext is absent from the binary and patching the comparison yields nothing

> [!note] Honest scope of this mapping
> An offline crackme with no host interaction. Only the obfuscation and encoding techniques the artifact genuinely exhibits are listed.

## 11. Detection / blue-team & fix notes
- **Section geometry classifies a binary before any disassembly.** `.text` (1,492 B) smaller than `.rodata` (4,918 B), an outsized `.bss` (65,608 B), and a `bad opcode` string is the signature of an interpreter. Recognising it reframed the target from "reverse 1,492 bytes of ARM" to "recover an ISA, then reverse the program written in it" — the single highest-leverage decision in the whole analysis. Commercial VM packers (VMProtect, Themida) present the same profile.
- **Reimplement the VM rather than reason about it.** A ~40-line interpreter turned an opaque target into an instrumentable one: opcode histograms, single-bit diffusion tests, and finally end-to-end confirmation of the answer. For any virtualised binary, building the interpreter is cheaper than reading the bytecode.
- **Distinguish static from executed opcode distribution.** The static histogram over the image contained bytes that are not valid opcodes at all — those were embedded constant tables read via `LDP`. Only the *executed* histogram characterises the algorithm, and it was the absence of `MUL`/`AND`/`OR`/shifts there that motivated the affinity test.
- **Cheap invariants eliminate whole classes of approach.** Single-bit diffusion (full after one round) killed per-byte solving in one test. A GF(2) affinity check (`F(a⊕b) ⊕ F(0) == F(a) ⊕ F(b)`) came back false and correctly pointed at a genuine S-box rather than a linear-only cipher. Both cost seconds.
- **Table adjacency is a structural check.** S-box, round keys, target and keystream tile the program image end to end with no gaps, and the key block stops exactly where the target begins. That contiguity confirmed the layout hypothesis before any of it was relied on.

## 12. Method notes

- **Section sizes classify a binary before disassembly.** `.text` smaller than `.rodata`, plus an outsized `.bss`, plus a `bad opcode` string, is an interpreter. Recognising that reframed the target from "reverse 1,492 bytes of ARM" to "recover an ISA, then reverse the program written in it."
- **Reimplement the VM rather than reason about it.** A ~40-line Python interpreter turned the target into something instrumentable: opcode histograms, diffusion tests, and finally end-to-end confirmation of the answer.
- **Distinguish static from executed opcode distribution.** The static histogram over the image contained bytes that are not valid opcodes (embedded tables read via `LDP`). Only the *executed* histogram characterises the algorithm.
- **Table adjacency is a structural check.** S-box, keys, target and keystream tile the program image end to end with no gaps, and the keys stop exactly where the target starts. That contiguity confirmed the layout hypothesis before any of it was used.
- **Verify through the target's own machinery.** Algebraic agreement (`forward(rec) == TARGET`) and behavioural agreement (the VM printing the flag) are different claims. The second is the stronger one.

## 13. Open items

- The binary was never executed natively; `qemu-user` was not installed and the Python reimplementation was used throughout. The two should agree, but this was not cross-checked against the real AArch64 binary.
- Opcodes `0x29`/`0x2a`/`0x2b`/`0x2c`/`0x53`/`0x54`/`0x6b`/`0x7d`/`0x11`/`0xa1` are implemented from the dispatch arms but never execute in this program, so their semantics are unverified by observation.
- The S-box was not checked against any known construction (AES, or an algebraic inverse over GF(2⁸)); it was treated purely as an opaque bijection.
- No attempt was made to determine whether the 32-byte preimage carries meaning — it is binary, not text, and appears to be an arbitrary SPN preimage rather than a passphrase.

## Cross-references
- [[HTB-CA2026-First-Mark-RISCV-Custom-Opcode-Recovery]]
- [[HTB-CA2026-Ringtrue-MLP-Inversion-Int8-Keygen]]

## Change Log
- 2026-07-25 — Note created. Full solve documented: identification of an interpreter from section geometry, complete recovery of a 22-opcode custom VM ISA from the AArch64 dispatch tree, VM reimplementation in Python, identification of the embedded firmware as an 8-round SPN with a bijective S-box and GF(2)-linear mix layer, table layout of the program image, and full inversion recovering the 32-byte preimage and the flag.
