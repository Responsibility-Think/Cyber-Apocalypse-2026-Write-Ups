---
title: "HTB CA2026 — First Mark: Recovering Undocumented RISC-V Custom Opcodes"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: First Mark
app: first-mark.elf (RV32 bare-metal crackme)
category: reversing
difficulty: easy
points: 1000
solves: 105
type: writeup
status: complete
mitre:
  - T1027
  - T1140
tags:
  - writeup
  - HTB
  - Security
  - Reverse_Engineering
  - riscv
related:
  - "[[HTB]]"
  - "[[HTB-CA2026-Ringtrue-MLP-Inversion-Int8-Keygen]]"
  - "[[HTB-CA2026-Cinderbound-MicroPython-MPY-Rolling-XOR]]"
aliases:
  - First Mark
  - CA2026 First Mark
created: 2026-07-25T02:25:43.065Z
updated: 2026-07-25T04:41:07.265Z
---

# First Mark — Recovering Undocumented RISC-V Custom Opcodes

> [!success] Solved
> Recovered input: `cut_f0r_th3_P1NT` — verified byte-for-byte against the binary's own target.
> Flag: `HTB{cut_f0r_th3_P1NT}` — confirmed. Scenario marked Pwned 2026-07-24 22:24 local.

## 0. How the flag was obtained

1. `file first-mark.elf` → RV32 bare-metal, **stripped**. `readelf -S` — `.text` only 376 bytes, `.bss` 16 bytes @ `0x80000000`.
2. Disassembled with Capstone (`CS_ARCH_RISCV`); it stalled on four words with opcodes `0x0b`/`0x2b` — the RISC-V **custom-0/custom-1** slots.
3. Recovered the tables from `.rodata`: `A` (rotate distances, masked `&7`), `B` (values in `{2,3,5,7}` — GF(2⁸) multipliers), `C` (the 16-byte target), and seed `0xa5`.
4. Read the loop: `x = R1(in[i], A[i]&7); x = R2(x, B[i]); x = R3(x, state); state = x; assert x == C[i]`.
5. Rune 3 disclosed by the scenario: `out = x ^ state ^ carry; carry = x & state` — a **stateful full adder**, which is why a 87,808-combination stateless sweep found nothing.
6. With rune 3 known, `state` entering round *i* is just `C[i-1]`, so the pre-rune-3 values are computable; a 256-way scan per position then fixed runes 1 and 2 as `ror8` and `gf_mul`.
7. Recovered `cut_f0r_th3_P1NT`; verified by re-running all four runes forward against `C`.

## 1. Shape of the challenge

One file: `first-mark.elf`, 4,992 bytes. `ELF 32-bit LSB executable, UCB RISC-V, soft-float ABI, statically linked, **stripped**`.

Bare-metal image, not a hosted binary:

| | |
|---|---|
| Entry | `0x20000000` (ROM-like LOAD, R+E) |
| `.text` | 376 bytes — 94 fixed-width instructions |
| `.rodata` | 188 bytes |
| `.bss` | 16 bytes @ `0x80000000` (RAM-like LOAD, R+W) |
| Stack | `0x80010000` |
| I/O | polled UART MMIO at `0x10000000` |
| ISA string | `rv32i2p1_m2p0_zmmul1p0` — RV32IM, **no** compressed encoding |

`nm` returns "no symbols". The Ringtrue shortcut — an unstripped symbol table naming every tensor — is unavailable here.

## 2. The wall

Capstone disassembles cleanly to `0x20000120` and then stops. Forcing per-word decode shows why: four instructions carry opcodes `0x0b` and `0x2b`.

Those are the RISC-V spec's **`custom-0`** and **`custom-1`** slots. The spec assigns them no semantics and reserves them for implementation-defined vendor extensions. Capstone did not fail to decode them — there is nothing to decode.

```
20000124  0b05b500   custom-0 f3=0  rd=a0 rs1=a0 rs2=a1
20000130  0b15b500   custom-0 f3=1  rd=a0 rs1=a0 rs2=a1
20000134  2b05c500   custom-1 f3=0 f7=0x00  rd=a0 rs1=a0 rs2=a2
20000144  2b00d502   custom-1 f3=0 f7=0x01  rd=zero rs1=a0 rs2=a3
```

`.riscv.attributes` advertises only `rv32i2p1_m2p0` — the extension is deliberately undeclared. The scenario states this outright: *"He left four of its instructions undocumented on purpose... gave them no key... Common chisels read most of it and stall exactly there."*

## 3. What static analysis recovered anyway

Everything except the four rune semantics.

The whole file was accounted for byte-by-byte to rule out hidden payloads — the 3,916-byte gap between the program headers and `.text` is entirely zero. Nothing is concealed; the 376 bytes of code and 188 bytes of rodata are the complete artifact.

Control flow: `_start` zeroes `.bss`, skips an empty `.data` copy, and calls `main` @ `0x20000094`. `main` prints the banner, calls the checker @ `0x200000d0` with `a0 = 0x80000000` (the `.bss` input buffer), then prints `ACCEPTED`. The checker traps on mismatch rather than returning a status.

Three pointer setups via `auipc`/`addi` resolve to the tables:

| Array | Addr | Bytes |
|---|---|---|
| `A` | `0x200001f4` | `03 07 01 05 02 06 04 00` × 2 — a permutation of 0–7 |
| `B` | `0x20000204` | `03 02 03 02 05 07 02 03 05 07 02 03 05 07 02 03` |
| `C` | `0x20000214` | `11 7a 35 90 7e 88 b0 59 79 7f 56 6a 3a 10 e9 05` — the target |

Loop structure, `s1 = i`, 16 iterations, `a2` seeded to `0xa5`:

```
x = input[i]
x = RUNE1(x, A[i] & 7)
x = RUNE2(x, B[i])
x = RUNE3(x, a2)
a2 = x                    # state feedback
RUNE4(x, C[i])            # rd=zero -> compare and trap
```

**Two constants were correctly inferred from the data before any hint.** `A` is masked `& 7`, which bounds it to a shift/rotate distance. `B` draws only from `{2,3,5,7}` — GF(2⁸) multiplier constants of the AES MixColumns family. Both inferences held.

## 4. The failed search — and why it was structurally doomed

With `A` and `B` read correctly, an exhaustive sweep was run over candidate rune semantics: 28 operations (rotates, shifts, XOR/ADD/SUB/MUL, GF(2⁸), bit reversal, nibble swap, and composites) in every ordered triple, against four candidate inputs including the unreferenced 16-byte string `" keep your steel"` sitting in `.rodata`. **87,808 combinations, zero hits.**

The conclusion drawn at the time — "unsolvable without the emulator" — was too strong. The correct statement was narrower: *unsolvable within the function space being searched.*

Every candidate op was a pure function `(byte, byte) → byte`. **Rune 3 is stateful.** It maintains a hidden `carry` register that appears in no instruction operand and is therefore invisible to operand-level analysis. The answer was never in the search space, and widening the op list would never have found it.

> [!warning] Lesson
> When an exhaustive search returns empty, suspect the **shape** of the search before its **size**. The arrays and loop structure were correctly labelled [Certain]; "the runes are stateless" rode underneath as an unexamined assumption and invalidated the entire sweep.

## 5. The four runes

Rune 3 was disclosed by the scenario's final clue. Runes 1 and 2 then fell out of a two-unknown search in one pass.

| Rune | Encoding | Semantics |
|---|---|---|
| 1 | `custom-0` f3=0 | `ror8(x, A[i] & 7)` |
| 2 | `custom-0` f3=1 | `gf_mul(x, B[i])` — GF(2⁸), AES polynomial `0x11b` |
| 3 | `custom-1` f7=0 | `out = x ^ state ^ carry` ; `carry = x & state` ; `state = out` ; `state₀ = 0xa5`, `carry₀ = 0` |
| 4 | `custom-1` f7=1, rd=0 | compare `x` against `C[i]`, trap on mismatch |

Rune 3's `sum` / `carry-out` pair is a **full adder** — the rune is one bit-slice of addition wearing a XOR disguise. That is also precisely what makes it stateless-indistinguishable: on any single round it looks like a XOR, and only the cross-round carry reveals otherwise.

`gf_mul` and its argument-swapped form both matched, because GF multiplication is commutative — one solution, not two.

## 6. Inversion

Rune 3's disclosure makes the value entering it computable at every round without knowing runes 1 or 2, because `state` is by construction the previous round's verified output:

```python
state, carry = 0xa5, 0
V = []
for i in range(16):
    v = C[i] ^ state ^ carry      # value entering rune 3
    carry = v & state
    state = C[i]
    V.append(v)
# V = b4 cf 4e ef cb 76 4e e1 80 06 29 15 44 6a d3 fc
```

With `V` known, each input byte is recovered by a 256-way scan per position — 4,096 evaluations total, no search over the input as a whole:

```python
M = 0xff
ror = lambda x, n: ((x >> (n & 7)) | (x << ((8 - (n & 7)) & 7))) & M
def gf(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        h = a & 0x80; a = (a << 1) & M
        if h: a ^= 0x1b
        b >>= 1
    return p

out = []
for i in range(16):
    out += [b for b in range(256) if gf(ror(b, A[i] & 7), B[i]) == V[i]]
print(bytes(out))    # b'cut_f0r_th3_P1NT'
```

Each position yielded exactly one solution. Forward re-execution of all four runes over `cut_f0r_th3_P1NT` reproduces `C` exactly across all 16 bytes.

## 8. Final payload

```python
A = [3,7,1,5,2,6,4,0]*2                                  # rune-1 rotate distances
B = [3,2,3,2,5,7,2,3,5,7,2,3,5,7,2,3]                    # rune-2 GF(2^8) multipliers
C = [0x11,0x7a,0x35,0x90,0x7e,0x88,0xb0,0x59,
     0x79,0x7f,0x56,0x6a,0x3a,0x10,0xe9,0x05]            # target

M = 0xff
ror = lambda x, n: ((x >> (n & 7)) | (x << ((8 - (n & 7)) & 7))) & M
def gf(a, b):                                            # GF(2^8), poly 0x11b
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        h = a & 0x80; a = (a << 1) & M
        if h: a ^= 0x1b
        b >>= 1
    return p

# rune 3 is a FULL ADDER: out = x ^ state ^ carry ; carry = x & state
# so the value entering it is computable at every round, because state = C[i-1]
state, carry, V = 0xa5, 0, []
for i in range(16):
    v = C[i] ^ state ^ carry
    carry = v & state
    state = C[i]
    V.append(v)

out = []
for i in range(16):                                      # 256-way scan per position
    out += [b for b in range(256) if gf(ror(b, A[i] & 7), B[i]) == V[i]]
print(bytes(out))                                        # b'cut_f0r_th3_P1NT'
```

Flag: `HTB{cut_f0r_th3_P1NT}`

## 9. Tools & techniques
`file` / `readelf` (RV32 identification, section map) · Capstone (`CS_ARCH_RISCV`) · Python (byte-complete file accounting, constraint search, inversion)
Concepts: RISC-V custom opcode space (`custom-0` / `custom-1`) · undocumented ISA extension · GF(2⁸) multiplication · stateful primitive with a hidden carry register · recovering semantics from surrounding context rather than a specification

## 10. MITRE ATT&CK
- **T1027** Obfuscated Files or Information — the validation logic uses four undocumented instructions in the RISC-V `custom-0`/`custom-1` opcode slots, which no standard disassembler can decode; `.riscv.attributes` deliberately advertises only `rv32i2p1_m2p0`, omitting the extension
- **T1140** Deobfuscate/Decode Files or Information — the check decodes the candidate through a rotate, a GF(2⁸) multiply and a stateful full-adder stage before comparison

> [!note] Honest scope of this mapping
> A bare-metal offline crackme with no host interaction. Only the obfuscation techniques the artifact genuinely exhibits are listed.

## 11. Detection / blue-team & fix notes
- **Custom opcodes are a hard wall for static analysis, by design.** `0x0b` / `0x2b` / `0x5b` / `0x7b` are reserved by the RISC-V spec for implementation-defined extensions and carry *no* standard meaning. Encountering them means the semantics live outside the binary — in an emulator, a vendor manual, a remote harness, or (here) the accompanying prose. This is a real anti-analysis technique on embedded targets, not just a CTF device.
- **Declared ISA is attacker-controlled metadata.** `.riscv.attributes` claimed base RV32IM and omitted the extension entirely. Treat any self-declared capability string as a hint, never as ground truth.
- **Analyst guidance — read constant tables as type information.** `A` masked `& 7` bounds its values to a rotate distance; `B` drawn only from `{2,3,5,7}` is a GF(2⁸) multiplier alphabet. Both were inferred from the data alone and both held, narrowing two of three unknowns before any external input arrived.
- **Analyst guidance — a stateful primitive is invisible to operand-level enumeration.** An exhaustive sweep of 87,808 ordered triples over 28 candidate operations returned zero hits, because every candidate was a pure `(byte, byte) -> byte` function and rune 3 carries a hidden `carry` register that appears in no instruction operand. **When a well-chosen exhaustive search comes back completely empty, suspect the shape of the search before its size.**
- **Analyst guidance — account for every byte before declaring a file exhausted.** Summing the region map against file size and confirming the 3,916-byte inter-section gap was all zero converted "I think there is nothing else" into a provable statement.

## 12. Method notes

- **Custom opcodes are a hard wall for static analysis, by definition.** `0x0b` / `0x2b` / `0x5b` / `0x7b` carry no spec-defined meaning. Encountering them means the semantics live outside the binary — in an emulator, a vendor manual, a remote harness, or (here) the challenge prose.
- **Account for every byte before declaring a file exhausted.** Summing the region map against file size and confirming the inter-section gap was all-zero converted "I think there's nothing else" into a provable statement, and made the subsequent request for more material defensible rather than a guess.
- **Read constant tables as type information.** `& 7` bounds a value to a rotate distance; `{2,3,5,7}` is a GF(2⁸) multiplier alphabet. Both inferences were made from the data alone and both survived contact with the answer — that is two of the three unknowns narrowed before any external input.
- **A stateful primitive is invisible to operand-level enumeration.** No sweep over `(byte, byte) → byte` can express a hidden register. If a search over a well-chosen op family comes back completely empty, that emptiness is evidence about the *model*, not about needing a bigger family.
- **`" keep your steel"` at `0x20000224` is exactly 16 bytes, unreferenced by any code path, and is not the answer.** A decoy sized to match the input buffer — the same trick as Ringtrue's unreferenced `W_SCALE`. Length coincidence is not evidence.

## 13. Open items

- No emulator was ever obtained. Whether the challenge shipped one, exposed a remote harness, or intended the prose clue as the sole key was never established.
- The sibling marks implied by *"read the four marks or be cast out"* were not located. If they exist they presumably reuse these same four runes, which are now fully documented above.
- Runes 1, 2 and 4 were recovered by constrained search rather than from a specification, so their semantics are confirmed only over the 16 observed inputs. Edge-case behaviour (e.g. rune 1 with a zero rotate distance, rune 2 with `B[i] = 0`) is unexercised by this binary.

## Cross-references
- [[HTB-CA2026-Ringtrue-MLP-Inversion-Int8-Keygen]]
- [[HTB-CA2026-Cinderbound-MicroPython-MPY-Rolling-XOR]]
- [[HTB]]

## Change Log
- 2026-07-25 — Note created. Full solve documented: RV32IM bare-metal recon of a stripped image, identification of four undocumented `custom-0`/`custom-1` instructions, byte-complete file accounting, recovery of the `A`/`B`/`C` tables and loop structure, a failed 87,808-combination sweep and the structural reason it could not succeed, the four rune semantics including the stateful full-adder rune, and single-pass inversion recovering `cut_f0r_th3_P1NT`.
