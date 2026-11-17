---
title: "HTB CA2026 — Ringtrue: Inverting a Quantized MLP to Recover a Keygen Input"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Ringtrue
app: ringtrue (Brine Signet resonance console — ELF keygen)
category: reversing
difficulty: very easy
points: 950
solves: 427
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
  - AI_ML
related:
  - "[[HTB-CA2026-Cinderbound-MicroPython-MPY-Rolling-XOR]]"
aliases:
  - Ringtrue
  - CA2026 Ringtrue
created: 2026-07-25T02:08:09.132Z
updated: 2026-07-25T04:41:07.265Z
---

# Ringtrue — Inverting a Quantized MLP to Recover a Keygen Input

> [!success] Solved
> Tones: `83 97 108 116 67 114 119 110` (ASCII `SaltCrwn`) · Flag: `HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}`
> Solved 2026-07-24 22:07 local. Single 25 KB ELF, no server. Difficulty: easy/medium.

## 0. How the flag was obtained

1. `file ringtrue` → x86-64 ELF, **not stripped**. `strings` revealed a fake boot log stating the architecture: `MLP 8-8-8-8, int8, leaky`.
2. `nm -C ringtrue` handed over the entire model by name: `L0_W/L1_W/L2_W`, `L0_B/L1_B/L2_B`, `ECHO_S`, `VOW_CIPHER`, `VOW_LEN`, `dense`.
3. Disassembled `dense` (60 bytes): `out[i] = B[i] + Σ W[i*8+j]*in[j]`, **int64 accumulate, no requantization**.
4. Found the activation in `main`: `cmovs` → `f(x) = x if x>=0 else 2*x` — injective, so invertible.
5. Extracted weights/biases/target straight from `.data` and inverted three exact linear solves over ℚ with `Fraction`, undoing `f` between layers.
6. Tones `83 97 108 116 67 114 119 110` = ASCII `SaltCrwn`.
7. Flag = `VOW_CIPHER XOR sha256(tones || u32le(0))`; confirmed by running the binary → `IT RINGS TRUE`.

## 1. Shape of the challenge

One file: `ringtrue`, 25,784 bytes, `ELF 64-bit LSB pie executable, x86-64, dynamically linked, **not stripped**`.

Scenario framing: eight tones, "each can be any value, and far too many to try one by one," but "Eastreach was careless and left the device open to read, with everything it was taught still written plainly inside."

That is an accurate technical description. The search space genuinely is 2^256. The binary genuinely does contain the entire model.

## 2. Recon — the binary describes itself

Two commands did most of the work before any disassembly.

`strings` recovers a fake boot log that states the architecture outright:

```
[ 0.031004] adc: tone-sensor ch0..ch7 online (8 samples / attune)
[ 0.061200] npu: resonance_core.tflm - MLP 8-8-8-8, int8, leaky ... ok
[ 0.072990] npu: weights symmetric int8 (zp=0), per-tensor scale
[ 0.077553] crypto: vault-seal = xor-stream, key = attunement-derived
[ 0.121002] astrael-echo: reference signature pinned
```

`nm` recovers the whole model, because the binary is not stripped:

| Symbol | Addr | Size | Contents |
|---|---|---|---|
| `L0_W` `L1_W` `L2_W` | `0x5180` `0x5140` `0x5100` | 64 | int8 weights, row-major `W[i*8+j]` |
| `L0_B` `L1_B` `L2_B` | `0x50e0` `0x50c0` `0x50a0` | 32 | int32 biases |
| `ECHO_S` | `0x5060` | 64 | 8 × int64 — the pinned target signature |
| `VOW_CIPHER` | `0x5030` | 30 | XOR-encrypted flag |
| `VOW_LEN` | `0x5020` | 4 | `30` |
| `W_SCALE` | `0x5050` | 12 | 3 floats — **never referenced** |
| `K.0` | `0x3a80` | 256 | SHA-256 round constants |
| `dense` | `0x1309` | 60 | the layer function |

**`W_SCALE` is dead data.** Zero references in the disassembly. It exists solely to corroborate the boot log's "per-tensor scale" line and suggest a dequantization step that does not occur. The FPU code in `main` computes the resonance-percentage bar for the UI, nothing else.

## 3. `dense` — 60 bytes, no quantization

```
dense(rdi=W, rsi=B, rdx=in, rcx=out):
    for i in 0..7:
        acc = (int64)B[i]                      # movsxd from int32
        for j in 0..7:
            acc += (int8)W[i*8+j] * (int64)in[j]
        out[i] = acc                           # int64, no rescale, no clamp
```

This is the crux. Despite `int8` weights and a boot log advertising quantized inference, **accumulation is int64 and there is no requantization between layers**. The forward pass is exact integer arithmetic, so it inverts over ℚ with zero rounding error.

## 4. The activation

Between layers, `main` applies:

```asm
mov  rax, [rsp+rdx+0x70]
lea  rcx, [rax+rax*1]       ; 2*x
test rax, rax
cmovs rax, rcx              ; if x < 0 take 2*x
```

```python
f(x) = x if x >= 0 else 2*x
```

The boot log calls this "leaky," and it is — but with negative slope **2**, not the conventional 0.01. It is strictly increasing, therefore injective, therefore invertible:

```python
f⁻¹(y) = y      if y >= 0
       = y // 2 if y < 0      # y is necessarily even
```

The sign of `y` selects the branch with no ambiguity, so there is no branching search across the 8 units — the preimage is unique at every layer.

## 5. Inversion

Structure: `x → dense0 → f → dense1 → f → dense2 → compare to ECHO_S`.

Every weight matrix is square 8×8 and non-singular, so each `dense` inverts by exact linear solve:

```
a1 = L2_W⁻¹ (ECHO_S − L2_B)      z1 = f⁻¹(a1)
a0 = L1_W⁻¹ (z1 − L1_B)          z0 = f⁻¹(a0)
x  = L0_W⁻¹ (z0 − L0_B)
```

Solver — reads the model straight out of the ELF, no hardcoded constants:

```python
import struct, subprocess
from fractions import Fraction as F

raw = open("ringtrue","rb").read()
for line in subprocess.run(["readelf","-S","--wide","ringtrue"],
                           capture_output=True,text=True).stdout.splitlines():
    if " .data " in line:
        p = line.split(); addr, off = int(p[3],16), int(p[4],16); break
at = lambda va,n: raw[off+(va-addr): off+(va-addr)+n]

M   = lambda va: [list(struct.unpack("<64b", at(va,64)))[i*8:(i+1)*8] for i in range(8)]
Bv  = lambda va: list(struct.unpack("<8i", at(va,32)))
L0_W,L1_W,L2_W = M(0x5180), M(0x5140), M(0x5100)
L0_B,L1_B,L2_B = Bv(0x50e0), Bv(0x50c0), Bv(0x50a0)
ECHO = list(struct.unpack("<8q", at(0x5060,64)))

def solve(W, rhs):                       # exact Gaussian elimination over Q
    n=8; A=[[F(W[i][j]) for j in range(n)]+[F(rhs[i])] for i in range(n)]
    for c in range(n):
        p=next(r for r in range(c,n) if A[r][c]!=0); A[c],A[p]=A[p],A[c]
        pv=A[c][c]; A[c]=[v/pv for v in A[c]]
        for r in range(n):
            if r!=c and A[r][c]!=0:
                f=A[r][c]; A[r]=[a-f*b for a,b in zip(A[r],A[c])]
    return [int(A[i][n]) for i in range(n)]

unact = lambda y: y if y>=0 else y//2
a1 = solve(L2_W, [ECHO[i]-L2_B[i] for i in range(8)]); z1 = [unact(v) for v in a1]
a0 = solve(L1_W, [z1[i]-L1_B[i]  for i in range(8)]); z0 = [unact(v) for v in a0]
x  = solve(L0_W, [z0[i]-L0_B[i]  for i in range(8)])
print(x)   # [83, 97, 108, 116, 67, 114, 119, 110]
```

`83 97 108 116 67 114 119 110` → ASCII **`SaltCrwn`** — the event name, *The Salt Crown*, with the vowel dropped to fit eight bytes.

## 6. The flag is derived, not compared

`K.0` being the SHA-256 round-constant table was the tell: the flag is not a string sitting in `.rodata` behind a check. Patching the `cmp` at `0x1b6e` would have printed garbage.

`main` builds a single 64-byte SHA-256 block by hand:

- `msg[0:8]` — the **low byte** of each of the eight input ints
- `msg[8:12]` — block counter, `u32` little-endian
- `msg[12] = 0x80` (padding), `msg[63] = 0x60` (96-bit length = 12 bytes)

```
keystream[i] = sha256( tones_bytes || u32le(i // 32) )[i % 32]
flag         = VOW_CIPHER XOR keystream
```

`VOW_LEN` is 30 and SHA-256 emits 32 bytes, so only counter `0` is ever used.

```python
import hashlib
seed   = bytes([83,97,108,116,67,114,119,110])
cipher = bytes.fromhex("1c9d59313d0da8fbca056a2ac0b6a51172dfd75c2b216c9dc67296b48d6f")
ks = b"".join(hashlib.sha256(seed + b.to_bytes(4,"little")).digest()
              for b in range((len(cipher)+31)//32))
print(bytes(c^k for c,k in zip(cipher,ks)).decode())
# HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}
```

Confirmed against ground truth by running the binary: `RESONANCE 100%`, `IT RINGS TRUE`, `vault-seal: OPEN`.

## 7. Why brute force was the wrong instinct

The scenario is honest that guessing fails, and the reflex on seeing "compare against a fixed target" is to search the input space. Three properties make search unnecessary:

- **Square, non-singular weight matrices** — each layer is a bijection on ℚ⁸, not a projection. A funnel architecture (8→4→8) would have destroyed information and forced a constraint solver.
- **Injective activation** — `leaky` with slope 2 loses nothing. Plain ReLU would have collapsed every negative pre-activation to zero and made the layer non-invertible.
- **No requantization** — int64 accumulate with no rescale or clamp means no rounding to absorb, so exact rational arithmetic recovers the input precisely.

Break any one of those and this becomes a z3 problem. All three hold, so it is three linear solves.

## 8. Final payload

```python
import struct, subprocess, hashlib
from fractions import Fraction as F

raw = open('ringtrue','rb').read()
for l in subprocess.run(['readelf','-S','--wide','ringtrue'],
                        capture_output=True,text=True).stdout.splitlines():
    if ' .data ' in l:
        p = l.split(); addr, off = int(p[3],16), int(p[4],16); break
at = lambda va,n: raw[off+(va-addr): off+(va-addr)+n]

M  = lambda va: [list(struct.unpack('<64b', at(va,64)))[i*8:(i+1)*8] for i in range(8)]
Bv = lambda va: list(struct.unpack('<8i', at(va,32)))
L0_W,L1_W,L2_W = M(0x5180), M(0x5140), M(0x5100)
L0_B,L1_B,L2_B = Bv(0x50e0), Bv(0x50c0), Bv(0x50a0)
ECHO   = list(struct.unpack('<8q', at(0x5060,64)))
CIPHER = at(0x5030, struct.unpack('<i', at(0x5020,4))[0])

def solve(W, rhs):                       # exact Gaussian elimination over Q
    n=8; A=[[F(W[i][j]) for j in range(n)]+[F(rhs[i])] for i in range(n)]
    for c in range(n):
        p=next(r for r in range(c,n) if A[r][c]!=0); A[c],A[p]=A[p],A[c]
        pv=A[c][c]; A[c]=[v/pv for v in A[c]]
        for r in range(n):
            if r!=c and A[r][c]!=0:
                f=A[r][c]; A[r]=[a-f*b for a,b in zip(A[r],A[c])]
    return [int(A[i][n]) for i in range(n)]

unact = lambda y: y if y >= 0 else y//2  # inverse of f(x)= x if x>=0 else 2x
a1 = solve(L2_W, [ECHO[i]-L2_B[i] for i in range(8)]); z1 = [unact(v) for v in a1]
a0 = solve(L1_W, [z1[i]-L1_B[i]  for i in range(8)]); z0 = [unact(v) for v in a0]
tones = solve(L0_W, [z0[i]-L0_B[i] for i in range(8)])
print(tones)                             # [83,97,108,116,67,114,119,110] = 'SaltCrwn'

ks = hashlib.sha256(bytes(tones) + (0).to_bytes(4,'little')).digest()
print(bytes(c ^ k for c,k in zip(CIPHER, ks)).decode())
# HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}
```

```bash
$ echo "83 97 108 116 67 114 119 110" | ./ringtrue
  RESONANCE [##############################] 100%
  -- ***** --      IT RINGS TRUE
  vault-seal: OPEN
```

## 9. Tools & techniques
`nm` (symbol table — the whole model, by name) · `strings` (fake boot log disclosing the architecture) · `objdump` (x86-64 disassembly) · Python + `fractions.Fraction` (exact rational linear algebra)
Concepts: quantised neural network as a keygen · int8 weights with int64 accumulation · injective "leaky" activation · exact inversion of a square non-singular MLP · SHA-256 keystream keyed on the recovered input · unreferenced decoy data

## 10. MITRE ATT&CK
- **T1027** Obfuscated Files or Information — the validation logic is expressed as a neural network rather than comparable code, and `W_SCALE` is unreferenced decoy data planted to corroborate a false "quantised inference" story
- **T1140** Deobfuscate/Decode Files or Information — the flag is a SHA-256 keystream XOR, derived at runtime from the accepted input rather than stored
- **T1480.001** Execution Guardrails: Environmental Keying — the flag material is keyed on the correct input, so the plaintext exists nowhere in the binary and patching the comparison yields only noise

> [!note] Honest scope of this mapping
> An offline keygen with no host interaction. Only techniques the artifact genuinely demonstrates are listed; no execution, persistence, or C2 behaviour occurs.

## 11. Detection / blue-team & fix notes
- **The transferable finding: "derived, not compared."** SHA-256 round constants (`K.0`) in `.rodata` mean the secret is *computed from* the input, not checked against a stored string. Patching the comparison produces garbage. **Before patching any licence or auth check, determine whether the protected material is compared or derived** — it decides whether the patch is worth attempting at all.
- **Ship-stripped is the fix.** `nm` handed over `L0_W`, `L1_W`, `L2_W`, `L0_B`, `L1_B`, `L2_B`, `ECHO_S`, `VOW_CIPHER`, `VOW_LEN` and `dense` by name. A missing `strip` reduced this from reverse engineering to reading a table of contents. In-scenario it is described as the vendor's "carelessness" — which is exactly what an unstripped production binary is.
- **Do not trust a boot banner.** The log advertises `int8, per-tensor scale`, and `W_SCALE` exists to back that up — but `dense` accumulates in int64 with no requantisation and `W_SCALE` is referenced **zero times**. Verify which constants the code actually reads; grepping the disassembly for each data symbol separated the real model from the decoration in one pass.
- **ML-as-obfuscation is weak when the layers are invertible.** Square non-singular weight matrices, an injective activation, and no requantisation make the whole network a bijection. Funnel layers, plain ReLU, or genuine quantisation each independently would have forced a constraint solver instead of three linear solves.

## 12. Method notes

- **Read the boot log before disassembling.** `strings` gave the architecture, the layer count, the activation family, and the fact that the seal is an XOR stream keyed on the input. That is the entire solution plan, in English, in `.rodata`.
- **`nm` on a not-stripped binary is the highest-value single command.** Every tensor, the target signature, and the ciphertext were named. The scenario's "left the device open to read" was a literal description of the missing `strip`.
- **Verify which constants the code actually reads.** `W_SCALE` looks load-bearing and is referenced zero times. Grepping the disassembly for references to each data symbol separated the real model from the decoration in one pass.
- **Distinguish "compared against" from "derived from" before patching.** SHA-256 constants in `.rodata` mean the flag is computed from the input; a keygen, not a check. Patching the comparison would have produced 30 bytes of noise and cost real time.
- **Ground-truth the answer by running the target.** The analytical derivation and the binary's own output agreed, which converts [Likely] into [Certain] for one command.

## 13. Open items

- The three floats in `W_SCALE` were never decoded to see whether they correspond to plausible per-tensor scales for these weights, i.e. whether the author generated them from a real quantized model or invented them. Cosmetic, but it would confirm the red herring was deliberate rather than vestigial.
- No check on whether alternative tone vectors satisfy `ECHO_S`. The inversion is unique given non-singular matrices and injective activation, so a second solution should not exist — but this was reasoned, not exhaustively verified.
- `judge`-style source was not shipped and no attempt was made to locate a source drop on the challenge page.

## Cross-references
- [[HTB-CA2026-Cinderbound-MicroPython-MPY-Rolling-XOR]]

## Change Log
- 2026-07-25 — Note created. Full solve documented: symbol-table recon of an unstripped ELF, model extraction from `.data`, exact rational inversion of a three-layer int64-accumulate MLP with slope-2 leaky activation, recovery of the tone vector `SaltCrwn`, SHA-256 keystream derivation of the flag, and confirmation against the running binary. `W_SCALE` identified as unreferenced decoration.
