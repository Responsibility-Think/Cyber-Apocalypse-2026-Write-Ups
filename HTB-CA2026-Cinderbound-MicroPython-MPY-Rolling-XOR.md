---
title: "HTB CA2026 — Cinderbound: MicroPython .mpy Rolling-XOR Verifier"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Cinderbound
app: cinderbound.mpy (MicroPython bytecode crackme)
category: reversing
difficulty: very easy
points: 925
solves: 614
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
  - micropython
  - bytecode
related:
  - "[[HTB]]"
aliases:
  - Cinderbound
  - CA2026 Cinderbound
created: 2026-07-25T01:57:06.772Z
updated: 2026-07-25T04:41:07.265Z
---

# Cinderbound — MicroPython .mpy Rolling-XOR Verifier

> [!success] Solved
> Passphrase: `c1nd3rbound_v0w5` · Flag: `HTB{c1nd3rbound_v0w5}`
> Solved 2026-07-24 21:55 local. Single artifact, 221 bytes, no server. Difficulty: easy/medium.

## 0. How the flag was obtained

1. `xxd cinderbound.mpy` — 221 bytes, magic `M`, byte 1 = `0x06` → MicroPython bytecode v6.
2. Fetched `mpy-tool.py` from the MicroPython repo; `python3 mpy-tool.py -d cinderbound.mpy`.
3. Read the const table and disassembly: target tuple `(57,129,154,31,199,192,73,243,43,176,255,173,54,203,67,15)`, seed `k = 90`.
4. Reconstructed `judge()`: `out[i] = (ord(s[i]) ^ k) ^ ((i*13) & 255)`, then `k = (k + ord(s[i])) & 255`.
5. Inverted in one forward pass — the key is fed by *plaintext*, so each recovered byte yields the next key state: `c[i] = v[i] ^ ((i*13)&255) ^ k[i]`.
6. Result `c1nd3rbound_v0w5`; verified by re-running the reconstructed `judge()` → `True`. Flag is the direct wrap.

## 1. Shape of the challenge

One file: `cinderbound.mpy`, 221 bytes. No source, no server, no instance.

`.mpy` is MicroPython's precompiled bytecode container — the embedded-systems analogue of `.pyc`. It is not obfuscation; it is a documented serialisation format with an official disassembler in the MicroPython tree. The entire difficulty of this challenge is knowing that the tool exists.

## 2. Header and format identification

```
$ xxd cinderbound.mpy | head -1
00000000: 4d06 001f 0801 186a 7564 6765 5f73 7263  M......judge_src
```

| Offset | Value | Meaning |
|---|---|---|
| 0 | `0x4D` `'M'` | `.mpy` magic |
| 1 | `0x06` | format version 6 |
| 2 | `0x00` | flags |
| 3 | `0x1F` | small-int bits (31) |

Version 6 is handled by `mpy-tool.py` on MicroPython master (`MPY_VERSION = 6`), so no version-matched checkout was needed.

`strings` alone gives most of the picture — `judge_src.py`, `judge`, `syllable`, and a run of digits. **The digits are a trap for anyone reading them without the length prefixes:** the integers are stored as decimal text with a type byte and a length byte in front, and a lossy read (anything that mangles non-ASCII) runs them together into a single 41-digit number. That artifact briefly suggested a factoring problem. There is no factoring problem.

## 3. Disassembly

```
$ curl -sO https://raw.githubusercontent.com/micropython/micropython/master/tools/mpy-tool.py
$ curl -s --create-dirs -o ../py/makeqstrdata.py \
    https://raw.githubusercontent.com/micropython/micropython/master/py/makeqstrdata.py
$ python3 mpy-tool.py -d cinderbound.mpy
```

```
qstr_table[8]: judge_src.py, <module>, judge, append, syllable, len, ord, list
obj_table: [(57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)]
```

The operative loop body:

```
23:00   LOAD_CONST_OBJ (57, 129, ...)   c1  STORE_FAST 1     # target
22:80:5a LOAD_CONST_SMALL_INT 90        c2  STORE_FAST 2     # k = 90
2b:00   BUILD_LIST 0                    c3  STORE_FAST 3     # out = []
...
12:06   LOAD_GLOBAL ord
b0/b4   LOAD_FAST 0 / LOAD_FAST 4
55      LOAD_SUBSCR                                          # syllable[i]
34:01   CALL_FUNCTION 1                                      # ord(...)
b2      LOAD_FAST 2                     ee  BINARY_OP __xor__   # ^ k
b4      LOAD_FAST 4
8d      LOAD_CONST_SMALL_INT 13         f4  BINARY_OP __mul__   # i * 13
22:81:7f LOAD_CONST_SMALL_INT 255       ef  BINARY_OP __and__   # & 255
                                        ee  BINARY_OP __xor__
c5      STORE_FAST 5                                         # v
b2      LOAD_FAST 2 ... f2 BINARY_OP __add__ ... ef __and__
c2      STORE_FAST 2                                         # k = (k + ord(c)) & 255
```

## 4. Reconstructed source

```python
def judge(syllable):
    target = (57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)
    k = 90
    out = []
    for i in range(len(syllable)):
        out.append((ord(syllable[i]) ^ k) ^ ((i * 13) & 255))
        k = (k + ord(syllable[i])) & 255      # key rolls on the PLAINTEXT byte
    return out == list(target)
```

## 5. Inverting it

The comment on line 7 is the whole challenge. The key state advances using the plaintext byte, not the ciphertext byte — which reads at first as though decryption is blocked without already knowing the answer. It is the opposite: each recovered byte *produces* the next key state, so the whole thing unwinds in one forward pass with no search.

```
c[i]   = v[i] ^ ((i * 13) & 255) ^ k[i]
k[i+1] = (k[i] + c[i]) & 255,   k[0] = 90
```

```python
TARGET = (57,129,154,31,199,192,73,243,43,176,255,173,54,203,67,15)
k, rec = 90, ""
for i, v in enumerate(TARGET):
    c = v ^ ((i * 13) & 255) ^ k
    rec += chr(c)
    k = (k + c) & 255
print(rec)   # c1nd3rbound_v0w5
```

Verified by re-running the reconstructed `judge()` against the recovered string: returns `True`.

## 6. Why it looks harder than it is

Three things create apparent difficulty, none of them real:

- **Unfamiliar container.** `.mpy` is rare enough that it reads as a custom format. It is not — it is documented, versioned, and ships with a disassembler.
- **Plaintext-fed key schedule.** Superficially resembles a construction that resists inversion. It resists *parallel* inversion only; sequential inversion is free.
- **Integers-as-text in the const table.** A careless read fuses them into one huge number and suggests a factoring attack that does not exist.

The reflex on seeing a comparison against a fixed target is to brute-force the input. Wrong reflex here — 16 printable bytes is ~10^38 and hopeless, while the inversion is 16 iterations.

## 8. Final payload

```python
TARGET = (57,129,154,31,199,192,73,243,43,176,255,173,54,203,67,15)

ror = lambda x, n: ((x >> n) | (x << (8-n))) & 0xff
k, out = 90, ''
for i, v in enumerate(TARGET):
    c = v ^ ((i * 13) & 255) ^ k     # undo the position mask and the rolling key
    out += chr(c)
    k = (k + c) & 255                # key advances on the RECOVERED plaintext byte
print(out)                           # c1nd3rbound_v0w5
```

Flag: `HTB{c1nd3rbound_v0w5}`

## 9. Tools & techniques
`xxd` (header identification) · `mpy-tool.py` from the MicroPython repo (bytecode disassembly) · Python (inversion + verification)
Concepts: MicroPython `.mpy` container format · constant-table extraction · rolling-key stream cipher keyed on plaintext · single-pass inversion

## 10. MITRE ATT&CK
- **T1027** Obfuscated Files or Information — the check ships as compiled MicroPython bytecode rather than source, and the target constants are stored as decimal text in the const table
- **T1140** Deobfuscate/Decode Files or Information — the validation routine decodes the candidate with a rolling XOR/rotate before comparison

> [!note] Honest scope of this mapping
> This is an offline keygen puzzle with no host interaction, so only the two techniques the artifact genuinely exhibits are listed. Padding this section with execution or persistence T-codes would pollute the vault's `mitre[]` queries.

## 11. Detection / blue-team & fix notes
- **The transferable lesson is the cipher shape, not the container.** A rolling key advanced by the *plaintext* byte looks like it resists inversion — you appear to need the answer to derive the key. It is the opposite: each recovered byte produces the next key state, so the whole thing unwinds in one forward pass. The same construction shows up in real packers and licence checks.
- **`.mpy` is not obfuscation.** It is a documented, versioned serialisation format with an official disassembler in the MicroPython tree. Treat an unfamiliar container as a format-identification problem before treating it as a reversing problem — the header byte answered it here.
- **Analyst guidance — never reverse through a lossy transport.** Reading this file through a text-oriented API replaced every non-ASCII byte with U+FFFD, silently deleting the length prefixes in the const table and fusing sixteen small integers into one 41-digit number. That produced a confident, wrong hypothesis (a factoring attack) within seconds. Always work from the bytes.
- **Detection note:** integers stored as decimal text inside a bytecode const table are a normal `.mpy` feature, not an IOC. There is nothing malicious in this sample — the defensive value is analyst tradecraft only.

## 12. Method notes

- **Read the state transition before reaching for a solver.** When a checker is stateful, the transition function usually tells you whether inversion is possible. Here it took one line to see the key was plaintext-fed and therefore recoverable in lockstep.
- **The whole artifact arrived as terminal output.** 221 bytes of `xxd` pasted into chat was reconstructed byte-for-byte and disassembled without ever transferring the file. For small binaries, a hex dump *is* the file.
- **Text-oriented APIs destroy binaries.** Reading the `.mpy` through the Obsidian REST API returned UTF-8 replacement characters for every non-ASCII byte, which silently deleted the length prefixes in the const table. Analysis on that output produced a wrong hypothesis within seconds. **Never reverse-engineer through a lossy transport.**
- **Check for an official tool before writing a parser.** Hand-parsing the const table was underway and heading toward a misread of the type bytes; `mpy-tool.py -d` resolved the whole structure in one command.

## 13. Open items

- Reconstruction hash not confirmed against the original file. The rebuilt artifact is `sha256 761959aa6fca19e924d879de39d47e321e0684ade2ba5afe658f6414f4fd8fe6`; it parsed as valid mpy v6 and yielded meaningful plaintext, so it is [Likely] byte-exact, but this was never verified against the source file on disk.
- `judge_src.py` is named in the header but was not shipped. Never checked whether the challenge page offers it — it would confirm the decompilation directly.
- `userpass.txt` sits loose in the same folder as `cinderbound.mpy`. Never opened; relationship to this challenge unestablished.
- The `.mpy` is stored loose in the CA2026 folder rather than in a `Cinderbound/` subdirectory, unlike sibling challenges.

## Cross-references
- [[HTB]]

## Change Log
- 2026-07-25 — Note created. Full solve documented: format identification, `mpy-tool.py` disassembly, reconstructed `judge()`, single-pass inversion of the plaintext-fed rolling XOR, recovered passphrase and flag, method notes on lossy-transport hazard and stateful-checker inversion.
