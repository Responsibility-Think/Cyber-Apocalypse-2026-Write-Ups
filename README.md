# Cyber Apocalypse 2026 — Write-Ups

Write-ups from **Hack The Box Cyber Apocalypse CTF 2026: The Salt Crown**.

Each note documents the full method, not just the solve path — the reasoning that led nowhere, the negative results worth proving, and the attempts that failed. Where a challenge went unsolved, the write-up says so and records how far it got.

28 challenges across nine categories.

---

## Index

### Hardware

| Challenge | Difficulty | Points | Focus | Status |
|---|---|---|---|---|
| [Cadence in the Cord](./HTB-CA2026-Cadence-in-the-Cord-UART-Inter-Frame-Timing-Covert-Channel.md) | easy | 975 | UART Inter Frame Timing Covert Channel | Solved |
| [Saltlock Drift](./HTB-CA2026-Saltlock-Drift-RollJam-Rolling-Code-Replay.md) | medium | 975 | RollJam Rolling Code Replay | Solved |
| [What the Shard Displayed](./HTB-CA2026-What-the-Shard-Displayed-I2C-SSD1306-Framebuffer-Reconstruction.md) | medium | 975 | I2C SSD1306 Framebuffer Reconstruction | Solved |
| [A Fault in the Cinder](./HTB-CA2026-A-Fault-in-the-Cinder-SPI-Triggered-Glitch-Auth-Bypass.md) | hard | 975 | SPI Triggered Glitch Auth Bypass | Solved |

### Reversing

| Challenge | Difficulty | Points | Focus | Status |
|---|---|---|---|---|
| [Cinderbound](./HTB-CA2026-Cinderbound-MicroPython-MPY-Rolling-XOR.md) | very easy | 925 | MicroPython MPY Rolling XOR | Solved |
| [Ringtrue](./HTB-CA2026-Ringtrue-MLP-Inversion-Int8-Keygen.md) | very easy | 950 | MLP Inversion Int8 Keygen | Solved |
| [First Mark](./HTB-CA2026-First-Mark-RISCV-Custom-Opcode-Recovery.md) | easy | 1000 | RISCV Custom Opcode Recovery | Solved |
| [The Cinder Engine](./HTB-CA2026-Cinder-Engine-AArch64-VM-SPN-Inversion.md) | medium | 975 | AArch64 VM SPN Inversion | Solved |
| [CorpSyncAudit](./HTB-CA2026-CorpSyncAudit-Log-Steganography-Shellcode-Dropper.md) | hard | 975 | Log Steganography Shellcode Dropper | Solved |
| [Secondhand](./HTB-CA2026-Secondhand-Overlapping-Instruction-Self-Decrypting-Stub.md) | insane | 975 | Overlapping Instruction Self Decrypting Stub | Solved |

### AI / ML

| Challenge | Difficulty | Points | Focus | Status |
|---|---|---|---|---|
| [Memento](./HTB-CA2026-Memento-Skill-Persistence-Memory-Poisoning.md) | easy | 950 | Skill Persistence Memory Poisoning | Solved |
| [Obligation Indexer](./HTB-CA2026-Obligation-Indexer-Stored-Dossier-Injection.md) | easy | 975 | Stored Dossier Injection | Solved |
| [Crownspire Petitions](./HTB-CA2026-Crownspire-Petitions.md) | medium | 1000 |  | Solved |
| [Forked Tongue](./HTB-CA2026-Forked-Tongue-Tokenizer-Vocab-Merges-Divergence.md) | medium | 975 | Tokenizer Vocab Merges Divergence | Solved |
| [Assay](./HTB-CA2026-Assay-Model-Extraction-Weight-LSB-Backdoor.md) | hard | 975 | Model Extraction Weight LSB Backdoor | Solved |
| [Custody Engine](./HTB-CA2026-Custody-Engine-Egress-Gate-Self-Rewrite-PARTIAL.md) | hard | 975 | Egress Gate Self Rewrite | **Partial** |

### Cloud

| Challenge | Difficulty | Points | Focus | Status |
|---|---|---|---|---|
| [Wrong Stamp](./HTB-CA2026-Wrong-Stamp-CloudTrail-Credential-Reuse-Log-Disablement.md) | easy | 1000 | CloudTrail Credential Reuse Log Disablement | Solved |
| [Bought Riot](./HTB-CA2026-Bought-Riot-AssumeRole-ExternalId-Chain-PARTIAL.md) | medium | 975 | AssumeRole ExternalId Chain | **Partial** |
| [False Order](./HTB-CA2026-False-Order-STS-Role-Chain-S3-Object-Tampering.md) | medium | 1000 | STS Role Chain S3 Object Tampering | Solved |

### Web

| Challenge | Difficulty | Points | Focus | Status |
|---|---|---|---|---|
| [Gatery](./HTB-CA2026-Gatery-Elysia-Cookie-Signature-Bypass.md) | very easy | — | Elysia Cookie Signature Bypass | Solved |
| [Massagold](./HTB-CA2026-Massagold-Stored-XSS-JSONP-CSP-Bypass.md) | very easy | — | Stored XSS JSONP CSP Bypass | Solved |
| [Provisioneds](./HTB-CA2026-Provisioneds-Joomla-PHP-Object-Injection-PARTIAL.md) | very easy | — | Joomla PHP Object Injection | **Partial** |

### Secure Coding

| Challenge | Difficulty | Points | Focus | Status |
|---|---|---|---|---|
| [Hollow Courier](./HTB-CA2026-Hollow-Courier-XFF-Hop-Count-Trust-Boundary.md) | easy | 950 | XFF Hop Count Trust Boundary | Solved |
| [Withered Registry](./HTB-CA2026-Withered-Registry-Broken-Access-Control-Privileged-Write.md) | medium | 975 | Broken Access Control Privileged Write | Solved |
| [Phantom burn](./HTB-CA2026-Phantom-Burn-Unverified-Receipts-And-Published-Entitlement.md) | hard | 975 | Unverified Receipts And Published Entitlement | Solved |

### Forensics

| Challenge | Difficulty | Points | Focus | Status |
|---|---|---|---|---|
| [Remnant](./HTB-CA2026-Remnant-TLS-Decrypt-C2-DFIR.md) | medium | — | TLS Decrypt C2 DFIR | Solved |

### Blockchain

| Challenge | Difficulty | Points | Focus | Status |
|---|---|---|---|---|
| [Caldrin's Day Away](./HTB-CA2026-Caldrins-Day-Away-Stamped-Oracle-Spot-Reserve-Manipulation.md) | easy | 975 | Stamped Oracle Spot Reserve Manipulation | Solved |

### GamePwn

| Challenge | Difficulty | Points | Focus | Status |
|---|---|---|---|---|
| [The Salt Crown](./HTB-CA2026-Salt-Crown-Deterministic-Transcript-HKDF-Key-Recovery.md) | hard | 975 | Deterministic Transcript HKDF Key Recovery | Solved |

---

## Notes

- **Credentials are truncated.** Passwords, access keys and credential hashes that appear in the evidence are shown truncated (for example `AKIA…RUOL`, `D1…26`), so no complete secret is published. File hashes and other IOCs are shown in full.
- **Points** are HTB's dynamic values as recorded at solve time; four notes predate the field being captured and show `—`.
- **Partial** marks a challenge that was worked but never flagged. Those write-ups document the approach and where it stalled — Bought Riot, Custody Engine, and Provisioneds.
- *The Salt Crown* was solved offline after the submission window closed, so it does not appear in the scoreboard result.
- MITRE ATT&CK mappings appear in most notes' frontmatter. Several are explicitly flagged as unverified in the note; treat them as working hypotheses rather than citations.

## Use

Licensed CC BY 4.0 — reuse freely with attribution. Challenge names, prose, and artefacts remain the property of Hack The Box.
